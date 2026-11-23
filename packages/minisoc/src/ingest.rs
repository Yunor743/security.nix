//! Spool reader: tails the NDJSON files written by the collector (Vector)
//! and the per-user inbox (`minisoc ingest`), with offsets persisted in the
//! store so a restart resumes where it stopped. Files are identified by
//! inode: a rotated/recreated file restarts at 0, and so does a file that
//! shrank (truncation). Partial trailing lines are left for the next pass.

use crate::store::Store;
use crate::{debug, warn};
use serde_json::Value;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_LINE: usize = 1 << 20;

fn spool_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("ndjson" | "json" | "log")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Read up to `budget` new records across all spool dirs; calls `f` for each
/// parsed record. Returns the number of records read.
pub fn poll(store: &Store, dirs: &[PathBuf], budget: usize, mut f: impl FnMut(Value)) -> usize {
    let mut total = 0;
    for dir in dirs {
        for path in spool_files(dir) {
            if total >= budget {
                return total;
            }
            match read_file(store, &path, budget - total, &mut f) {
                Ok(n) => total += n,
                Err(e) => warn!("spool {}: {e}", path.display()),
            }
        }
    }
    total
}

fn read_file(
    store: &Store,
    path: &Path,
    budget: usize,
    f: &mut impl FnMut(Value),
) -> std::io::Result<usize> {
    let meta = fs::metadata(path)?;
    let key = path.to_string_lossy().to_string();
    let (inode, size) = (meta.ino(), meta.size());
    let mut offset = match store.offset(&key).ok().flatten() {
        Some((ino, off)) if ino == inode && off <= size => off,
        Some((ino, _)) if ino == inode => {
            debug!("{key} was truncated, restarting at 0");
            0
        }
        _ => 0,
    };
    if offset == size {
        return Ok(0);
    }
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    file.take(((size - offset) as usize).min(8 << 20) as u64)
        .read_to_end(&mut buf)?;
    let mut n = 0;
    let mut start = 0;
    while n < budget {
        let Some(rel) = buf[start..].iter().position(|b| *b == b'\n') else {
            // Incomplete last line: wait for the writer, unless it is absurdly long.
            if buf.len() - start > MAX_LINE {
                warn!("{key}: dropping an over-long unterminated line");
                start = buf.len();
            }
            break;
        };
        let line = &buf[start..start + rel];
        start += rel + 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(v) if v.is_object() => {
                f(v);
                n += 1;
            }
            _ => warn!("{key}: skipping a malformed spool line"),
        }
    }
    offset += start as u64;
    let _ = store.set_offset(&key, inode, offset);
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn resume_partial_lines_rotation_truncation() {
        let d = std::env::temp_dir().join(format!("minisoc-ingest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let store = Store::open(&d.join("db.sqlite3")).unwrap();
        let spool = d.join("spool");
        fs::create_dir_all(&spool).unwrap();
        let f = spool.join("events-2026-11-23.ndjson");
        let line = |i: u32| format!("{{\"minisoc\":{{\"source\":\"t\"}},\"raw\":\"l{i}\"}}\n");
        let l3 = line(3);
        let (head, tail) = l3.split_at(20);
        fs::write(&f, format!("{}{}{head}", line(1), line(2))).unwrap();
        let dirs = vec![spool.clone()];
        let mut seen = vec![];
        assert_eq!(
            poll(&store, &dirs, 100, |v| seen
                .push(v["raw"].as_str().unwrap().to_string())),
            2
        );
        // The writer completes the partial line, plus a malformed one.
        let mut h = fs::OpenOptions::new().append(true).open(&f).unwrap();
        h.write_all(tail.as_bytes()).unwrap();
        h.write_all(b"{not json\n").unwrap();
        let n = poll(&store, &dirs, 100, |v| {
            seen.push(v["raw"].as_str().unwrap().to_string())
        });
        assert_eq!(n, 1, "completed line read once, malformed line skipped");
        // Restart: nothing replayed.
        let store2 = Store::open(&d.join("db.sqlite3")).unwrap();
        assert_eq!(poll(&store2, &dirs, 100, |_| {}), 0);
        // Truncation restarts at 0.
        fs::write(&f, line(4)).unwrap();
        assert_eq!(
            poll(&store2, &dirs, 100, |v| seen
                .push(v["raw"].as_str().unwrap().to_string())),
            1
        );
        // New file created after start (rotation) is picked up.
        fs::write(spool.join("events-2026-11-24.ndjson"), line(5)).unwrap();
        assert_eq!(
            poll(&store2, &dirs, 100, |v| seen
                .push(v["raw"].as_str().unwrap().to_string())),
            1
        );
        assert_eq!(seen, ["l1", "l2", "l3", "l4", "l5"]);
    }
}
