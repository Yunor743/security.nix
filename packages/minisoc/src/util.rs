//! Shared helpers: severities, timestamps, dotted-path lookup, hashing,
//! atomic writes and a minimal stderr logger (the journal captures it).

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

/// Ordered from least to most severe. `unknown` sorts lowest for display but
/// every automatic decision treats it conservatively (see ai::policy).
pub const SEVERITIES: [&str; 6] = ["unknown", "info", "low", "medium", "high", "critical"];

pub fn sev_rank(sev: &str) -> usize {
    SEVERITIES.iter().position(|s| *s == sev).unwrap_or(0)
}

pub fn is_severity(sev: &str) -> bool {
    SEVERITIES.contains(&sev)
}

pub fn now_iso() -> String {
    format_ts(Utc::now())
}

pub fn format_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse RFC 3339 / ISO 8601 strings (any fractional precision) or epoch
/// seconds / milliseconds into the canonical `...T..:..:..mmmZ` form.
pub fn parse_ts(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => {
            let f = n.as_f64()?;
            let secs = if f > 1e11 { f / 1000.0 } else { f };
            let dt = Utc
                .timestamp_opt(secs.trunc() as i64, ((secs.fract()) * 1e9) as u32)
                .single()?;
            Some(format_ts(dt))
        }
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if let Ok(f) = s.parse::<f64>() {
                return parse_ts(&serde_json::json!(f));
            }
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                return Some(format_ts(dt.with_timezone(&Utc)));
            }
            for fmt in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
                if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
                    return Some(format_ts(dt.with_timezone(&Utc)));
                }
            }
            for fmt in [
                "%Y-%m-%dT%H:%M:%S%.f",
                "%Y-%m-%d %H:%M:%S%.f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ] {
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
                    return Some(format_ts(Utc.from_utc_datetime(&dt)));
                }
            }
            None
        }
        _ => None,
    }
}

/// Look up `path` in `obj`, accepting flat dotted keys (ECS style,
/// `{"process.name": ..}`), nested objects, or any mix of both.
pub fn get_path<'a>(obj: &'a Value, path: &str) -> Option<&'a Value> {
    let map = obj.as_object()?;
    if path.is_empty() {
        return None;
    }
    if let Some(v) = map.get(path) {
        return Some(v);
    }
    let parts: Vec<&str> = path.split('.').collect();
    for i in (1..parts.len()).rev() {
        let head = parts[..i].join(".");
        if let Some(sub) = map.get(&head) {
            if let Some(found) = get_path(sub, &parts[i..].join(".")) {
                return Some(found);
            }
        }
    }
    None
}

pub fn sha(parts: &[&str], len: usize) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    hex[..len.min(hex.len())].to_string()
}

pub fn truncate(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let mut out: String = s.chars().take(limit.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Text form of a JSON value for display / string matching.
pub fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(", "),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn ensure_dir(path: &Path, mode: u32) -> std::io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Write atomically (temp file in the same dir + fsync + rename): a reader
/// never observes a partially written file.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

// ------------------------------------------------------------------ logging

static LEVEL: AtomicU8 = AtomicU8::new(2);

pub fn set_log_level(level: &str) {
    let l = match level {
        "error" => 0,
        "warn" | "warning" => 1,
        "debug" | "trace" => 3,
        _ => 2,
    };
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn log_enabled(level: u8) -> bool {
    level <= LEVEL.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! log_at {
    ($lvl:expr, $tag:expr, $($arg:tt)*) => {
        if $crate::util::log_enabled($lvl) { eprintln!("{} {}", $tag, format!($($arg)*)); }
    };
}
#[macro_export]
macro_rules! error { ($($a:tt)*) => { $crate::log_at!(0, "<3>error:", $($a)*) }; }
#[macro_export]
macro_rules! warn { ($($a:tt)*) => { $crate::log_at!(1, "<4>warn:", $($a)*) }; }
#[macro_export]
macro_rules! info { ($($a:tt)*) => { $crate::log_at!(2, "<6>info:", $($a)*) }; }
#[macro_export]
macro_rules! debug { ($($a:tt)*) => { $crate::log_at!(3, "<7>debug:", $($a)*) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_nanosecond_rfc3339() {
        assert_eq!(
            parse_ts(&json!("2026-11-23T18:21:47.241781791Z")).unwrap(),
            "2026-11-23T18:21:47.241Z"
        );
        assert_eq!(
            parse_ts(&json!(1_700_000_000)).unwrap(),
            "2023-11-14T22:13:20.000Z"
        );
        assert_eq!(
            parse_ts(&json!(1_700_000_000_000u64)).unwrap(),
            "2023-11-14T22:13:20.000Z"
        );
        assert!(parse_ts(&json!("not a date")).is_none());
    }

    #[test]
    fn dotted_path_lookup() {
        let v = json!({"process.name": "zsh", "source": {"ip": "1.2.3.4"}, "a.b": {"c": 1}});
        assert_eq!(get_path(&v, "process.name").unwrap(), "zsh");
        assert_eq!(get_path(&v, "source.ip").unwrap(), "1.2.3.4");
        assert_eq!(get_path(&v, "a.b.c").unwrap(), 1);
        assert!(get_path(&v, "missing").is_none());
    }
}
