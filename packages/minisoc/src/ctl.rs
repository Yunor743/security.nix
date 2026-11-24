//! User commands (also what the Quickshell UI runs). They act directly on the
//! store / rule file; the running engine notices (SQLite data_version, file
//! mtime) and republishes the state.

use crate::ai::prompts;
use crate::config::{expand, Config};
use crate::filters::{self, EventView, FilterManager};
use crate::store::Store;
use crate::util::{atomic_write, ensure_dir, get_path, now_iso, truncate};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub type Res = Result<(), String>;

pub fn open_store(cfg: &Config) -> Result<Store, String> {
    ensure_dir(&cfg.state_dir(), 0o700).map_err(|e| e.to_string())?;
    Store::open(&cfg.db_path()).map_err(|e| format!("store: {e}"))
}

fn print(v: &Value, as_json: bool, human: impl FnOnce(&Value)) {
    if as_json {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    } else {
        human(v);
    }
}

fn need(store: &Store, id: &str) -> Res {
    if store.exists(id).map_err(|e| e.to_string())? {
        Ok(())
    } else {
        Err(format!("no such event: {id}"))
    }
}

pub fn status(cfg: &Config, as_json: bool) -> Res {
    let state: Value = std::fs::read(cfg.state_json())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    let store = open_store(cfg)?;
    let v = json!({
        "engine_state_file": cfg.state_json(), "engine_running": !state.is_null(),
        "engine_state_generated_at": state.get("generated_at"),
        "counts": store.counts().map_err(|e| e.to_string())?,
        "filter": fm.status(), "ai": state.get("ai").cloned().unwrap_or(json!({"enabled": cfg.ai.enable})),
    });
    print(&v, as_json, |v| {
        println!(
            "state file: {} ({})",
            cfg.state_json().display(),
            if state.is_null() {
                "absent: is minisoc-engine running?"
            } else {
                "ok"
            }
        );
        println!("events: {}", v["counts"]);
        for f in v["filter"]["files"].as_array().unwrap() {
            println!(
                "rules: {} — {} rule(s){}{}",
                f["path"].as_str().unwrap_or(""),
                f["rules"],
                f["error"]
                    .as_str()
                    .map(|e| format!(" — ERROR: {e}"))
                    .unwrap_or_default(),
                f["warning"]
                    .as_str()
                    .map(|e| format!(" — warning: {e}"))
                    .unwrap_or_default()
            );
        }
        println!("ai: {}", v["ai"]);
    });
    Ok(())
}

pub fn list(cfg: &Config, state: &str, limit: usize, as_json: bool) -> Res {
    let store = open_store(cfg)?;
    let rows = store.list(state, limit).map_err(|e| e.to_string())?;
    print(&json!(rows), as_json, |v| {
        for e in v.as_array().unwrap() {
            let flags = [
                ("P", e["pinned"] == true),
                (
                    if e["verdict"] == "tp" { "T" } else { "X" },
                    e["closed"] == true,
                ),
                ("F", !e["filtered_by"].is_null()),
                ("A", e["analyzed"] == true),
            ]
            .iter()
            .map(|(f, on)| if *on { *f } else { "." })
            .collect::<String>();
            println!(
                "{}  {}  {:8} {:12} {} x{}  {}",
                e["id"].as_str().unwrap_or(""),
                flags,
                e["severity"].as_str().unwrap_or(""),
                e["source"].as_str().unwrap_or(""),
                e["timestamp"].as_str().unwrap_or(""),
                e["occurrences"],
                e["message"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}

pub fn show(cfg: &Config, id: &str, as_json: bool) -> Res {
    let store = open_store(cfg)?;
    let mut v = store
        .get(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no such event: {id}"))?;
    // Rule responsible for the exclusion, if any (current rule set).
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    if let Some(rid) = v["filtered_by"].as_str() {
        v["filter_rule"] = fm
            .ruleset
            .get(rid)
            .map(|r| r.summary())
            .unwrap_or(json!({"id": rid, "note": "rule no longer present"}));
    }
    print(&v, as_json, |v| {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default())
    });
    Ok(())
}

pub fn set_pin(cfg: &Config, id: &str, pinned: bool) -> Res {
    let store = open_store(cfg)?;
    need(&store, id)?;
    store
        .set_pinned(id, pinned, "user")
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Close an alert as true positive (`tp`) or false positive (`fp`).
pub fn close(cfg: &Config, id: &str, verdict: &str, reason: Option<&str>) -> Res {
    let store = open_store(cfg)?;
    need(&store, id)?;
    store
        .close(id, verdict, "user", json!({"reason": reason}))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn close_all_fp(cfg: &Config, reason: Option<&str>) -> Res {
    let store = open_store(cfg)?;
    let n = store
        .close_all_fp("user", json!({"reason": reason, "bulk": true}))
        .map_err(|e| e.to_string())?;
    println!("closed {n} alert(s) as false positive (pinned alerts kept; re-open with `minisoc reopen <id>`)");
    Ok(())
}

pub fn restore(cfg: &Config, id: &str) -> Res {
    let store = open_store(cfg)?;
    need(&store, id)?;
    store.restore(id, "user").map_err(|e| e.to_string())?;
    Ok(())
}

pub fn analyze(cfg: &Config, id: &str) -> Res {
    if !cfg.ai.enable {
        return Err("AI analysis is disabled (services.minisoc.ai.enable)".into());
    }
    let store = open_store(cfg)?;
    need(&store, id)?;
    store.request_analysis(id).map_err(|e| e.to_string())?;
    store
        .history(Some(id), "user", "analysis_requested", json!({}))
        .map_err(|e| e.to_string())
}

pub fn explain(cfg: &Config, id: &str, as_json: bool) -> Res {
    let store = open_store(cfg)?;
    let e = store
        .event(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no such event: {id}"))?;
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    let view = EventView {
        source: &e.source,
        severity: &e.severity,
        event_type: &e.event_type,
        message: &e.message,
        fields: &e.fields,
    };
    let ex = fm.ruleset.explain(&view);
    let pinned = store.is_pinned(id).unwrap_or(false);
    let v = json!({"event": id, "pinned": pinned, "decision": fm.ruleset.matching(&view).map(|r| r.id.clone()), "rules": ex});
    print(&v, as_json, |v| {
        match v["decision"].as_str() {
            Some(r) if pinned => {
                println!("{id}: would be excluded by '{r}' but is PINNED (always shown)")
            }
            Some(r) => println!("{id}: EXCLUDED by rule '{r}' (first matching rule wins)"),
            None => println!("{id}: KEPT (no enabled rule matches)"),
        }
        for r in v["rules"].as_array().unwrap() {
            println!(
                "  rule {} [{}]{}",
                r["rule"].as_str().unwrap_or(""),
                if r["matched"] == true {
                    "match"
                } else {
                    "no match"
                },
                if r["enabled"] == false {
                    " (disabled)"
                } else {
                    ""
                }
            );
            for t in r["trace"].as_array().unwrap() {
                println!(
                    "    {} {} {}",
                    if t["matched"] == true { "✓" } else { "✗" },
                    t["condition"].as_str().unwrap_or(""),
                    t.get("expected").map(|x| x.to_string()).unwrap_or_default()
                );
            }
        }
    });
    Ok(())
}

// ------------------------------------------------------------------ filters

pub fn draft_rule(
    cfg: &Config,
    id: &str,
    fields: &[String],
    with_message: bool,
    rule_id: Option<&str>,
) -> Result<Value, String> {
    let store = open_store(cfg)?;
    let e = store
        .event(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no such event: {id}"))?;
    let mut m = Map::new();
    m.insert("source".into(), json!(e.source));
    m.insert("event_type".into(), json!(e.event_type));
    if with_message {
        m.insert("message".into(), json!({"equals": e.message}));
    }
    let mut fm = Map::new();
    for p in fields {
        let v = get_path(&e.fields, p).ok_or_else(|| format!("event has no field '{p}'"))?;
        if v.is_object()
            || v.is_array()
                && v.as_array()
                    .unwrap()
                    .iter()
                    .any(|x| x.is_object() || x.is_array())
        {
            return Err(format!("field '{p}' is not a scalar"));
        }
        fm.insert(p.clone(), v.clone());
    }
    if !fm.is_empty() {
        m.insert("fields".into(), Value::Object(fm));
    }
    if !with_message && fields.is_empty() {
        return Err(
            "refusing a rule on source + event_type only: keep the message or add --field".into(),
        );
    }
    let stamp = now_iso().replace([':', '-', '.'], "");
    Ok(json!({
        "id": rule_id.map(String::from).unwrap_or_else(|| format!("user-{}-{stamp}", &e.id[4..12.min(e.id.len())])),
        "enabled": true,
        "description": format!("Created from alert: {}", truncate(&e.message, 120)),
        "match": Value::Object(m),
        "action": "exclude",
        "metadata": {"created_by": "user", "created_at": now_iso(), "source_event": e.id},
    }))
}

pub fn filter_draft(
    cfg: &Config,
    id: &str,
    fields: &[String],
    with_message: bool,
    as_json: bool,
) -> Res {
    let rule = draft_rule(cfg, id, fields, with_message, None)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rule).unwrap());
    } else {
        print!("{}", serde_yaml::to_string(&vec![rule]).unwrap_or_default());
    }
    Ok(())
}

pub fn filter_create(
    cfg: &Config,
    id: &str,
    fields: &[String],
    with_message: bool,
    rule_id: Option<&str>,
) -> Res {
    let rule = draft_rule(cfg, id, fields, with_message, rule_id)?;
    let path = cfg.user_filter_file();
    filters::append_rule(
        &path,
        &rule,
        Some(&cfg.backup_dir()),
        cfg.filter.max_backups,
    )?;
    let store = open_store(cfg)?;
    store
        .history(
            Some(id),
            "user",
            "filter_created",
            json!({"rule_id": rule["id"], "file": path}),
        )
        .map_err(|e| e.to_string())?;
    println!(
        "added rule {} to {}",
        rule["id"].as_str().unwrap_or(""),
        path.display()
    );
    Ok(())
}

pub fn filter_validate(cfg: &Config, file: Option<&str>) -> Res {
    let path = file
        .map(PathBuf::from)
        .unwrap_or_else(|| cfg.user_filter_file());
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let rules = filters::parse_document(&text, &path.to_string_lossy())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    println!("{}: valid, {} rule(s)", path.display(), rules.len());
    Ok(())
}

pub fn filter_list(cfg: &Config, as_json: bool) -> Res {
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    let store = open_store(cfg)?;
    let stats = store
        .filter_stats(cfg.filter.recent_days)
        .map_err(|e| e.to_string())?;
    let rules: Vec<Value> = fm
        .ruleset
        .rules
        .iter()
        .map(|r| {
            let mut v = r.summary();
            let s = stats.get(&r.id);
            v["hits"] = s.map(|s| s["hits"].clone()).unwrap_or(json!(0));
            v["since"] = s.map(|s| s["since"].clone()).unwrap_or(Value::Null);
            v["hidden"] = s.map(|s| s["hidden"].clone()).unwrap_or(json!(0));
            v["recent_hits"] = s.map(|s| s["recent_hits"].clone()).unwrap_or(json!(0));
            v["owner"] = json!(fm.owner(std::path::Path::new(&r.origin)));
            v
        })
        .collect();
    let v = json!({"status": fm.status(), "rules": rules});
    print(&v, as_json, |v| {
        for r in v["rules"].as_array().unwrap() {
            println!(
                "{} [{}, {}] {} filtered since {}, {} in {} d {} — {}",
                r["id"].as_str().unwrap_or(""),
                r["owner"].as_str().unwrap_or("?"),
                if r["enabled"] == true { "on" } else { "off" },
                r["hits"],
                r["since"].as_str().unwrap_or("its creation (engine not run yet)"),
                r["recent_hits"],
                cfg.filter.recent_days.max(1),
                r["generated_by"]
                    .as_str()
                    .map(|g| format!("({g})"))
                    .unwrap_or_default(),
                r["description"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}

pub fn filter_backups(cfg: &Config) -> Res {
    for b in filters::list_backups(&cfg.backup_dir()) {
        println!("{}", b.display());
    }
    Ok(())
}

pub fn filter_rollback(cfg: &Config, to: Option<&str>) -> Res {
    let backups = filters::list_backups(&cfg.backup_dir());
    let target = match to {
        Some(t) => PathBuf::from(t),
        None => backups.first().cloned().ok_or("no backup available")?,
    };
    filters::restore_backup(
        &cfg.user_filter_file(),
        &target,
        &cfg.backup_dir(),
        cfg.filter.max_backups,
    )?;
    let store = open_store(cfg)?;
    store
        .history(None, "user", "filter_rollback", json!({"restored": target}))
        .map_err(|e| e.to_string())?;
    println!("restored {}", target.display());
    Ok(())
}

// ---------------------------------------------------------------- proposals

pub fn proposals(cfg: &Config, status: Option<&str>, as_json: bool) -> Res {
    let store = open_store(cfg)?;
    let rows = store.proposals(status, 200).map_err(|e| e.to_string())?;
    print(&json!(rows), as_json, |v| {
        for p in v.as_array().unwrap() {
            println!(
                "#{} {} {} conf={} event={} — {}",
                p["id"],
                p["kind"].as_str().unwrap_or(""),
                p["status"].as_str().unwrap_or(""),
                p["confidence"],
                p["event_id"].as_str().unwrap_or(""),
                p["reason"].as_str().unwrap_or("")
            );
        }
    });
    Ok(())
}

pub fn proposal_decide(cfg: &Config, id: i64, accept: bool) -> Res {
    let store = open_store(cfg)?;
    let p = store
        .proposal(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no such proposal: {id}"))?;
    if p["status"] != "pending" {
        return Err(format!("proposal #{id} is {}, not pending", p["status"]));
    }
    let event = p["event_id"].as_str().unwrap_or("");
    if accept {
        match p["kind"].as_str() {
            Some("discard") => {
                store.close(event, "fp", "user", json!({"via": "ai_proposal", "proposal": id, "reasons": p["payload"]["reasons"]}))
                    .map_err(|e| e.to_string())?;
            }
            Some("filter") => {
                let rule = p["payload"]
                    .get("rule")
                    .filter(|r| r.is_object())
                    .ok_or("proposal has no valid rule")?;
                // AI-generated: the rule joins the AI file, not the user's.
                filters::append_rule(
                    &cfg.ai_filter_file(),
                    rule,
                    Some(&cfg.ai_backup_dir()),
                    cfg.filter.max_backups,
                )?;
                store
                    .history(
                        Some(event),
                        "user",
                        "filter_created",
                        json!({"rule_id": rule["id"], "via": "ai_proposal"}),
                    )
                    .map_err(|e| e.to_string())?;
            }
            Some("review") => {
                // Re-checked against the current rules and closures.
                crate::ai::review::accept(cfg, &store, &p["payload"])?;
                store
                    .history(
                        None,
                        "user",
                        &format!(
                            "filter_review_{}",
                            p["payload"]["action"].as_str().unwrap_or("change")
                        ),
                        json!({"rule_id": p["payload"]["id"], "via": "ai_proposal", "proposal": id}),
                    )
                    .map_err(|e| e.to_string())?;
            }
            k => return Err(format!("unknown proposal kind {k:?}")),
        }
    }
    store
        .set_proposal_status(id, if accept { "accepted" } else { "rejected" })
        .map_err(|e| e.to_string())?;
    store
        .history(
            Some(event),
            "user",
            if accept {
                "proposal_accepted"
            } else {
                "proposal_rejected"
            },
            json!({"proposal": id, "kind": p["kind"]}),
        )
        .map_err(|e| e.to_string())
}

// ------------------------------------------------------------------- ingest

/// Ingest lines without the collector: each line becomes a spool record in
/// the user inbox, processed by the engine like Vector output.
pub fn ingest(cfg: &Config, source: &str, parser: &str, file: Option<&str>) -> Res {
    use std::io::BufRead;
    let input: Box<dyn BufRead> = match file {
        Some("-") | None => Box::new(std::io::BufReader::new(std::io::stdin())),
        Some(f) => Box::new(std::io::BufReader::new(
            std::fs::File::open(f).map_err(|e| format!("{f}: {e}"))?,
        )),
    };
    let dir = cfg.inbox_dir();
    ensure_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    let path = dir.join(format!(
        "ingest-{}.ndjson",
        chrono::Utc::now().format("%Y-%m-%d")
    ));
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    let mut n = 0;
    for line in input.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let mut meta = json!({"source": source, "parser": parser, "file": file.unwrap_or("-"), "collected_at": now_iso()});
        let parsed = match parser {
            "json" => match serde_json::from_str::<Value>(&line) {
                Ok(v) => v,
                Err(e) => {
                    meta["parse_error"] = json!(e.to_string());
                    Value::Null
                }
            },
            _ => json!({"message": line}),
        };
        buf.push_str(&json!({"minisoc": meta, "raw": line, "parsed": parsed}).to_string());
        buf.push('\n');
        n += 1;
    }
    out.write_all(buf.as_bytes()).map_err(|e| e.to_string())?;
    println!("queued {n} record(s) in {}", path.display());
    Ok(())
}

// ------------------------------------------------------------------ prompts

pub fn prompts_cmd(cfg: &Config, action: &str, name: Option<&str>) -> Res {
    let dir = expand(&cfg.ai.prompt_override_dir);
    let check = |n: Option<&str>| -> Result<String, String> {
        let n = n.ok_or("prompt name required")?;
        if !prompts::NAMES.contains(&n) {
            return Err(format!(
                "unknown prompt '{n}' (one of: {})",
                prompts::NAMES.join(", ")
            ));
        }
        Ok(n.to_string())
    };
    match action {
        "list" => {
            for n in prompts::NAMES {
                println!("{n}: {}", prompts::resolve(&cfg.ai, n).1);
            }
        }
        "show" => print!("{}", prompts::resolve(&cfg.ai, &check(name)?).0),
        "path" => println!("{}", dir.join(format!("{}.md", check(name)?)).display()),
        "edit" => {
            let n = check(name)?;
            let path = dir.join(format!("{n}.md"));
            if !path.exists() {
                ensure_dir(&dir, 0o700).map_err(|e| e.to_string())?;
                atomic_write(&path, prompts::resolve(&cfg.ai, &n).0.as_bytes(), 0o600)
                    .map_err(|e| e.to_string())?;
            }
            let editor = std::env::var("VISUAL")
                .or_else(|_| std::env::var("EDITOR"))
                .ok();
            let (cmd, args) = match editor {
                Some(e) if std::io::IsTerminal::is_terminal(&std::io::stdout()) => {
                    (e, vec![path.clone()])
                }
                _ => ("xdg-open".to_string(), vec![path.clone()]),
            };
            let st = std::process::Command::new(&cmd)
                .args(&args)
                .status()
                .map_err(|e| format!("{cmd}: {e}"))?;
            if !st.success() {
                return Err(format!("{cmd} exited with {st}"));
            }
        }
        "reset" => {
            let path = dir.join(format!("{}.md", check(name)?));
            let _ = std::fs::remove_file(&path);
            println!("removed override {}", path.display());
        }
        other => {
            return Err(format!(
                "unknown action '{other}' (list, show, path, edit, reset)"
            ))
        }
    }
    Ok(())
}
