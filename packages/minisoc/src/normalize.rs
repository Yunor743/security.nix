//! Convert collector records into the common MiniSOC event format.
//!
//! Spool record (one JSON object per line, written by Vector or by
//! `minisoc ingest`):
//!
//! ```json
//! {"minisoc": {"source": "rustinel", "parser": "json", "file": "...",
//!              "parse_error": null},
//!  "raw": "<original line>", "parsed": {...}}
//! ```

use crate::config::SourceCfg;
use crate::util::{get_path, is_severity, now_iso, parse_ts, sha, text, truncate};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub source: String,
    pub severity: String,
    pub event_type: String,
    pub message: String,
    /// The original parsed fields, untouched.
    pub fields: Value,
    pub raw: String,
    pub fingerprint: String,
    pub meta: Value,
}

const TS_KEYS: &[&str] = &["@timestamp", "timestamp", "time", "ts", "date", "datetime"];
const SEV_KEYS: &[&str] = &[
    "severity",
    "level",
    "log.level",
    "priority",
    "event.severity",
];
const MSG_KEYS: &[&str] = &[
    "message",
    "msg",
    "rule.name",
    "alert.signature",
    "description",
];
const TYPE_KEYS: &[&str] = &[
    "event_type",
    "event.action",
    "type",
    "event.type",
    "category",
];

fn word_severity(w: &str) -> Option<&'static str> {
    Some(match w {
        "critical" | "crit" | "emerg" | "emergency" | "alert" | "fatal" | "panic" => "critical",
        "high" | "error" | "err" | "severe" => "high",
        "medium" | "moderate" | "warning" | "warn" => "medium",
        "low" | "notice" => "low",
        "info" | "informational" | "information" | "debug" | "trace" | "verbose" => "info",
        "unknown" | "none" => "unknown",
        _ => return None,
    })
}

/// Map a source severity (word or number) to the 6 MiniSOC levels. Integers
/// 0-7 are syslog levels, larger numbers the ECS 0-100 scale.
pub fn normalize_severity(v: &Value, map: &BTreeMap<String, String>) -> Option<String> {
    let v = match v {
        Value::Array(a) => a.first()?,
        other => other,
    };
    if v.is_null() || v.is_boolean() {
        return None;
    }
    let s = text(v).trim().to_lowercase();
    if let Some(m) = map.get(&s).filter(|m| is_severity(m)) {
        return Some(m.clone());
    }
    if let Ok(n) = s.parse::<f64>() {
        let sev = if n <= 7.0 && n.fract() == 0.0 && n >= 0.0 {
            [
                "critical", "critical", "critical", "high", "medium", "low", "info", "info",
            ][n as usize]
        } else if n >= 90.0 {
            "critical"
        } else if n >= 70.0 {
            "high"
        } else if n >= 40.0 {
            "medium"
        } else if n >= 20.0 {
            "low"
        } else {
            "info"
        };
        return Some(sev.into());
    }
    word_severity(&s).map(str::to_string)
}

fn first<'a>(fields: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|k| get_path(fields, k)).find(|v| {
        !(v.is_null() || v.as_str() == Some("") || v.as_array().is_some_and(|a| a.is_empty()))
    })
}

struct Partial {
    timestamp: Option<Value>,
    severity: Option<String>,
    event_type: Option<String>,
    message: Option<String>,
}

fn generic(fields: &Value, cfg: &SourceCfg) -> Partial {
    let pick = |key: &str, defaults: &[&str]| -> Option<Value> {
        match cfg.mapping.get(key) {
            Some(p) => first(fields, &[p.as_str()]).cloned(),
            None => first(fields, defaults).cloned(),
        }
    };
    Partial {
        timestamp: pick("timestamp", TS_KEYS),
        severity: pick("severity", SEV_KEYS)
            .and_then(|v| normalize_severity(&v, &cfg.severity_map)),
        event_type: cfg
            .event_type
            .clone()
            .or_else(|| pick("event_type", TYPE_KEYS).map(|v| text(&v))),
        message: pick("message", MSG_KEYS).map(|v| text(&v)),
    }
}

/// Rustinel (>= 1.x) writes flat ECS keys: `rule.name`, `edr.rule.severity`,
/// `edr.rule.engine`, `process.executable`, ...
fn rustinel(fields: &Value, cfg: &SourceCfg) -> Partial {
    let sev = first(
        fields,
        &["edr.rule.severity", "edr.sigma.level", "event.severity"],
    )
    .and_then(|v| normalize_severity(v, &cfg.severity_map));
    let etype = match get_path(fields, "edr.rule.engine") {
        Some(e) => format!("{}_match", text(e).to_lowercase()),
        None => first(fields, &["event.action"])
            .map(text)
            .unwrap_or_else(|| "alert".into()),
    };
    let name = first(fields, &["rule.name", "message"])
        .map(text)
        .unwrap_or_else(|| "Rustinel alert".into());
    let msg = match first(fields, &["process.executable", "file.path", "process.name"]) {
        Some(t) => format!("{name} — {}", text(t)),
        None => name,
    };
    Partial {
        timestamp: first(fields, &["@timestamp", "timestamp"]).cloned(),
        severity: sev,
        event_type: Some(etype),
        message: Some(msg),
    }
}

/// Similarity key: same source/type and same message once numbers, hex ids
/// and pids are stripped. Drives AI dedup, caching and repetition counts.
pub fn fingerprint(source: &str, event_type: &str, message: &str) -> String {
    static VOLATILE: OnceLock<Regex> = OnceLock::new();
    let re =
        VOLATILE.get_or_init(|| Regex::new(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,}\b|\d+").unwrap());
    sha(&[source, event_type, &re.replace_all(message, "#")], 16)
}

pub fn normalize(record: &Value, sources: &BTreeMap<String, SourceCfg>) -> Event {
    let meta = record.get("minisoc").cloned().unwrap_or(json!({}));
    let source = meta
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let default_cfg = SourceCfg::default();
    let cfg = sources.get(&source).unwrap_or(&default_cfg);
    let parsed = record.get("parsed").filter(|v| !v.is_null());
    let raw = match record.get("raw") {
        Some(Value::String(s)) => s.clone(),
        Some(v) if !v.is_null() => v.to_string(),
        _ => parsed.map(|p| p.to_string()).unwrap_or_default(),
    };
    let parse_error = meta.get("parse_error").filter(|v| !v.is_null()).map(text);

    let (fields, partial) = match (parse_error.as_ref(), parsed) {
        (None, Some(p)) => {
            let fields = if p.is_object() {
                p.clone()
            } else {
                json!({ "value": p })
            };
            let normalizer = cfg
                .normalizer
                .as_deref()
                .unwrap_or(if source == "rustinel" {
                    "rustinel"
                } else {
                    "generic"
                });
            let part = if normalizer == "rustinel" {
                rustinel(&fields, cfg)
            } else {
                generic(&fields, cfg)
            };
            (fields, part)
        }
        _ => {
            let mut f = json!({ "_raw": raw });
            if let Some(e) = &parse_error {
                f["_parse_error"] = json!(e);
            }
            let part = Partial {
                timestamp: None,
                severity: None,
                event_type: Some("parse_error".into()),
                message: Some(format!("Unparsed line: {}", truncate(&raw, 200))),
            };
            (f, part)
        }
    };

    let timestamp = partial
        .timestamp
        .as_ref()
        .and_then(parse_ts)
        .or_else(|| meta.get("collected_at").and_then(parse_ts))
        .unwrap_or_else(now_iso);
    let severity = partial
        .severity
        .or_else(|| cfg.default_severity.clone())
        .filter(|s| is_severity(s))
        .unwrap_or_else(|| "unknown".into());
    let event_type = truncate(
        &partial
            .event_type
            .or_else(|| cfg.event_type.clone())
            .unwrap_or_else(|| "event".into()),
        128,
    );
    let message = truncate(&partial.message.unwrap_or_else(|| raw.clone()), 1000);
    Event {
        id: format!("evt-{}", sha(&[&source, &raw], 20)),
        fingerprint: fingerprint(&source, &event_type, &message),
        timestamp,
        source,
        severity,
        event_type,
        message,
        fields,
        raw,
        meta: json!({
            "file": meta.get("file"),
            "parser": meta.get("parser"),
            "parse_error": parse_error,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fictional alert shaped like Rustinel 1.8 output (flat ECS keys).
    fn rustinel_record() -> Value {
        let parsed = json!({
            "@timestamp": "2026-11-23T18:21:47.241781791Z",
            "event.kind": "alert", "event.action": "process-start", "event.severity": 50,
            "rule.name": "Execution Of Script Located In Potentially Suspicious Directory",
            "edr.rule.severity": "Medium", "edr.rule.engine": "Sigma",
            "process.executable": "/run/current-system/sw/bin/zsh", "process.pid": 4242
        });
        json!({"minisoc": {"source": "rustinel", "parser": "json"}, "raw": parsed.to_string(), "parsed": parsed})
    }

    #[test]
    fn rustinel_normalization() {
        let e = normalize(&rustinel_record(), &BTreeMap::new());
        assert_eq!(e.source, "rustinel");
        assert_eq!(e.severity, "medium");
        assert_eq!(e.event_type, "sigma_match");
        assert_eq!(e.timestamp, "2026-11-23T18:21:47.241Z");
        assert!(e.message.starts_with("Execution Of Script"));
        assert!(e.message.ends_with("/zsh"));
        assert_eq!(e.fields["process.pid"], 4242, "original fields preserved");
        assert!(e.id.starts_with("evt-"));
    }

    #[test]
    fn stable_ids_and_dedup_key() {
        let a = normalize(&rustinel_record(), &BTreeMap::new());
        let b = normalize(&rustinel_record(), &BTreeMap::new());
        assert_eq!(a.id, b.id, "same raw line => same id");
        assert_eq!(
            fingerprint("s", "t", "pid 123 started"),
            fingerprint("s", "t", "pid 98765 started")
        );
        assert_ne!(
            fingerprint("s", "t", "ssh login"),
            fingerprint("s", "t", "sudo login")
        );
    }

    #[test]
    fn generic_mapping_and_regex_output() {
        // What Vector's parse_regex / parse_grok produce: a flat object of captures.
        let rec = json!({"minisoc": {"source": "appA", "parser": "grok"},
            "raw": "2026-11-23T10:00:00Z 10.0.0.5 ERROR disk full",
            "parsed": {"timestamp": "2026-11-23T10:00:00Z", "ip": "10.0.0.5", "level": "ERROR", "message": "disk full"}});
        let mut sources = BTreeMap::new();
        sources.insert(
            "appA".into(),
            SourceCfg {
                event_type: Some("app_log".into()),
                ..Default::default()
            },
        );
        let e = normalize(&rec, &sources);
        assert_eq!(e.severity, "high");
        assert_eq!(e.event_type, "app_log");
        assert_eq!(e.message, "disk full");
        assert_eq!(e.timestamp, "2026-11-23T10:00:00.000Z");
    }

    #[test]
    fn severity_scales() {
        let m = BTreeMap::new();
        assert_eq!(normalize_severity(&json!(3), &m).unwrap(), "high"); // syslog err
        assert_eq!(normalize_severity(&json!(95), &m).unwrap(), "critical"); // ECS
        assert_eq!(normalize_severity(&json!("Warning"), &m).unwrap(), "medium");
        let mut custom = BTreeMap::new();
        custom.insert("p1".to_string(), "critical".to_string());
        assert_eq!(
            normalize_severity(&json!("P1"), &custom).unwrap(),
            "critical"
        );
        assert!(normalize_severity(&json!("weird"), &m).is_none());
    }

    #[test]
    fn parse_errors_are_kept() {
        let rec = json!({"minisoc": {"source": "appA", "parse_error": "unable to parse json"}, "raw": "{oops"});
        let e = normalize(&rec, &BTreeMap::new());
        assert_eq!(e.event_type, "parse_error");
        assert_eq!(e.severity, "unknown");
        assert_eq!(e.fields["_raw"], "{oops");
    }
}
