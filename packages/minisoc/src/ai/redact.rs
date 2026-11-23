//! Privacy: build the (minimal, redacted, size-bounded) payload sent to the
//! model. The raw log line is not sent unless `privacy.send_raw` is set.

use crate::config::PrivacyCfg;
use crate::normalize::Event;
use crate::util::{sha, truncate};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::sync::OnceLock;

fn ip_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b")
            .unwrap()
    })
}

fn path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:/[A-Za-z0-9._@+\-]+){2,}").unwrap())
}

fn home_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"/home/[^/\s\x22']+").unwrap())
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub struct Redactor<'a> {
    cfg: &'a PrivacyCfg,
    users: Vec<String>,
}

impl<'a> Redactor<'a> {
    pub fn new(cfg: &'a PrivacyCfg, event: &Event) -> Self {
        let mut users: Vec<String> = vec![];
        if cfg.redact_users {
            if let Ok(u) = std::env::var("USER") {
                users.push(u);
            }
            for p in [
                "user.name",
                "related.user",
                "process.user.name",
                "username",
                "user",
            ] {
                match crate::util::get_path(&event.fields, p) {
                    Some(Value::String(s)) => users.push(s.clone()),
                    Some(Value::Array(a)) => {
                        users.extend(a.iter().filter_map(|x| x.as_str().map(String::from)))
                    }
                    _ => {}
                }
            }
            users.retain(|u| u.len() >= 2 && u != "root");
            users.sort();
            users.dedup();
        }
        Self { cfg, users }
    }

    pub fn string(&self, s: &str) -> String {
        let mut out = s.to_string();
        if self.cfg.redact_users {
            out = home_re().replace_all(&out, "/home/<user>").into_owned();
            for u in &self.users {
                let re = Regex::new(&format!(r"\b{}\b", regex::escape(u))).unwrap();
                out = re.replace_all(&out, "<user>").into_owned();
            }
        }
        if self.cfg.redact_private_ips {
            out = ip_re()
                .replace_all(&out, |c: &regex::Captures| {
                    let m = &c[0];
                    match m.parse::<IpAddr>() {
                        Ok(ip) if is_private(&ip) => format!("<private-ip-{}>", sha(&[m], 6)),
                        _ => m.to_string(),
                    }
                })
                .into_owned();
        }
        if self.cfg.redact_paths {
            out = path_re()
                .replace_all(&out, |c: &regex::Captures| {
                    let m = &c[0];
                    let base = m.rsplit('/').next().unwrap_or("");
                    format!("<path:{}…/{base}>", sha(&[m], 6))
                })
                .into_owned();
        }
        out
    }

    fn excluded(&self, path: &str) -> bool {
        self.cfg
            .exclude_fields
            .iter()
            .any(|x| path == x || path.starts_with(&format!("{x}.")))
    }

    pub fn value(&self, v: &Value, path: &str) -> Value {
        match v {
            Value::String(s) => json!(self.string(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.value(x, path)).collect()),
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, x) in m {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    if !self.excluded(&p) {
                        out.insert(k.clone(), self.value(x, &p));
                    }
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

fn shrink(v: &Value, max_str: usize) -> Value {
    match v {
        Value::String(s) => json!(truncate(s, max_str)),
        Value::Array(a) => Value::Array(a.iter().take(20).map(|x| shrink(x, max_str)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), shrink(x, max_str)))
                .collect(),
        ),
        o => o.clone(),
    }
}

/// The payload describing one event to the model.
pub fn payload(event: &Event, cfg: &PrivacyCfg, max_bytes: usize, extra: Value) -> String {
    let r = Redactor::new(cfg, event);
    let mut p = json!({
        "source": event.source,
        "timestamp": event.timestamp,
        "severity": event.severity,
        "event_type": event.event_type,
        "message": r.string(&event.message),
        "fields": r.value(&event.fields, ""),
    });
    if cfg.send_raw {
        p["raw"] = json!(r.string(&event.raw));
    }
    if let (Value::Object(m), Value::Object(x)) = (&mut p, extra) {
        m.extend(x);
    }
    let mut s = p.to_string();
    for max_str in [512, 160, 64] {
        if s.len() <= max_bytes {
            break;
        }
        p.as_object_mut().unwrap().remove("raw");
        p = shrink(&p, max_str);
        s = p.to_string();
    }
    if s.len() > max_bytes {
        // Last resort: keep only the normalized summary.
        p["fields"] = json!({"_truncated": true});
        s = p.to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(fields: Value, msg: &str) -> Event {
        Event {
            id: "evt-x".into(),
            timestamp: "2026-11-23T00:00:00.000Z".into(),
            source: "s".into(),
            severity: "low".into(),
            event_type: "t".into(),
            message: msg.into(),
            fields,
            raw: "RAWLINE".into(),
            fingerprint: "fp".into(),
            meta: json!({}),
        }
    }

    #[test]
    fn redacts_private_ips_users_paths_and_fields() {
        let cfg = PrivacyCfg {
            redact_paths: true,
            exclude_fields: vec!["secret".into()],
            ..Default::default()
        };
        let e = ev(
            json!({"src": "192.168.1.10", "dst": "8.8.8.8", "user.name": "alice",
            "cmd": "/home/alice/bin/tool --user alice", "secret": {"token": "abc"}}),
            "login from 10.0.0.2 by alice",
        );
        let out: Value = serde_json::from_str(&payload(&e, &cfg, 10000, json!({}))).unwrap();
        let s = out.to_string();
        assert!(
            !s.contains("192.168.1.10") && !s.contains("10.0.0.2"),
            "private IPs redacted"
        );
        assert!(s.contains("8.8.8.8"), "public IPs kept");
        assert!(!s.contains("alice"), "user names redacted");
        assert!(!s.contains("abc"), "excluded field dropped");
        assert!(!s.contains("RAWLINE"), "raw not sent by default");
        assert!(s.contains("<path:"));
    }

    #[test]
    fn bounded_size() {
        let cfg = PrivacyCfg::default();
        let e = ev(json!({"big": "x".repeat(20000)}), "m");
        assert!(payload(&e, &cfg, 1000, json!({})).len() <= 1000);
    }
}
