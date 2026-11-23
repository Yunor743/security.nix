//! Alert filter engine (`alert_filter.yaml`).
//!
//! ```yaml
//! version: 1
//! filters:
//!   - id: ignore_localhost_noise        # unique, [A-Za-z0-9_.:-]{1,128}
//!     enabled: true                     # optional (default true)
//!     description: Ignore localhost info
//!     match:                            # condition (keys are ANDed)
//!       severity: [info]
//!       source_ip: {cidr: 127.0.0.0/8}
//!     action: exclude                   # only action for now
//!     metadata: {}                      # optional, free-form
//! ```
//!
//! Condition keys: `source`, `severity`, `event_type`, `message`,
//! `source_ip`, `dest_ip` (matchers), `fields: {<dotted.path>: <matcher>}`,
//! `all: [..]`, `any: [..]`, `not: {..}`.
//! Matcher: scalar (equality), list (membership), or a mapping of operators
//! that must all hold: equals, not_equals, in, contains, prefix, suffix,
//! regex, cidr, exists. A list-valued field matches when any element does.
//!
//! Safety: a file failing validation is rejected as a whole and its last
//! valid version stays in force (also persisted across restarts), so a broken
//! edit never makes every alert disappear. Pinned events are never hidden by
//! any rule (enforced by the store).

use crate::util::{atomic_write, ensure_dir, get_path, is_severity, sha, text, SEVERITIES};
use crate::{error, info};
use ipnet::IpNet;
use regex::Regex;
use serde_json::{json, Value};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const LEAF_KEYS: [&str; 6] = [
    "source",
    "severity",
    "event_type",
    "message",
    "source_ip",
    "dest_ip",
];
const OPS: [&str; 9] = [
    "equals",
    "not_equals",
    "in",
    "contains",
    "prefix",
    "suffix",
    "regex",
    "cidr",
    "exists",
];
const RULE_KEYS: [&str; 6] = [
    "id",
    "enabled",
    "description",
    "match",
    "action",
    "metadata",
];
const MAX_REGEX: usize = 512;

pub const SOURCE_IP_PATHS: [&str; 7] = [
    "source.ip",
    "src_ip",
    "source_ip",
    "src",
    "client.ip",
    "srcip",
    "ip",
];
pub const DEST_IP_PATHS: [&str; 7] = [
    "destination.ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "dst",
    "server.ip",
    "dstip",
];

pub const SEED: &str = "\
# MiniSOC alert filter rules — see the security.nix README (MiniSOC section).
# Edits are picked up automatically. An invalid file is ignored as a whole and
# the last valid version stays in force: check `minisoc status`.
version: 1
filters: []
#  - id: ignore_known_test_alert
#    enabled: true
#    description: Ignore known test events
#    match:
#      source: rustinel
#      event_type: sigma_match
#      message: {contains: \"Whoami\"}
#    action: exclude
";

pub type RuleError = String;

// ------------------------------------------------------------------ matchers

#[derive(Debug)]
enum Op {
    Equals(Value),
    NotEquals(Value),
    In(Vec<Value>),
    Contains(String),
    Prefix(String),
    Suffix(String),
    Regex(Regex),
    Cidr(Vec<IpNet>),
    Exists(bool),
}

fn is_scalar(v: &Value) -> bool {
    matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

fn eq(a: &Value, b: &Value) -> bool {
    a == b
        || text(a).eq_ignore_ascii_case(&text(b)) && (a.is_boolean() || b.is_boolean())
        || text(a) == text(b)
}

#[derive(Debug)]
pub struct Matcher {
    spec: Value,
    ops: Vec<Op>,
}

impl Matcher {
    fn new(spec: &Value, w: &str, severity: bool) -> Result<Self, RuleError> {
        let mut ops = vec![];
        match spec {
            v if is_scalar(v) => ops.push(Op::Equals(v.clone())),
            Value::Array(a) => {
                if a.is_empty() || !a.iter().all(is_scalar) {
                    return Err(format!("{w}: list must be a non-empty list of scalars"));
                }
                ops.push(Op::In(a.clone()));
            }
            Value::Object(m) => {
                if m.is_empty() {
                    return Err(format!("{w}: empty operator mapping"));
                }
                for (op, arg) in m {
                    ops.push(Self::compile(op, arg, &format!("{w}.{op}"))?);
                }
            }
            other => return Err(format!("{w}: unsupported matcher {other}")),
        }
        if severity {
            for op in &ops {
                let vals: Vec<&Value> = match op {
                    Op::Equals(v) | Op::NotEquals(v) => vec![v],
                    Op::In(v) => v.iter().collect(),
                    _ => continue,
                };
                if let Some(bad) = vals.iter().find(|v| !is_severity(&text(v))) {
                    return Err(format!(
                        "{w}: invalid severity {bad} (allowed: {})",
                        SEVERITIES.join(", ")
                    ));
                }
            }
        }
        Ok(Self {
            spec: spec.clone(),
            ops,
        })
    }

    fn compile(op: &str, arg: &Value, w: &str) -> Result<Op, RuleError> {
        let s = || -> Result<String, RuleError> {
            if !is_scalar(arg) {
                return Err(format!("{w}: expected a scalar"));
            }
            let t = text(arg);
            if t.is_empty() {
                return Err(format!("{w}: empty string would match everything"));
            }
            Ok(t)
        };
        Ok(match op {
            "equals" | "not_equals" => {
                if !is_scalar(arg) {
                    return Err(format!("{w}: expected a scalar"));
                }
                if op == "equals" {
                    Op::Equals(arg.clone())
                } else {
                    Op::NotEquals(arg.clone())
                }
            }
            "in" => match arg {
                Value::Array(a) if !a.is_empty() && a.iter().all(is_scalar) => Op::In(a.clone()),
                _ => return Err(format!("{w}: expected a non-empty list of scalars")),
            },
            "contains" => Op::Contains(s()?),
            "prefix" => Op::Prefix(s()?),
            "suffix" => Op::Suffix(s()?),
            "regex" => {
                let p = arg
                    .as_str()
                    .filter(|p| !p.is_empty() && p.len() <= MAX_REGEX)
                    .ok_or_else(|| format!("{w}: expected a pattern of 1..{MAX_REGEX} chars"))?;
                Op::Regex(Regex::new(p).map_err(|e| format!("{w}: invalid pattern: {e}"))?)
            }
            "cidr" => {
                let items: Vec<Value> = match arg {
                    Value::Array(a) => a.clone(),
                    v => vec![v.clone()],
                };
                let mut nets = vec![];
                for n in items {
                    let t = text(&n);
                    let net = t
                        .parse::<IpNet>()
                        .or_else(|_| t.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| format!("{w}: invalid network '{t}'"))?;
                    nets.push(net);
                }
                Op::Cidr(nets)
            }
            "exists" => Op::Exists(
                arg.as_bool()
                    .ok_or_else(|| format!("{w}: expected true/false"))?,
            ),
            _ => {
                return Err(format!(
                    "{w}: unknown operator (allowed: {})",
                    OPS.join(", ")
                ))
            }
        })
    }

    pub fn test(&self, value: Option<&Value>) -> bool {
        self.ops.iter().all(|op| Self::test_one(op, value))
    }

    fn test_one(op: &Op, value: Option<&Value>) -> bool {
        let value = value.filter(|v| !v.is_null());
        if let Op::Exists(want) = op {
            return value.is_some() == *want;
        }
        let Some(value) = value else {
            return matches!(op, Op::NotEquals(_));
        };
        let values: Vec<&Value> = match value {
            Value::Array(a) => a.iter().collect(),
            v => vec![v],
        };
        if let Op::NotEquals(x) = op {
            return !values.iter().any(|v| eq(v, x));
        }
        values.iter().filter(|v| is_scalar(v)).any(|v| {
            let s = text(v);
            match op {
                Op::Equals(x) => eq(v, x),
                Op::In(xs) => xs.iter().any(|x| eq(v, x)),
                Op::Contains(x) => s.contains(x.as_str()),
                Op::Prefix(x) => s.starts_with(x.as_str()),
                Op::Suffix(x) => s.ends_with(x.as_str()),
                Op::Regex(r) => r.is_match(&s),
                Op::Cidr(nets) => s
                    .trim()
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| nets.iter().any(|n| n.contains(&ip))),
                Op::NotEquals(_) | Op::Exists(_) => unreachable!(),
            }
        })
    }
}

// ---------------------------------------------------------------- conditions

#[derive(Debug)]
enum Leaf {
    Key(&'static str),
    Field(String),
}

#[derive(Debug)]
enum Combinator {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
}

#[derive(Debug)]
pub struct Condition {
    leaves: Vec<(Leaf, Matcher)>,
    children: Vec<Combinator>,
}

pub fn resolve_ip<'a>(fields: &'a Value, paths: &[&str]) -> Option<&'a Value> {
    paths
        .iter()
        .filter_map(|p| get_path(fields, p))
        .find(|v| !v.is_null() && v.as_str() != Some(""))
}

/// The view of an event the filter engine evaluates.
pub struct EventView<'a> {
    pub source: &'a str,
    pub severity: &'a str,
    pub event_type: &'a str,
    pub message: &'a str,
    pub fields: &'a Value,
}

impl Condition {
    pub fn new(spec: &Value, w: &str) -> Result<Self, RuleError> {
        let m = spec
            .as_object()
            .filter(|m| !m.is_empty())
            .ok_or_else(|| format!("{w}: a condition must be a non-empty mapping"))?;
        let mut c = Condition {
            leaves: vec![],
            children: vec![],
        };
        for (k, v) in m {
            let wk = format!("{w}.{k}");
            if let Some(key) = LEAF_KEYS.iter().find(|x| **x == k) {
                c.leaves
                    .push((Leaf::Key(key), Matcher::new(v, &wk, *key == "severity")?));
            } else if k == "fields" {
                let fm = v
                    .as_object()
                    .filter(|m| !m.is_empty())
                    .ok_or_else(|| format!("{wk}: expected a non-empty mapping of field paths"))?;
                for (path, ms) in fm {
                    if path.is_empty() {
                        return Err(format!("{wk}: empty field path"));
                    }
                    c.leaves.push((
                        Leaf::Field(path.clone()),
                        Matcher::new(ms, &format!("{wk}.{path}"), false)?,
                    ));
                }
            } else if k == "all" || k == "any" {
                let list = v
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| format!("{wk}: expected a non-empty list of conditions"))?;
                let subs = list
                    .iter()
                    .enumerate()
                    .map(|(i, s)| Condition::new(s, &format!("{wk}[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                c.children.push(if k == "all" {
                    Combinator::All(subs)
                } else {
                    Combinator::Any(subs)
                });
            } else if k == "not" {
                c.children
                    .push(Combinator::Not(Box::new(Condition::new(v, &wk)?)));
            } else {
                return Err(format!(
                    "{wk}: unknown key (allowed: {}, fields, all, any, not)",
                    LEAF_KEYS.join(", ")
                ));
            }
        }
        Ok(c)
    }

    fn leaf_value<'a>(
        leaf: &Leaf,
        e: &'a EventView,
        owned: &'a mut Option<Value>,
    ) -> Option<&'a Value> {
        match leaf {
            Leaf::Key("source_ip") => resolve_ip(e.fields, &SOURCE_IP_PATHS),
            Leaf::Key("dest_ip") => resolve_ip(e.fields, &DEST_IP_PATHS),
            Leaf::Key(k) => {
                let s = match *k {
                    "source" => e.source,
                    "severity" => e.severity,
                    "event_type" => e.event_type,
                    _ => e.message,
                };
                *owned = Some(Value::String(s.to_string()));
                owned.as_ref()
            }
            Leaf::Field(p) => get_path(e.fields, p),
        }
    }

    pub fn evaluate(&self, e: &EventView, mut trace: Option<&mut Vec<Value>>) -> bool {
        let mut ok = true;
        for (leaf, m) in &self.leaves {
            let mut owned = None;
            let matched = m.test(Self::leaf_value(leaf, e, &mut owned));
            if let Some(t) = trace.as_deref_mut() {
                let label = match leaf {
                    Leaf::Key(k) => k.to_string(),
                    Leaf::Field(p) => format!("fields.{p}"),
                };
                t.push(json!({"condition": label, "expected": m.spec, "matched": matched}));
            } else if !matched {
                return false;
            }
            ok &= matched;
        }
        for child in &self.children {
            let (kind, res) = match child {
                Combinator::All(cs) => ("all", cs.iter().all(|c| c.evaluate(e, None))),
                Combinator::Any(cs) => ("any", cs.iter().any(|c| c.evaluate(e, None))),
                Combinator::Not(c) => ("not", !c.evaluate(e, None)),
            };
            if let Some(t) = trace.as_deref_mut() {
                t.push(json!({"condition": kind, "matched": res}));
            } else if !res {
                return false;
            }
            ok &= res;
        }
        ok
    }
}

// --------------------------------------------------------------------- rules

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub description: String,
    pub action: String,
    pub metadata: Value,
    pub origin: String,
    pub spec: Value,
    condition: Condition,
}

impl Rule {
    pub fn new(spec: &Value, origin: &str, index: usize) -> Result<Self, RuleError> {
        let w = format!("filters[{index}]");
        let m = spec
            .as_object()
            .ok_or_else(|| format!("{w}: a rule must be a mapping"))?;
        if let Some(k) = m.keys().find(|k| !RULE_KEYS.contains(&k.as_str())) {
            return Err(format!(
                "{w}: unknown key '{k}' (allowed: {})",
                RULE_KEYS.join(", ")
            ));
        }
        let id = m
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
            })
            .ok_or_else(|| format!("{w}.id: required, 1-128 chars of [A-Za-z0-9_.:-]"))?;
        let w = format!("filters[{index}] ({id})");
        let enabled = match m.get("enabled") {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(format!("{w}.enabled: expected true/false")),
        };
        let action = match m.get("action") {
            None => "exclude".to_string(),
            Some(Value::String(a)) if a == "exclude" => a.clone(),
            Some(a) => return Err(format!("{w}.action: unsupported {a} (allowed: exclude)")),
        };
        let description = match m.get("description") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(d)) => d.clone(),
            Some(_) => return Err(format!("{w}.description: expected a string")),
        };
        let metadata = match m.get("metadata") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            Some(_) => return Err(format!("{w}.metadata: expected a mapping")),
        };
        let cond = m
            .get("match")
            .ok_or_else(|| format!("{w}.match: required"))?;
        Ok(Rule {
            condition: Condition::new(cond, &format!("{w}.match"))?,
            id: id.to_string(),
            enabled,
            description,
            action,
            metadata,
            origin: origin.to_string(),
            spec: spec.clone(),
        })
    }

    pub fn matches(&self, e: &EventView) -> bool {
        self.enabled && self.condition.evaluate(e, None)
    }

    pub fn summary(&self) -> Value {
        json!({
            "id": self.id, "enabled": self.enabled, "description": self.description,
            "action": self.action, "origin": self.origin,
            "generated_by": self.metadata.get("generated_by"),
            "match": self.spec.get("match"),
        })
    }
}

pub fn yaml_to_value(text: &str) -> Result<Value, RuleError> {
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_yaml::from_str::<Value>(text).map_err(|e| format!("YAML syntax error: {e}"))
}

/// Strictly validate a filter document.
pub fn parse_document(text: &str, origin: &str) -> Result<Vec<Rule>, RuleError> {
    let doc = yaml_to_value(text)?;
    let m = match &doc {
        Value::Null => return Err("empty document (expected at least `version: 1`)".into()),
        Value::Object(m) => m,
        _ => return Err("top level must be a mapping with `version` and `filters`".into()),
    };
    if let Some(k) = m.keys().find(|k| *k != "version" && *k != "filters") {
        return Err(format!("unknown top-level key '{k}'"));
    }
    if m.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("`version: 1` is required".into());
    }
    let items = match m.get("filters") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("`filters` must be a list".into()),
    };
    let mut rules: Vec<Rule> = vec![];
    for (i, spec) in items.iter().enumerate() {
        let r = Rule::new(spec, origin, i)?;
        if rules.iter().any(|x| x.id == r.id) {
            return Err(format!("duplicate rule id '{}'", r.id));
        }
        rules.push(r);
    }
    Ok(rules)
}

#[derive(Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn matching(&self, e: &EventView) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(e))
    }

    pub fn explain(&self, e: &EventView) -> Vec<Value> {
        self.rules.iter().map(|r| {
            let mut trace = vec![];
            let matched = r.enabled && r.condition.evaluate(e, Some(&mut trace));
            json!({"rule": r.id, "origin": r.origin, "enabled": r.enabled, "matched": matched, "trace": trace})
        }).collect()
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

// -------------------------------------------------------------- file manager

struct FileState {
    sig: Option<(i64, u64, u64)>,
    rules: Vec<Value>,
    error: Option<String>,
    warning: Option<String>,
    using_last_good: bool,
}

/// Loads the NixOS-managed system file(s) (read-only) and the user file
/// (writable, 0600), hot-reloads them on change and keeps the last valid
/// version of each one.
pub struct FilterManager {
    pub user_file: PathBuf,
    files: Vec<PathBuf>,
    good_dir: PathBuf,
    seed_enabled: bool,
    state: Vec<(PathBuf, FileState)>,
    pub ruleset: RuleSet,
    pub generation: u64,
}

fn sig(p: &Path) -> Option<(i64, u64, u64)> {
    fs::metadata(p).ok().map(|m| {
        (
            m.mtime_nsec() + m.mtime() * 1_000_000_000,
            m.size(),
            m.ino(),
        )
    })
}

impl FilterManager {
    pub fn new(
        system_files: Vec<PathBuf>,
        user_file: PathBuf,
        state_dir: &Path,
        seed: bool,
    ) -> Self {
        let mut files = system_files;
        files.push(user_file.clone());
        Self {
            user_file,
            files,
            good_dir: state_dir.join("filters-last-good"),
            seed_enabled: seed,
            state: vec![],
            ruleset: RuleSet::default(),
            generation: 0,
        }
    }

    pub fn from_config(cfg: &crate::config::Config) -> Self {
        Self::new(
            cfg.system_filter_files(),
            cfg.user_filter_file(),
            &cfg.state_dir(),
            cfg.filter.seed,
        )
    }

    /// Create the user file (0600 in a 0700 dir) if missing. Never overwrites.
    pub fn seed(&self) {
        if !self.seed_enabled || self.user_file.exists() {
            return;
        }
        if let Some(d) = self.user_file.parent() {
            let _ = ensure_dir(d, 0o700);
        }
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.user_file);
        if let Ok(mut f) = f {
            use std::io::Write;
            let _ = f.write_all(SEED.as_bytes());
            info!("created {}", self.user_file.display());
        }
    }

    fn good_path(&self, p: &Path) -> PathBuf {
        self.good_dir
            .join(format!("{}.yaml", sha(&[&p.to_string_lossy()], 16)))
    }

    fn load_one(&self, p: &Path, prev: Option<&FileState>) -> FileState {
        let mut st = FileState {
            sig: sig(p),
            rules: vec![],
            error: None,
            warning: None,
            using_last_good: false,
        };
        let is_user = p == self.user_file;
        if st.sig.is_none() {
            if !is_user {
                st.error = Some("missing".into());
            }
            return st;
        }
        let origin = p.to_string_lossy().to_string();
        let res = fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_document(&t, &origin).map(|r| (t, r)));
        match res {
            Ok((t, rules)) => {
                st.rules = rules.iter().map(|r| r.spec.clone()).collect();
                if is_user {
                    let mode = fs::metadata(p)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    if mode & 0o077 != 0 {
                        st.warning =
                            Some(format!("permissions {mode:o} are too open (expected 600)"));
                    }
                    if ensure_dir(&self.good_dir, 0o700).is_ok() {
                        let _ = atomic_write(&self.good_path(p), t.as_bytes(), 0o600);
                    }
                }
            }
            Err(e) => {
                st.error = Some(e.clone());
                if let Some(prev) = prev.filter(|p| !p.rules.is_empty()) {
                    st.rules = prev.rules.clone();
                    st.using_last_good = true;
                } else if let Ok(t) = fs::read_to_string(self.good_path(p)) {
                    if let Ok(r) = parse_document(&t, &origin) {
                        st.rules = r.iter().map(|r| r.spec.clone()).collect();
                        st.using_last_good = true;
                    }
                }
                error!(
                    "filter file {} rejected: {e} ({})",
                    p.display(),
                    if st.using_last_good {
                        "keeping its last valid version"
                    } else {
                        "no rules from this file"
                    }
                );
            }
        }
        st
    }

    /// Returns true when the effective rule set changed.
    pub fn reload(&mut self, force: bool) -> bool {
        let mut changed = false;
        for p in self.files.clone() {
            let idx = self.state.iter().position(|(q, _)| *q == p);
            let prev = idx.map(|i| &self.state[i].1);
            if force || prev.is_none() || prev.unwrap().sig != sig(&p) {
                let st = self.load_one(&p, prev);
                match idx {
                    Some(i) => self.state[i].1 = st,
                    None => self.state.push((p.clone(), st)),
                }
                changed = true;
            }
        }
        if !changed {
            return false;
        }
        let mut rules: Vec<Rule> = vec![];
        for (p, st) in &self.state {
            let origin = p.to_string_lossy();
            for (i, spec) in st.rules.iter().enumerate() {
                let Ok(r) = Rule::new(spec, &origin, i) else {
                    continue;
                };
                if rules.iter().any(|x| x.id == r.id) {
                    error!(
                        "rule id '{}' from {} shadows an earlier rule; ignored",
                        r.id, origin
                    );
                    continue;
                }
                rules.push(r);
            }
        }
        info!("filters loaded: {} rule(s)", rules.len());
        self.ruleset = RuleSet { rules };
        self.generation += 1;
        true
    }

    pub fn status(&self) -> Value {
        let files: Vec<Value> = self
            .state
            .iter()
            .map(|(p, st)| {
                json!({
                    "path": p, "writable": *p == self.user_file, "present": st.sig.is_some(),
                    "rules": st.rules.len(), "error": st.error, "warning": st.warning,
                    "using_last_good": st.using_last_good,
                })
            })
            .collect();
        let ok = self.state.iter().all(|(_, s)| s.error.is_none());
        json!({"files": files, "rules": self.ruleset.rules.len(), "ok": ok})
    }
}

// --------------------------------------------------------- safe file writing

pub fn backup(path: &Path, dir: &Path, keep: usize) -> std::io::Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    ensure_dir(dir, 0o700)?;
    let now = chrono::Utc::now();
    let dst = dir.join(format!(
        "alert_filter.{}.yaml",
        now.format("%Y%m%dT%H%M%S%.6f")
    ));
    fs::copy(path, &dst)?;
    fs::set_permissions(&dst, fs::Permissions::from_mode(0o600))?;
    let all = list_backups(dir);
    for old in all.iter().skip(keep.max(1)) {
        let _ = fs::remove_file(old);
    }
    Ok(Some(dst))
}

/// Newest first.
pub fn list_backups(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("alert_filter."))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.reverse();
    v
}

fn dump_rule_item(rule: &Value, indent: &str) -> String {
    let y = serde_yaml::to_string(&vec![rule]).unwrap_or_default();
    y.lines()
        .map(|l| {
            if l.trim().is_empty() {
                "\n".to_string()
            } else {
                format!("{indent}{l}\n")
            }
        })
        .collect()
}

/// Append one rule to a filter file, keeping the user's other rules and
/// comments whenever possible. The result is validated (and checked to be
/// exactly "old rules + new rule") before an atomic write; an invalid current
/// file is never touched.
pub fn append_rule(
    path: &Path,
    rule: &Value,
    backup_dir: Option<&Path>,
    keep: usize,
) -> Result<String, RuleError> {
    let origin = path.to_string_lossy().to_string();
    Rule::new(rule, &origin, 0)?;
    let old_text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SEED.to_string(),
        Err(e) => return Err(e.to_string()),
    };
    let old_rules = parse_document(&old_text, &origin)
        .map_err(|e| format!("current file is invalid, not modified: {e}"))?;
    let rid = rule["id"].as_str().unwrap_or_default();
    if old_rules.iter().any(|r| r.id == rid) {
        return Err(format!("rule id '{rid}' already exists"));
    }
    let mut expected = yaml_to_value(&old_text)?;
    let mut list = expected
        .get("filters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let had_rules = !list.is_empty();
    list.push(rule.clone());
    expected["filters"] = Value::Array(list);

    let same = |cand: &str| yaml_to_value(cand).is_ok_and(|v| v == expected);
    let mut candidate = None;
    if had_rules {
        // `filters` is the last key and a block sequence: plain text append.
        let indent = Regex::new(r"(?m)^([ \t]*)- id:")
            .unwrap()
            .captures(&old_text)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "  ".into());
        let cand = format!(
            "{}\n{}",
            old_text.trim_end_matches('\n'),
            dump_rule_item(rule, &indent)
        );
        if same(&cand) {
            candidate = Some(cand);
        }
    } else {
        // Seed layout `filters: []`: replace that line only.
        let re = Regex::new(r"(?m)^filters:[ \t]*\[[ \t]*\][ \t]*$").unwrap();
        let item = dump_rule_item(rule, "  ");
        let cand = re
            .replacen(
                &old_text,
                1,
                format!("filters:\n{}", item.trim_end_matches('\n')),
            )
            .to_string();
        if cand != old_text && same(&cand) {
            candidate = Some(cand);
        }
    }
    let candidate = match candidate {
        Some(c) => c,
        None => serde_yaml::to_string(&expected).map_err(|e| e.to_string())?,
    };
    parse_document(&candidate, &origin)?;
    if let Some(d) = backup_dir {
        backup(path, d, keep).map_err(|e| format!("backup failed, not modified: {e}"))?;
    }
    if let Some(d) = path.parent() {
        ensure_dir(d, 0o700).map_err(|e| e.to_string())?;
    }
    atomic_write(path, candidate.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    Ok(candidate)
}

/// Restore a backup (validated first; the current file is backed up too).
pub fn restore_backup(
    path: &Path,
    backup_file: &Path,
    backup_dir: &Path,
    keep: usize,
) -> Result<(), RuleError> {
    let t = fs::read_to_string(backup_file).map_err(|e| e.to_string())?;
    parse_document(&t, &backup_file.to_string_lossy())?;
    backup(path, backup_dir, keep + 1).map_err(|e| e.to_string())?;
    atomic_write(path, t.as_bytes(), 0o600).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(
        fields: &'a Value,
        source: &'a str,
        sev: &'a str,
        et: &'a str,
        msg: &'a str,
    ) -> EventView<'a> {
        EventView {
            source,
            severity: sev,
            event_type: et,
            message: msg,
            fields,
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("minisoc-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const DOC: &str = r#"
version: 1
filters:
  - id: ignore_known_test_alert
    enabled: true
    description: Ignore known test events
    match:
      source: snort
      event_type: test_alert
    action: exclude
  - id: ignore_localhost_noise
    match:
      severity: [info]
      fields:
        source_ip: "127.0.0.1"
    action: exclude
  - id: nested
    match:
      any:
        - message: {regex: "^backup (started|done)$"}
        - all:
            - source_ip: {cidr: 10.0.0.0/8}
            - not: {severity: [high, critical]}
"#;

    #[test]
    fn matching_and_combinators() {
        let rs = RuleSet {
            rules: parse_document(DOC, "t").unwrap(),
        };
        let none = json!({});
        assert_eq!(
            rs.matching(&ev(&none, "snort", "low", "test_alert", "x"))
                .unwrap()
                .id,
            "ignore_known_test_alert"
        );
        assert!(rs
            .matching(&ev(&none, "snort", "low", "other", "x"))
            .is_none());
        let lo = json!({"source_ip": "127.0.0.1"});
        assert_eq!(
            rs.matching(&ev(&lo, "a", "info", "t", "x")).unwrap().id,
            "ignore_localhost_noise"
        );
        assert!(
            rs.matching(&ev(&lo, "a", "medium", "t", "x")).is_none(),
            "severity condition is ANDed"
        );
        assert_eq!(
            rs.matching(&ev(&none, "a", "high", "t", "backup done"))
                .unwrap()
                .id,
            "nested"
        );
        let lan = json!({"source.ip": "10.1.2.3"});
        assert_eq!(
            rs.matching(&ev(&lan, "a", "low", "t", "x")).unwrap().id,
            "nested"
        );
        assert!(
            rs.matching(&ev(&lan, "a", "high", "t", "x")).is_none(),
            "not: excludes high"
        );
    }

    #[test]
    fn explain_shows_why() {
        let rs = RuleSet {
            rules: parse_document(DOC, "t").unwrap(),
        };
        let none = json!({});
        let ex = rs.explain(&ev(&none, "snort", "low", "other", "x"));
        assert_eq!(ex[0]["matched"], false);
        assert_eq!(ex[0]["trace"][0]["condition"], "source");
        assert_eq!(ex[0]["trace"][0]["matched"], true);
        assert_eq!(ex[0]["trace"][1]["matched"], false);
    }

    #[test]
    fn strict_validation() {
        for (bad, why) in [
            ("version: 2\nfilters: []", "version"),
            ("version: 1\nfilters:\n  - id: a\n    match: {}\n", "empty match"),
            ("version: 1\nfilters:\n  - id: a\n    match: {sevrity: info}\n", "typo key"),
            ("version: 1\nfilters:\n  - id: a\n    match: {severity: urgent}\n", "bad severity"),
            ("version: 1\nfilters:\n  - id: a\n    match: {message: {regex: '('}}\n", "bad regex"),
            ("version: 1\nfilters:\n  - id: a\n    match: {source_ip: {cidr: nope}}\n", "bad cidr"),
            ("version: 1\nfilters:\n  - id: a\n    match: {message: {contains: ''}}\n", "empty contains"),
            ("version: 1\nfilters:\n  - id: a\n    match: {source: x}\n  - id: a\n    match: {source: y}\n", "dup id"),
            ("version: 1\nfilters:\n  - id: a\n    match: {source: x}\n    action: delete\n", "action"),
            ("version: 1\nfilters: [ {id: a, match: {source: x}}", "yaml syntax"),
        ] {
            assert!(parse_document(bad, "t").is_err(), "should reject: {why}");
        }
    }

    #[test]
    fn hot_reload_keeps_last_valid_version() {
        let d = tmpdir("reload");
        let f = d.join("alert_filter.yaml");
        let mut fm = FilterManager::new(vec![], f.clone(), &d, true);
        fm.seed();
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(fm.reload(false));
        assert_eq!(fm.ruleset.rules.len(), 0);
        fs::write(&f, DOC).unwrap();
        assert!(fm.reload(false));
        assert_eq!(fm.ruleset.rules.len(), 3);
        assert!(!fm.reload(false), "no change => no reload");
        // Broken edit: whole file rejected, previous rules stay in force.
        fs::write(
            &f,
            "version: 1\nfilters:\n  - id: x\n    match: {}\n# padding to change size\n",
        )
        .unwrap();
        assert!(fm.reload(false));
        assert_eq!(fm.ruleset.rules.len(), 3);
        assert_eq!(fm.status()["ok"], false);
        // Also across restarts (persisted last-good copy).
        let mut fm2 = FilterManager::new(vec![], f.clone(), &d, true);
        fm2.reload(false);
        assert_eq!(fm2.ruleset.rules.len(), 3);
        assert_eq!(fm2.status()["files"][0]["using_last_good"], true);
    }

    #[test]
    fn append_keeps_comments_backup_and_rollback() {
        let d = tmpdir("append");
        let f = d.join("alert_filter.yaml");
        let bdir = d.join("backups");
        // Seed layout (`filters: []`).
        fs::write(&f, SEED).unwrap();
        let r1 =
            json!({"id": "r1", "match": {"source": "a", "event_type": "b"}, "action": "exclude"});
        append_rule(&f, &r1, Some(&bdir), 5).unwrap();
        let t = fs::read_to_string(&f).unwrap();
        assert!(t.contains("# MiniSOC alert filter rules"), "comments kept");
        assert_eq!(parse_document(&t, "t").unwrap().len(), 1);
        // Block-list layout: text append.
        let r2 = json!({"id": "r2", "match": {"source": "c"}});
        append_rule(&f, &r2, Some(&bdir), 5).unwrap();
        let t = fs::read_to_string(&f).unwrap();
        assert!(t.contains("# MiniSOC alert filter rules"));
        assert_eq!(parse_document(&t, "t").unwrap().len(), 2);
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            append_rule(&f, &r2, Some(&bdir), 5).is_err(),
            "duplicate id refused"
        );
        let backups = list_backups(&bdir);
        assert_eq!(backups.len(), 2);
        // Rollback to the state before r2.
        restore_backup(&f, &backups[0], &bdir, 5).unwrap();
        assert_eq!(
            parse_document(&fs::read_to_string(&f).unwrap(), "t")
                .unwrap()
                .len(),
            1
        );
        // An invalid current file is never modified.
        fs::write(&f, "version: 1\nfilters: {broken").unwrap();
        assert!(append_rule(
            &f,
            &json!({"id": "r3", "match": {"source": "z"}}),
            Some(&bdir),
            5
        )
        .is_err());
        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "version: 1\nfilters: {broken"
        );
    }
}
