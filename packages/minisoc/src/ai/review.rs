//! Scheduled AI review of the AI's own exclusion rules.
//!
//! At a fixed interval (or on `minisoc review`), the model receives the
//! alerts the user recently closed as false positive (grouped by similarity),
//! those closed as true positive (counter-examples), the rules of the AI file
//! with their counters (alerts excluded since their last change) and the
//! user's rules (read-only context). It answers with changes to the AI file:
//! create, update, delete. The goal: as little noise as possible while every
//! relevant alert still reaches the user, improving with use.
//!
//! The model only proposes. Every change is checked here, from the Nix
//! configuration (`ai.filter_review`), before anything is written:
//! - only rules of the AI file are modified or deleted; the user's rules are
//!   never touched;
//! - a created/updated rule names an exact source and event type plus a
//!   specific message/fields condition, gets the protected severities
//!   injected, covers at least `minimum_false_positives` alerts the user
//!   closed as FP, and hides nothing else among recent alerts: no pinned
//!   alert, no alert closed as TP, no alert of a pattern the user never
//!   judged FP;
//! - a rule younger than `minimum_rule_age_hours` is left alone; a rule is
//!   deleted only when it excluded at most `low_hits_threshold` alerts since
//!   its last change, or when it would hide a TP (then without delay);
//! - at most `max_changes` per review; `suggest` mode only stores proposals.
//! The AI never learns from its own closures, only from the user's.

use super::{extract_json, policy, prompts, providers, redact};
use crate::config::Config;
use crate::filters::{self, EventView, FilterManager, Rule};
use crate::normalize::Event;
use crate::store::Store;
use crate::util::{format_ts, now_iso, sev_rank, sha, truncate};
use crate::{info, warn};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

const RECENT: usize = 5000;

fn view(e: &Event) -> EventView<'_> {
    EventView {
        source: &e.source,
        severity: &e.severity,
        event_type: &e.event_type,
        message: &e.message,
        fields: &e.fields,
    }
}

fn hours_since(ts: Option<&str>) -> f64 {
    ts.and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds() as f64 / 3600.0)
        .unwrap_or(f64::INFINITY)
}

/// What the checks need to know, gathered once per review.
pub struct Context {
    /// Alerts the user closed as FP within the look-back window.
    pub fp: Vec<Event>,
    /// Alerts the user closed as TP (counter-examples).
    pub tp: Vec<Event>,
    /// Recent alerts: (event, pinned, verdict if closed).
    pub recent: Vec<(Event, bool, Option<String>)>,
    /// AI rules: id -> (spec, since, hits since the last change).
    pub ai_rules: BTreeMap<String, (Value, Option<String>, i64)>,
    /// Match conditions of every other rule (duplicates are refused).
    pub other_matches: Vec<Value>,
}

impl Context {
    pub fn gather(cfg: &Config, store: &Store, fm: &FilterManager) -> Result<Self, String> {
        let r = &cfg.ai.filter_review;
        let since = format_ts(chrono::Utc::now() - chrono::Duration::days(r.lookback_days.max(1)));
        let e = |x: rusqlite::Error| x.to_string();
        let stats = store.filter_stats().map_err(e)?;
        let ai_rules = fm
            .rules_of("ai")
            .into_iter()
            .map(|rule| {
                let s = stats.get(&rule.id);
                (
                    rule.id.clone(),
                    (
                        rule.spec.clone(),
                        s.and_then(|s| s["since"].as_str()).map(String::from),
                        s.and_then(|s| s["hits"].as_i64()).unwrap_or(0),
                    ),
                )
            })
            .collect();
        let other_matches = fm
            .ruleset
            .rules
            .iter()
            .filter(|rule| fm.owner(std::path::Path::new(&rule.origin)) != "ai")
            .map(|rule| rule.spec["match"].clone())
            .collect();
        Ok(Self {
            fp: store.closed_events("fp", true, &since, r.max_alerts).map_err(e)?,
            tp: store.closed_events("tp", true, &since, r.max_alerts).map_err(e)?,
            recent: store.recent_with_verdict(RECENT).map_err(e)?,
            ai_rules,
            other_matches,
        })
    }

    fn fp_fingerprints(&self) -> HashSet<&str> {
        self.fp.iter().map(|e| e.fingerprint.as_str()).collect()
    }

    /// How many FP / TP closures a compiled rule matches.
    fn coverage(&self, rule: &Rule) -> (usize, usize) {
        let n = |v: &[Event]| v.iter().filter(|e| rule.matches(&view(e))).count();
        (n(&self.fp), n(&self.tp))
    }

    fn hides_tp(&self, rule: &Rule) -> bool {
        self.coverage(rule).1 > 0
            || self
                .recent
                .iter()
                .any(|(e, _, v)| v.as_deref() == Some("tp") && rule.matches(&view(e)))
    }
}

/// Model input: FP groups, TP examples, AI rules with counters, user rules.
pub fn input(cfg: &Config, ctx: &Context, fm: &FilterManager) -> Value {
    let privacy = &cfg.ai.privacy;
    let max = cfg.ai.limits.max_event_bytes / 2;
    let sample = |e: &Event, extra: Value| -> Value {
        serde_json::from_str(&redact::payload(e, privacy, max, extra)).unwrap_or(Value::Null)
    };
    let group = |events: &[Event], cap: usize| -> Vec<Value> {
        let mut groups: Vec<(String, usize, &Event)> = vec![];
        for e in events {
            match groups.iter_mut().find(|g| g.0 == e.fingerprint) {
                Some(g) => g.1 += 1,
                None => groups.push((e.fingerprint.clone(), 1, e)),
            }
        }
        groups.sort_by(|a, b| b.1.cmp(&a.1));
        groups
            .into_iter()
            .take(cap)
            .map(|(fp, n, e)| sample(e, json!({"pattern": &fp[..8.min(fp.len())], "closed_count": n})))
            .collect()
    };
    let compile = |id: &str, spec: &Value| Rule::new(spec, id, 0).ok();
    let ai_rules: Vec<Value> = ctx
        .ai_rules
        .iter()
        .map(|(id, (spec, since, hits))| {
            let (fp, tp) = compile(id, spec)
                .map(|r| ctx.coverage(&r))
                .unwrap_or((0, 0));
            json!({
                "id": id, "description": spec.get("description"), "match": spec.get("match"),
                "enabled": spec.get("enabled").cloned().unwrap_or(json!(true)),
                "last_change": since,
                "excluded_since_last_change": hits,
                "matches_fp_closed": fp, "matches_tp_closed": tp,
            })
        })
        .collect();
    let user_rules: Vec<Value> = fm
        .rules_of("user")
        .iter()
        .chain(fm.rules_of("system").iter())
        .map(|r| json!({"id": r.id, "description": r.description, "match": r.spec.get("match")}))
        .collect();
    json!({
        "lookback_days": cfg.ai.filter_review.lookback_days,
        "closed_false_positive": group(&ctx.fp, 60),
        "closed_true_positive": group(&ctx.tp, 30),
        "ai_rules": ai_rules,
        "user_rules_read_only": user_rules,
        "limits": {
            "minimum_false_positives_per_rule": cfg.ai.filter_review.minimum_false_positives,
            "low_hits_threshold": cfg.ai.filter_review.low_hits_threshold,
            "minimum_rule_age_hours": cfg.ai.filter_review.minimum_rule_age_hours,
            "max_changes": cfg.ai.filter_review.max_changes,
        },
    })
}

/// Validate a `match` from the model and turn it into a rule of the AI file.
fn build_rule(
    cfg: &Config,
    ctx: &Context,
    change: &Value,
    id: Option<&str>,
    previous: Option<&Value>,
) -> Result<(Value, usize), String> {
    let m = change
        .get("match")
        .and_then(Value::as_object)
        .ok_or("no `match` mapping")?;
    let mut clean = Map::new();
    for (k, v) in m {
        match k.as_str() {
            "source" | "event_type" => {
                if v.as_str().is_none_or(str::is_empty) {
                    return Err(format!("`{k}` must be an exact string"));
                }
            }
            "message" => policy::check_matcher(v, "message")?,
            "fields" => {
                let f = v
                    .as_object()
                    .filter(|f| !f.is_empty() && f.len() <= 8)
                    .ok_or("fields: 1..8 entries")?;
                for (p, mv) in f {
                    policy::check_matcher(mv, &format!("fields.{p}"))?;
                }
            }
            other => return Err(format!("key '{other}' is not allowed in AI rules")),
        }
        clean.insert(k.clone(), v.clone());
    }
    if !clean.contains_key("source") || !clean.contains_key("event_type") {
        return Err("`source` and `event_type` are required".into());
    }
    if !clean.contains_key("message") && !clean.contains_key("fields") {
        return Err("a `message` or `fields` condition is required (no source-wide rules)".into());
    }
    let allowed = policy::allowed_severities(&cfg.ai.auto_filter);
    if allowed.is_empty() {
        return Err("every severity is protected".into());
    }
    clean.insert("severity".into(), json!({"in": allowed}));
    let clean = Value::Object(clean);
    if ctx.other_matches.contains(&clean)
        || ctx
            .ai_rules
            .iter()
            .any(|(rid, (s, _, _))| Some(rid.as_str()) != id && s.get("match") == Some(&clean))
    {
        return Err("an identical rule already exists".into());
    }

    let now = now_iso();
    let id = id
        .map(String::from)
        .unwrap_or_else(|| format!("ai-review-{}", sha(&[&clean.to_string()], 10)));
    let confidence = change.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
    let created = previous
        .and_then(|p| p.pointer("/metadata/created_at").cloned())
        .unwrap_or(json!(now));
    let mut rule = json!({
        "id": id,
        "enabled": true,
        "description": truncate(change.get("description").and_then(Value::as_str).unwrap_or("AI exclusion (filter review)"), 200),
        "match": clean,
        "action": "exclude",
        "metadata": {
            "generated_by": "minisoc-ai-review",
            "provider": cfg.ai.provider, "model": cfg.ai.model, "confidence": confidence,
            "created_at": created, "reason": truncate(change.get("reason").and_then(Value::as_str).unwrap_or(""), 500),
        },
    });
    if previous.is_some() {
        rule["metadata"]["updated_at"] = json!(now);
    }
    let compiled = Rule::new(&rule, "ai-review", 0)?;
    let (fp_n, _) = ctx.coverage(&compiled);
    let min = cfg.ai.filter_review.minimum_false_positives.max(1);
    if fp_n < min {
        return Err(format!(
            "covers {fp_n} alert(s) closed as FP by the user, {min} required"
        ));
    }
    let fps = ctx.fp_fingerprints();
    for (e, pinned, verdict) in &ctx.recent {
        if !compiled.matches(&view(e)) {
            continue;
        }
        if *pinned {
            return Err(format!("would hide pinned alert {}", e.id));
        }
        if verdict.as_deref() == Some("tp") {
            return Err(format!("would hide alert {} closed as true positive", e.id));
        }
        if sev_rank(&e.severity) >= sev_rank("high") {
            return Err("would hide a high/critical alert".into());
        }
        if !fps.contains(e.fingerprint.as_str()) {
            return Err(format!(
                "too broad: would also hide alert {} ({}), of a pattern never closed as FP",
                e.id,
                truncate(&e.message, 80)
            ));
        }
    }
    if ctx.tp.iter().any(|e| compiled.matches(&view(e))) {
        return Err("would hide an alert closed as true positive".into());
    }
    rule["metadata"]["fp_evidence"] = json!(fp_n);
    Ok((rule, fp_n))
}

/// A change that passed every check, ready to apply.
#[derive(Debug, Clone)]
pub struct Checked {
    pub action: String,
    pub id: String,
    pub rule: Option<Value>,
    pub reason: String,
    pub confidence: f64,
}

impl Checked {
    pub fn to_json(&self) -> Value {
        json!({"action": self.action, "id": self.id, "rule": self.rule, "reason": self.reason, "confidence": self.confidence})
    }
    /// Identity, so a proposal refused by the user is not proposed again.
    pub fn key(&self) -> String {
        sha(
            &[
                &self.action,
                &self.id,
                &self.rule.as_ref().map(|r| r["match"].to_string()).unwrap_or_default(),
            ],
            16,
        )
    }
}

/// Check every change of the model's reply. Returns (accepted, rejected).
pub fn check(cfg: &Config, ctx: &Context, reply: &Value) -> (Vec<Checked>, Vec<Value>) {
    let r = &cfg.ai.filter_review;
    let mut ok: Vec<Checked> = vec![];
    let mut rejected = vec![];
    let changes = reply
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut touched: HashSet<String> = HashSet::new();
    for c in changes.iter().take(50) {
        let action = c.get("action").and_then(Value::as_str).unwrap_or("");
        let reason = truncate(c.get("reason").and_then(Value::as_str).unwrap_or(""), 500);
        let confidence = c.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
        let res: Result<Checked, String> = (|| {
            if confidence < r.minimum_confidence {
                return Err(format!(
                    "confidence {confidence:.2} below {:.2}",
                    r.minimum_confidence
                ));
            }
            match action {
                "create" => {
                    let (rule, _) = build_rule(cfg, ctx, c, None, None)?;
                    let id = rule["id"].as_str().unwrap_or_default().to_string();
                    if ctx.ai_rules.contains_key(&id) {
                        return Err("an identical rule already exists".into());
                    }
                    Ok(Checked { action: action.into(), id, rule: Some(rule), reason, confidence })
                }
                "update" | "delete" => {
                    let id = c.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                    let (spec, since, hits) = ctx
                        .ai_rules
                        .get(&id)
                        .ok_or(format!("'{id}' is not a rule of the AI file (user rules are never changed)"))?;
                    let old = Rule::new(spec, "ai", 0)?;
                    let unsafe_rule = ctx.hides_tp(&old);
                    let age = hours_since(since.as_deref());
                    if age < r.minimum_rule_age_hours && !unsafe_rule {
                        return Err(format!(
                            "rule changed {age:.0} h ago, {} h minimum",
                            r.minimum_rule_age_hours
                        ));
                    }
                    if action == "delete" {
                        if *hits > r.low_hits_threshold && !unsafe_rule {
                            return Err(format!(
                                "still excludes {hits} alert(s) since its last change (> {})",
                                r.low_hits_threshold
                            ));
                        }
                        Ok(Checked { action: action.into(), id, rule: None, reason, confidence })
                    } else {
                        let (rule, _) = build_rule(cfg, ctx, c, Some(&id), Some(spec))?;
                        Ok(Checked { action: action.into(), id, rule: Some(rule), reason, confidence })
                    }
                }
                other => Err(format!("unknown action '{other}'")),
            }
        })();
        match res {
            Ok(ch) if touched.contains(&ch.id) => rejected.push(json!({"change": c, "error": "rule already changed in this review"})),
            Ok(_) if ok.len() >= r.max_changes => rejected.push(json!({"change": c, "error": format!("over max_changes ({})", r.max_changes)})),
            Ok(ch) => {
                touched.insert(ch.id.clone());
                ok.push(ch)
            }
            Err(e) => rejected.push(json!({"change": c, "error": e})),
        }
    }
    (ok, rejected)
}

/// Apply checked changes to the AI file (one validated, backed-up write).
pub fn apply(cfg: &Config, fm: &FilterManager, changes: &[Checked]) -> Result<(), String> {
    let mut rules: Vec<Value> = fm.rules_of("ai").iter().map(|r| r.spec.clone()).collect();
    for c in changes {
        match c.action.as_str() {
            "delete" => rules.retain(|r| r["id"] != json!(c.id)),
            "update" => {
                let new = c.rule.clone().ok_or("update without rule")?;
                match rules.iter_mut().find(|r| r["id"] == json!(c.id)) {
                    Some(r) => *r = new,
                    None => return Err(format!("rule {} no longer exists", c.id)),
                }
            }
            "create" => rules.push(c.rule.clone().ok_or("create without rule")?),
            a => return Err(format!("unknown action {a}")),
        }
    }
    let backup = cfg
        .ai
        .filter_review
        .backup_before_write
        .then(|| cfg.ai_backup_dir());
    filters::write_rules(
        &cfg.ai_filter_file(),
        &rules,
        filters::AI_HEADER,
        backup.as_deref(),
        cfg.filter.max_backups,
    )
    .map(|_| ())
}

/// One review. `dry_run`: report only (no write, no proposal).
pub fn run(cfg: &Config, store: &Store, dry_run: bool) -> Result<Value, String> {
    let r = &cfg.ai.filter_review;
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    let ctx = Context::gather(cfg, store, &fm)?;
    let data = input(cfg, &ctx, &fm);
    let mut report = json!({
        "ran_at": now_iso(), "mode": r.mode, "dry_run": dry_run,
        "fp_closed": ctx.fp.len(), "tp_closed": ctx.tp.len(), "ai_rules": ctx.ai_rules.len(),
        "applied": [], "proposed": [], "rejected": [],
    });
    if ctx.fp.is_empty() && ctx.ai_rules.is_empty() {
        report["skipped"] = json!("no alert closed as FP and no AI rule: nothing to review");
        return Ok(report);
    }
    // Same evidence as the last review: no new request.
    let input_hash = sha(&[&data.to_string()], 16);
    if !dry_run && store.meta_get("review_input").ok().flatten().as_deref() == Some(&input_hash) {
        report["skipped"] = json!("nothing changed since the last review");
        return Ok(report);
    }
    let (req, _) = store.usage_today().unwrap_or((0, 0));
    if req >= cfg.ai.limits.daily_quota as i64 {
        return Err("daily AI quota reached".into());
    }
    let mut sent = data.clone();
    sent["now"] = json!(now_iso());
    let user = prompts::review_user_prompt(&cfg.ai, &sent.to_string());
    let reply = providers::complete_with_retry(&cfg.ai, &prompts::system_prompt(&cfg.ai), &user, |err| {
        let _ = store.count_usage(err);
    })
    .map_err(|e| e.message)?;
    let reply = extract_json(&reply).ok_or("the model did not answer with a JSON object")?;
    report["summary"] = json!(truncate(reply.get("summary").and_then(Value::as_str).unwrap_or(""), 1000));
    let (ok, rejected) = check(cfg, &ctx, &reply);
    report["rejected"] = json!(rejected);
    let list: Vec<Value> = ok.iter().map(Checked::to_json).collect();
    if dry_run {
        report["would_apply"] = json!(list);
        return Ok(report);
    }
    if r.mode == "automatic" && !ok.is_empty() {
        apply(cfg, &fm, &ok)?;
        for c in &ok {
            let _ = store.add_proposal("review", "", &c.key(), &c.to_json(), &c.reason, c.confidence, "applied");
            let _ = store.history(None, "ai", &format!("filter_review_{}", c.action), json!({"rule_id": c.id, "reason": c.reason}));
            info!("AI filter review: {} {}", c.action, c.id);
        }
        report["applied"] = json!(list);
        // The evidence now includes the rules just written.
        fm.reload(true);
        let after = input(cfg, &Context::gather(cfg, store, &fm)?, &fm);
        let _ = store.meta_set("review_input", &sha(&[&after.to_string()], 16));
        return Ok(report);
    } else if r.mode == "suggest" {
        let mut proposed = vec![];
        for c in &ok {
            if store.has_proposal("review", &c.key()).unwrap_or(true) {
                continue;
            }
            let _ = store.add_proposal("review", "", &c.key(), &c.to_json(), &c.reason, c.confidence, "pending");
            proposed.push(c.to_json());
        }
        report["proposed"] = json!(proposed);
    }
    let _ = store.meta_set("review_input", &input_hash);
    Ok(report)
}

/// Accept a `review` proposal (suggest mode): apply that single change,
/// re-checked against the current rules and closures.
pub fn accept(cfg: &Config, store: &Store, payload: &Value) -> Result<(), String> {
    let mut fm = FilterManager::from_config(cfg);
    fm.reload(true);
    let ctx = Context::gather(cfg, store, &fm)?;
    let mut change = payload.clone();
    if let Some(rule) = payload.get("rule").filter(|r| r.is_object()) {
        change["match"] = rule["match"].clone();
        if let Some(m) = change["match"].as_object_mut() {
            m.remove("severity");
        }
        change["description"] = rule["description"].clone();
    }
    let mut cfg2 = cfg.clone();
    cfg2.ai.filter_review.minimum_confidence = 0.0;
    cfg2.ai.filter_review.minimum_rule_age_hours = 0.0; // the user decides
    let (ok, rejected) = check(&cfg2, &ctx, &json!({"changes": [change]}));
    if let Some(r) = rejected.first() {
        return Err(format!("no longer valid: {}", r["error"]));
    }
    apply(cfg, &fm, &ok)
}

fn record(store: &Store, res: &Result<Value, String>) {
    let _ = store.meta_set("review_last", &now_iso());
    match res {
        Ok(rep) => {
            let _ = store.meta_set("review_report", &rep.to_string());
            let _ = store.meta_set("review_error", "");
        }
        Err(e) => {
            warn!("AI filter review failed: {e}");
            let _ = store.meta_set("review_error", e);
        }
    }
}

/// State for the UI: mode, last run, next run, last report or error.
pub fn status(cfg: &Config, store: &Store) -> Value {
    let r = &cfg.ai.filter_review;
    let last = store.meta_get("review_last").ok().flatten();
    let next = last
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| format_ts(t.with_timezone(&chrono::Utc) + chrono::Duration::seconds((r.interval_hours * 3600.0) as i64)));
    json!({
        "mode": r.mode, "interval_hours": r.interval_hours, "last_run": last, "next_run": next,
        "report": store.meta_get("review_report").ok().flatten().and_then(|s| serde_json::from_str::<Value>(&s).ok()),
        "error": store.meta_get("review_error").ok().flatten().filter(|e| !e.is_empty()),
    })
}

/// Background scheduler (engine): one review every `interval_hours`, the
/// first one shortly after start.
pub fn spawn(cfg: Arc<Config>) {
    let r = &cfg.ai.filter_review;
    if !cfg.ai.enable || (r.mode != "suggest" && r.mode != "automatic") {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("ai-review".into())
        .spawn(move || {
            let store = match Store::open(&cfg.db_path()) {
                Ok(s) => s,
                Err(e) => return warn!("AI filter review cannot open the store: {e}"),
            };
            let interval = (cfg.ai.filter_review.interval_hours * 3600.0).max(60.0);
            info!("AI filter review scheduled every {:.1} h ({})", interval / 3600.0, cfg.ai.filter_review.mode);
            loop {
                let last = store.meta_get("review_last").ok().flatten();
                if hours_since(last.as_deref()) * 3600.0 >= interval {
                    let res = run(&cfg, &store, false);
                    record(&store, &res);
                }
                std::thread::sleep(Duration::from_secs(60));
            }
        });
}

/// `minisoc review`: run now, print the report.
pub fn run_cli(cfg: &Config, dry_run: bool, as_json: bool) -> Result<(), String> {
    if !cfg.ai.enable {
        return Err("AI is disabled (services.minisoc.ai.enable)".into());
    }
    if !dry_run && cfg.ai.filter_review.mode == "off" {
        return Err("filter review is off (services.minisoc.ai.filterReview.mode); use --dry-run to preview".into());
    }
    let store = crate::ctl::open_store(cfg)?;
    let res = run(cfg, &store, dry_run);
    if !dry_run {
        record(&store, &res);
    }
    let rep = res?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
        return Ok(());
    }
    println!(
        "review: {} FP / {} TP closures, {} AI rule(s){}",
        rep["fp_closed"], rep["tp_closed"], rep["ai_rules"],
        rep["skipped"].as_str().map(|s| format!(" — skipped: {s}")).unwrap_or_default()
    );
    if let Some(s) = rep["summary"].as_str().filter(|s| !s.is_empty()) {
        println!("summary: {s}");
    }
    for (label, key) in [("applied", "applied"), ("proposed", "proposed"), ("would apply", "would_apply")] {
        for c in rep[key].as_array().into_iter().flatten() {
            println!("{label}: {} {} — {}", c["action"].as_str().unwrap_or(""), c["id"].as_str().unwrap_or(""), c["reason"].as_str().unwrap_or(""));
        }
    }
    for c in rep["rejected"].as_array().into_iter().flatten() {
        println!("rejected: {} — {}", c["change"]["action"].as_str().unwrap_or("?"), c["error"].as_str().unwrap_or(""));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::providers::tests::mock_server;
    use crate::store::rule_hash;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "minisoc-review-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn config(url: &str, d: &std::path::Path) -> Config {
        let mut c = Config {
            state_dir: d.to_string_lossy().into(),
            ..Default::default()
        };
        c.filter.file = Some(d.join("alert_filter.yaml").to_string_lossy().into());
        c.filter.ai_file = d.join("ai_filters.yaml").to_string_lossy().into();
        c.ai.enable = true;
        c.ai.provider = Some("ollama".into());
        c.ai.model = Some("mock".into());
        c.ai.endpoint = Some(url.into());
        c.ai.prompt_override_dir = d.join("prompts").to_string_lossy().into();
        c.ai.limits.timeout_secs = 5;
        c.ai.filter_review.mode = "automatic".into();
        c
    }

    /// fapolicyd-like alert on one executable.
    fn alert(exe: &str, n: usize) -> Event {
        let rec = json!({"minisoc": {"source": "fapolicyd"}, "raw": format!("deny {exe} #{n}"),
            "parsed": {"severity": "low", "event_type": "fapolicyd_would_deny",
                       "message": format!("fapolicyd would deny execute {exe}"), "exe": exe, "n": n}});
        crate::normalize::normalize(&rec, &BTreeMap::new())
    }

    fn reply(changes: Value) -> impl Fn(&Value) -> (u16, Value) + Send + 'static {
        move |_| (200, json!({"message": {"content": json!({"summary": "s", "changes": changes}).to_string()}}))
    }

    const FILE_RULE: &str = r#"{"source": "fapolicyd", "event_type": "fapolicyd_would_deny", "fields": {"exe": "/home/u/.local/bin/tool"}}"#;

    #[test]
    fn creates_a_rule_from_repeated_fp_closures_and_counts_reset() {
        let d = tmp("create");
        let m: Value = serde_json::from_str(FILE_RULE).unwrap();
        let url = mock_server(reply(json!([{"action": "create", "match": m, "description": "tool", "reason": "user closes it as FP", "confidence": 0.9}])), Duration::ZERO);
        let cfg = config(&url, &d);
        let store = Store::open(&cfg.db_path()).unwrap();
        // Two FP closures: below the minimum (3) -> rejected.
        for n in 0..2 {
            let e = alert("/home/u/.local/bin/tool", n);
            store.upsert(&e, None).unwrap();
            store.close(&e.id, "fp", "user", json!({})).unwrap();
        }
        let rep = run(&cfg, &store, false).unwrap();
        assert!(rep["applied"].as_array().unwrap().is_empty(), "{rep}");
        assert!(rep["rejected"][0]["error"].as_str().unwrap().contains("required"), "{rep}");
        // A third one: created in the AI file, severity injected.
        let e = alert("/home/u/.local/bin/tool", 2);
        store.upsert(&e, None).unwrap();
        store.close(&e.id, "fp", "user", json!({})).unwrap();
        let rep = run(&cfg, &store, false).unwrap();
        assert_eq!(rep["applied"].as_array().unwrap().len(), 1, "{rep}");
        let text = std::fs::read_to_string(cfg.ai_filter_file()).unwrap();
        assert!(text.contains("ai-review-") && text.contains("severity"), "{text}");
        assert!(!cfg.user_filter_file().exists(), "the user file is never written");
        // Same evidence again: no new request.
        assert!(run(&cfg, &store, false).unwrap()["skipped"].is_string());
    }

    #[test]
    fn never_hides_tp_pinned_or_unjudged_patterns() {
        let d = tmp("guard");
        let cfg = config("http://127.0.0.1:9", &d);
        let store = Store::open(&cfg.db_path()).unwrap();
        for n in 0..3 {
            let e = alert("/tmp/x/tool", n);
            store.upsert(&e, None).unwrap();
            store.close(&e.id, "fp", "user", json!({})).unwrap();
        }
        // Same executable prefix, another pattern the user closed as TP.
        let tp = alert("/tmp/x/tool-evil", 9);
        store.upsert(&tp, None).unwrap();
        store.close(&tp.id, "tp", "user", json!({})).unwrap();
        let mut fm = FilterManager::from_config(&cfg);
        fm.reload(true);
        let ctx = Context::gather(&cfg, &store, &fm).unwrap();
        let broad = json!({"changes": [{"action": "create", "confidence": 0.9, "match": {
            "source": "fapolicyd", "event_type": "fapolicyd_would_deny", "fields": {"exe": {"prefix": "/tmp/x/tool"}}}}]});
        let (ok, rej) = check(&cfg, &ctx, &broad);
        assert!(ok.is_empty());
        assert!(rej[0]["error"].as_str().unwrap().contains("true positive"), "{rej:?}");
        let exact = json!({"changes": [{"action": "create", "confidence": 0.9, "match": {
            "source": "fapolicyd", "event_type": "fapolicyd_would_deny", "fields": {"exe": "/tmp/x/tool"}}}]});
        assert_eq!(check(&cfg, &ctx, &exact).0.len(), 1);
        // A user rule can never be changed.
        let user = json!({"changes": [{"action": "delete", "id": "user-rule", "confidence": 1.0}]});
        assert!(check(&cfg, &ctx, &user).1[0]["error"].as_str().unwrap().contains("never changed"));
        // Source-wide rules are refused.
        let wide = json!({"changes": [{"action": "create", "confidence": 1.0, "match": {"source": "fapolicyd", "event_type": "fapolicyd_would_deny"}}]});
        assert!(check(&cfg, &ctx, &wide).0.is_empty());
    }

    #[test]
    fn deletes_only_old_rules_that_filter_little() {
        let d = tmp("delete");
        let cfg = config("http://127.0.0.1:9", &d);
        let store = Store::open(&cfg.db_path()).unwrap();
        filters::write_rules(&cfg.ai_filter_file(), &[
            json!({"id": "ai-quiet", "match": {"source": "a", "event_type": "b", "message": "quiet rule"}}),
            json!({"id": "ai-busy", "match": {"source": "a", "event_type": "b", "message": "busy rule"}}),
        ], filters::AI_HEADER, None, 5).unwrap();
        let mut fm = FilterManager::from_config(&cfg);
        fm.reload(true);
        store.sync_rule_stats(&fm.ruleset).unwrap();
        for i in 0..5 {
            store.upsert(&alert(&format!("/x{i}"), i), Some("ai-busy")).unwrap();
        }
        let del = json!({"changes": [{"action": "delete", "id": "ai-quiet", "confidence": 0.9}, {"action": "delete", "id": "ai-busy", "confidence": 0.9}]});
        // Too young.
        let ctx = Context::gather(&cfg, &store, &fm).unwrap();
        assert!(check(&cfg, &ctx, &del).0.is_empty());
        // Old enough: the quiet one goes, the busy one stays.
        store.conn.execute("UPDATE filter_stats SET since = '2000-01-01T00:00:00.000Z'", []).unwrap();
        let ctx = Context::gather(&cfg, &store, &fm).unwrap();
        let (ok, rej) = check(&cfg, &ctx, &del);
        assert_eq!(ok.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["ai-quiet"]);
        assert!(rej[0]["error"].as_str().unwrap().contains("still excludes 5"), "{rej:?}");
        apply(&cfg, &fm, &ok).unwrap();
        let text = std::fs::read_to_string(cfg.ai_filter_file()).unwrap();
        assert!(!text.contains("ai-quiet") && text.contains("ai-busy"));
    }

    #[test]
    fn rule_hash_follows_the_definition() {
        let a = json!({"id": "r", "match": {"source": "x"}});
        let b = json!({"id": "r", "match": {"source": "y"}});
        assert_ne!(rule_hash(&a), rule_hash(&b));
    }
}
