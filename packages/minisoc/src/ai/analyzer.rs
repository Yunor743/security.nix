//! Asynchronous AI analysis: a bounded in-memory queue drained by worker
//! threads, each with its own SQLite connection. The collector loop only
//! enqueues, so a slow or unavailable provider never blocks ingestion or the
//! UI.
//!
//! Per job: daily quota -> rate limit -> cache (by similarity fingerprint +
//! provider + model + prompts) -> provider call with timeout/retry/backoff ->
//! strict reply validation -> store -> auto-discard / auto-filter policies.
//! Events of a similarity group already queued or in flight share its result
//! instead of costing another request.

use super::policy::{self, Decision};
use super::{prompts, providers, redact, validate_analysis};
use crate::config::Config;
use crate::store::Store;
use crate::util::{now_iso, sev_rank, sha};
use crate::{error, info, warn};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct Job {
    event_id: String,
    fingerprint: String,
    rank: usize,
    manual: bool,
}

#[derive(Default)]
struct Shared {
    queue: VecDeque<Job>,
    /// fingerprint -> event ids waiting for the result of a queued/in-flight job
    waiters: HashMap<String, Vec<String>>,
    in_flight: usize,
    next_slot: Option<Instant>,
    last_error: Option<String>,
    last_success: Option<String>,
    dropped: u64,
    stop: bool,
}

pub struct Analyzer {
    cfg: Arc<Config>,
    shared: Arc<(Mutex<Shared>, Condvar)>,
    #[allow(dead_code)] // joined by stop() (tests, graceful shutdown)
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl Analyzer {
    pub fn start(cfg: Arc<Config>) -> Self {
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let n = cfg.ai.limits.max_concurrent.clamp(1, 8);
        let handles = (0..n)
            .map(|i| {
                let (cfg, shared) = (cfg.clone(), shared.clone());
                std::thread::Builder::new()
                    .name(format!("ai-{i}"))
                    .spawn(move || worker(cfg, shared))
                    .unwrap()
            })
            .collect();
        info!(
            "AI analyzer started: provider={} model={} remote={} workers={n}",
            cfg.ai.provider.as_deref().unwrap_or("?"),
            cfg.ai.model.as_deref().unwrap_or("?"),
            providers::is_remote(&cfg.ai)
        );
        Self {
            cfg,
            shared,
            handles,
        }
    }

    pub fn admissible(&self, severity: &str) -> bool {
        let a = &self.cfg.ai.analysis;
        // `unknown` is treated as medium: uncertain events deserve a look.
        let rank = if severity == "unknown" {
            sev_rank("medium")
        } else {
            sev_rank(severity)
        };
        a.enabled && a.auto_analyze && rank >= sev_rank(&a.min_severity)
    }

    pub fn submit(&self, event_id: &str, fingerprint: &str, severity: &str, manual: bool) {
        let (lock, cv) = &*self.shared;
        let mut s = lock.lock().unwrap();
        if let Some(w) = s.waiters.get_mut(fingerprint) {
            if !w.iter().any(|x| x == event_id) {
                w.push(event_id.to_string());
            }
            return;
        }
        if s.queue.len() >= self.cfg.ai.limits.max_queue.max(1) {
            // Drop the least severe, oldest job (manual requests are kept).
            let victim = s
                .queue
                .iter()
                .enumerate()
                .filter(|(_, j)| !j.manual)
                .min_by_key(|(i, j)| (j.rank, *i))
                .map(|(i, _)| i);
            match victim {
                Some(i) if s.queue[i].rank <= sev_rank(severity) || manual => {
                    let j = s.queue.remove(i).unwrap();
                    s.waiters.remove(&j.fingerprint);
                    s.dropped += 1;
                    warn!("AI queue full, dropped analysis of {}", j.event_id);
                }
                _ => {
                    s.dropped += 1;
                    return;
                }
            }
        }
        s.waiters
            .insert(fingerprint.to_string(), vec![event_id.to_string()]);
        let job = Job {
            event_id: event_id.into(),
            fingerprint: fingerprint.into(),
            rank: sev_rank(severity),
            manual,
        };
        // Most severe first, FIFO within a level.
        let pos = s
            .queue
            .iter()
            .position(|j| j.rank < job.rank)
            .unwrap_or(s.queue.len());
        s.queue.insert(pos, job);
        cv.notify_one();
    }

    pub fn status(&self, store: &Store) -> Value {
        let s = self.shared.0.lock().unwrap();
        let (req, err) = store.usage_today().unwrap_or((0, 0));
        json!({
            "enabled": true,
            "provider": self.cfg.ai.provider, "model": self.cfg.ai.model,
            "remote": providers::is_remote(&self.cfg.ai),
            "endpoint_host": providers::endpoint(&self.cfg.ai).map(|e| e.split('/').take(3).collect::<Vec<_>>().join("/")),
            "queue": s.queue.len(), "in_flight": s.in_flight, "dropped": s.dropped,
            "last_error": s.last_error, "last_success": s.last_success,
            "requests_today": req, "errors_today": err, "daily_quota": self.cfg.ai.limits.daily_quota,
            "auto_discard": self.cfg.ai.auto_discard.mode, "auto_filter": self.cfg.ai.auto_filter.mode,
            "state": if s.last_error.is_some() && s.last_success.is_none() { "error" }
                     else if s.in_flight > 0 || !s.queue.is_empty() { "busy" } else { "idle" },
        })
    }

    #[allow(dead_code)]
    pub fn stop(self) {
        {
            let mut s = self.shared.0.lock().unwrap();
            s.stop = true;
            s.queue.clear();
        }
        self.shared.1.notify_all();
        for h in self.handles {
            let _ = h.join();
        }
    }
}

fn worker(cfg: Arc<Config>, shared: Arc<(Mutex<Shared>, Condvar)>) {
    let store = match Store::open(&cfg.db_path()) {
        Ok(s) => s,
        Err(e) => {
            error!("AI worker cannot open the store: {e}");
            return;
        }
    };
    let (lock, cv) = &*shared;
    loop {
        let job = {
            let mut s = lock.lock().unwrap();
            loop {
                if s.stop {
                    return;
                }
                if let Some(j) = s.queue.pop_front() {
                    s.in_flight += 1;
                    break j;
                }
                s = cv.wait_timeout(s, Duration::from_secs(5)).unwrap().0;
            }
        };
        let res = process(&cfg, &store, &shared, &job);
        let mut s = lock.lock().unwrap();
        s.in_flight -= 1;
        let waiters = s.waiters.remove(&job.fingerprint).unwrap_or_default();
        match res {
            Ok(Some((analysis, provider, model))) => {
                s.last_success = Some(now_iso());
                s.last_error = None;
                drop(s);
                for id in waiters.iter().filter(|w| **w != job.event_id) {
                    let _ = store.set_analysis(id, &provider, &model, &analysis, true);
                    let _ = store.history(
                        Some(id),
                        "ai",
                        "analysis_shared",
                        json!({"from": job.event_id}),
                    );
                    apply_discard_policy(&cfg, &store, id, &analysis);
                }
            }
            Ok(None) => {}
            Err(e) => {
                s.last_error = Some(e.clone());
                drop(s);
                let _ = store.history(
                    Some(&job.event_id),
                    "ai",
                    "analysis_failed",
                    json!({"error": e}),
                );
            }
        }
    }
}

fn wait_rate_slot(cfg: &Config, shared: &Arc<(Mutex<Shared>, Condvar)>) {
    let rpm = cfg.ai.limits.requests_per_minute.max(1);
    let interval = Duration::from_secs_f64(60.0 / rpm as f64);
    let wait = {
        let mut s = shared.0.lock().unwrap();
        let now = Instant::now();
        let slot = s.next_slot.filter(|t| *t > now).unwrap_or(now);
        s.next_slot = Some(slot + interval);
        slot.saturating_duration_since(now)
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

fn prompt_hash(cfg: &Config) -> String {
    let parts: Vec<String> = prompts::NAMES
        .iter()
        .map(|n| prompts::resolve(&cfg.ai, n).0)
        .collect();
    sha(&parts.iter().map(String::as_str).collect::<Vec<_>>(), 12)
}

type Analysis = (Value, String, String);

fn process(
    cfg: &Config,
    store: &Store,
    shared: &Arc<(Mutex<Shared>, Condvar)>,
    job: &Job,
) -> Result<Option<Analysis>, String> {
    let ai = &cfg.ai;
    let provider = ai.provider.clone().unwrap_or_default();
    let model = ai.model.clone().unwrap_or_default();
    let Some(event) = store.event(&job.event_id).map_err(|e| e.to_string())? else {
        return Ok(None);
    };

    let cache_key = sha(
        &[&event.fingerprint, &provider, &model, &prompt_hash(cfg)],
        24,
    );
    if !job.manual {
        if let Ok(Some(cached)) = store.cache_get(&cache_key, ai.limits.cache_ttl_hours) {
            store
                .set_analysis(&event.id, &provider, &model, &cached, true)
                .map_err(|e| e.to_string())?;
            apply_discard_policy(cfg, store, &event.id, &cached);
            // Recurring patterns are served from the cache: they must still be
            // able to trigger a rule proposal (guarded by has_proposal).
            maybe_auto_filter(cfg, store, shared, &event, &cached);
            return Ok(Some((cached, provider, model)));
        }
    }

    loop {
        let (req, _) = store.usage_today().unwrap_or((0, 0));
        if req < ai.limits.daily_quota as i64 {
            break;
        }
        shared.0.lock().unwrap().last_error = Some("daily quota reached".into());
        std::thread::sleep(Duration::from_secs(60));
        if shared.0.lock().unwrap().stop {
            return Ok(None);
        }
    }

    let stats = store
        .fingerprint_stats(&event.fingerprint)
        .map_err(|e| e.to_string())?;
    let data = redact::payload(
        &event,
        &ai.privacy,
        ai.limits.max_event_bytes,
        json!({
            "occurrences": stats["occurrences"], "similar_events": stats["events"],
        }),
    );
    let system = prompts::system_prompt(ai);
    let user = prompts::analysis_user_prompt(ai, &data);
    wait_rate_slot(cfg, shared);
    let reply = providers::complete_with_retry(ai, &system, &user, |err| {
        let _ = store.count_usage(err);
    })
    .map_err(|e| e.message)?;
    let analysis = validate_analysis(&reply)?;
    store
        .set_analysis(&event.id, &provider, &model, &analysis, false)
        .map_err(|e| e.to_string())?;
    store
        .cache_put(&cache_key, &analysis)
        .map_err(|e| e.to_string())?;
    store.history(Some(&event.id), "ai", "analyzed", json!({
        "provider": provider, "model": model, "classification": analysis["classification"],
        "confidence": analysis["confidence"], "suggested_action": analysis["suggested_action"],
    })).map_err(|e| e.to_string())?;
    apply_discard_policy(cfg, store, &event.id, &analysis);
    maybe_auto_filter(cfg, store, shared, &event, &analysis);
    Ok(Some((analysis, provider, model)))
}

fn apply_discard_policy(cfg: &Config, store: &Store, id: &str, analysis: &Value) {
    let Ok(Some(e)) = store.event(id) else { return };
    let pinned = store.is_pinned(id).unwrap_or(true);
    let stats = store.fingerprint_stats(&e.fingerprint).unwrap_or(json!({}));
    match policy::auto_discard(&e.severity, pinned, analysis, &stats, &cfg.ai.auto_discard) {
        Decision::Keep(why) => {
            info!("auto-discard: kept {} ({}): {}", e.id, e.severity, why);
        }
        Decision::Suggest(reasons) => {
            if !store.has_proposal("discard", &e.id).unwrap_or(true) {
                let _ = store.add_proposal("discard", &e.id, &e.id, &json!({"reasons": reasons}),
                    analysis["summary"].as_str().unwrap_or(""), analysis["benign_confidence"].as_f64().unwrap_or(0.0), "pending");
            }
        }
        Decision::Discard(reasons) => {
            if let Ok(true) = store.close(&e.id, "fp", "ai", json!({
                "reasons": reasons, "summary": analysis["summary"], "benign_confidence": analysis["benign_confidence"],
                "model": cfg.ai.model,
            })) {
                info!("AI closed {} ({}) as false positive", e.id, e.severity);
            }
        }
    }
}

fn maybe_auto_filter(
    cfg: &Config,
    store: &Store,
    shared: &Arc<(Mutex<Shared>, Condvar)>,
    event: &crate::normalize::Event,
    analysis: &Value,
) {
    let af = &cfg.ai.auto_filter;
    if af.mode != "suggest" && af.mode != "automatic" {
        return;
    }
    if !policy::allowed_severities(af).contains(&event.severity.as_str())
        || store.is_pinned(&event.id).unwrap_or(true)
    {
        return;
    }
    let stats = store
        .fingerprint_stats(&event.fingerprint)
        .unwrap_or(json!({}));
    if af.require_repeated_events
        && stats["occurrences"].as_i64().unwrap_or(0) < af.minimum_occurrences
    {
        return;
    }
    // Judge the verdict, not the verb: a cautious model rarely says "discard".
    let cls = analysis["classification"].as_str().unwrap_or("unknown");
    let benign = !policy::is_alarming(cls)
        && (policy::is_benign(cls) || analysis["suggested_action"] == "discard")
        && policy::fp_likely_enough(analysis, &af.minimum_false_positive_likelihood)
        && analysis["benign_confidence"].as_f64().unwrap_or(0.0) >= af.minimum_confidence;
    if !benign
        || store
            .has_proposal("filter", &event.fingerprint)
            .unwrap_or(true)
    {
        return;
    }
    let samples = store
        .events_by_fingerprint(&event.fingerprint, 5)
        .unwrap_or_default();
    let data: Vec<Value> = samples
        .iter()
        .map(|e| {
            serde_json::from_str(&redact::payload(
                e,
                &cfg.ai.privacy,
                cfg.ai.limits.max_event_bytes / 2,
                json!({}),
            ))
            .unwrap_or(Value::Null)
        })
        .collect();
    let user = prompts::filter_user_prompt(
        &cfg.ai,
        &json!({"events": data, "occurrences": stats["occurrences"]}).to_string(),
    );
    wait_rate_slot(cfg, shared);
    let reply = match providers::complete_with_retry(
        &cfg.ai,
        &prompts::system_prompt(&cfg.ai),
        &user,
        |err| {
            let _ = store.count_usage(err);
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("AI filter proposal failed: {}", e.message);
            return;
        }
    };
    let provider = cfg.ai.provider.clone().unwrap_or_default();
    let model = cfg.ai.model.clone().unwrap_or_default();
    let proposal = super::extract_json(&reply).unwrap_or(Value::Null);
    let confidence = proposal
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let reason = proposal
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let recent = store
        .recent_events(Some(&event.source), 5000)
        .unwrap_or_default();
    let built = if confidence < af.minimum_confidence {
        Err(format!(
            "confidence {confidence:.2} below {:.2}",
            af.minimum_confidence
        ))
    } else {
        policy::build_ai_rule(&proposal, event, &recent, af, &provider, &model)
    };
    match built {
        Err(why) => {
            let _ = store.add_proposal(
                "filter",
                &event.id,
                &event.fingerprint,
                &json!({"proposal": proposal, "error": why}),
                &reason,
                confidence,
                "invalid",
            );
            let _ = store.history(
                Some(&event.id),
                "ai",
                "filter_proposal_rejected",
                json!({"error": why}),
            );
            info!("AI filter proposal rejected by policy: {why}");
        }
        Ok(rule) if af.mode == "automatic" => {
            let backup = af.backup_before_write.then(|| cfg.ai_backup_dir());
            match crate::filters::append_rule(
                &cfg.ai_filter_file(),
                &rule,
                backup.as_deref(),
                cfg.filter.max_backups,
            ) {
                Ok(_) => {
                    let _ = store.add_proposal(
                        "filter",
                        &event.id,
                        &event.fingerprint,
                        &json!({"rule": rule}),
                        &reason,
                        confidence,
                        "applied",
                    );
                    let _ = store.history(
                        Some(&event.id),
                        "ai",
                        "filter_rule_added",
                        json!({"rule_id": rule["id"], "reason": reason}),
                    );
                    info!("AI added filter rule {}", rule["id"]);
                }
                Err(e) => {
                    let _ = store.add_proposal(
                        "filter",
                        &event.id,
                        &event.fingerprint,
                        &json!({"rule": rule, "error": e}),
                        &reason,
                        confidence,
                        "pending",
                    );
                    warn!("AI filter rule kept as suggestion, write failed: {e}");
                }
            }
        }
        Ok(rule) => {
            let _ = store.add_proposal(
                "filter",
                &event.id,
                &event.fingerprint,
                &json!({"rule": rule}),
                &reason,
                confidence,
                "pending",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::providers::tests::mock_server;
    use crate::store::Store;

    fn config(url: &str, dir: &std::path::Path) -> Config {
        let mut c = Config {
            state_dir: dir.to_string_lossy().into(),
            ..Default::default()
        };
        c.filter.file = Some(dir.join("alert_filter.yaml").to_string_lossy().into());
        c.ai.enable = true;
        c.ai.provider = Some("ollama".into());
        c.ai.model = Some("mock".into());
        c.ai.endpoint = Some(url.into());
        c.ai.prompt_override_dir = dir.join("prompts").to_string_lossy().into();
        c.ai.limits.requests_per_minute = 6000;
        c.ai.limits.timeout_secs = 5;
        c.ai.analysis.min_severity = "info".into();
        c
    }

    fn wait_idle(a: &Analyzer) {
        for _ in 0..200 {
            {
                let s = a.shared.0.lock().unwrap();
                if s.queue.is_empty() && s.in_flight == 0 {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("analyzer did not finish");
    }

    #[test]
    fn end_to_end_with_mock_provider_and_guardrails() {
        let d = std::env::temp_dir().join(format!("minisoc-analyzer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // A model that always says "benign, discard" with full confidence.
        let url = mock_server(
            |_| {
                (
                    200,
                    json!({"message": {"content": json!({
            "summary": "Benign admin command", "classification": "benign", "severity_assessment": "info",
            "confidence": 0.99, "benign_confidence": 0.99, "false_positive_likelihood": "high",
            "suggested_action": "discard"}).to_string()}}),
                )
            },
            Duration::ZERO,
        );
        let mut cfg = config(&url, &d);
        cfg.ai.auto_discard.mode = "automatic".into();
        cfg.ai.auto_discard.require_repeated_benign_pattern = false;
        let cfg = Arc::new(cfg);
        let store = Store::open(&cfg.db_path()).unwrap();
        let mk = |sev: &str, msg: &str| {
            let rec = json!({"minisoc": {"source": "app"}, "raw": format!("{sev}{msg}"), "parsed": {"severity": sev, "message": msg}});
            crate::normalize::normalize(&rec, &Default::default())
        };
        let low = mk("low", "admin ran whoami");
        let crit = mk("critical", "ransomware note dropped");
        let pinned = mk("low", "pinned thing");
        for e in [&low, &crit, &pinned] {
            store.upsert(e, None).unwrap();
        }
        store.set_pinned(&pinned.id, true, "user").unwrap();
        let a = Analyzer::start(cfg.clone());
        for e in [&low, &crit, &pinned] {
            a.submit(&e.id, &e.fingerprint, &e.severity, false);
        }
        wait_idle(&a);
        let get = |id: &str| store.get(id).unwrap().unwrap();
        assert_eq!(get(&low.id)["analyzed"], true);
        assert_eq!(
            get(&low.id)["discarded"],
            true,
            "low + benign => auto-discarded"
        );
        assert_eq!(get(&low.id)["closed_by"], "ai");
        assert_eq!(get(&low.id)["verdict"], "fp", "the AI closes as false positive only");
        assert_eq!(get(&crit.id)["analyzed"], true);
        assert_eq!(
            get(&crit.id)["discarded"],
            false,
            "critical never auto-discarded"
        );
        assert_eq!(get(&pinned.id)["discarded"], false, "pinned protected");
        assert!(get(&low.id)["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["actor"] == "ai" && h["action"] == "close_fp"));
        // Restorable.
        assert!(store.restore(&low.id, "user").unwrap());
        a.stop();
    }

    #[test]
    fn provider_down_does_not_block_and_is_reported() {
        let d = std::env::temp_dir().join(format!("minisoc-analyzer-down-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut cfg = config("http://127.0.0.1:9", &d); // nothing listens on port 9
        cfg.ai.limits.max_retries = 0;
        let cfg = Arc::new(cfg);
        let store = Store::open(&cfg.db_path()).unwrap();
        let rec = json!({"minisoc": {"source": "app"}, "raw": "x", "parsed": {"severity": "high", "message": "x"}});
        let e = crate::normalize::normalize(&rec, &Default::default());
        store.upsert(&e, None).unwrap();
        let a = Analyzer::start(cfg.clone());
        let t = Instant::now();
        a.submit(&e.id, &e.fingerprint, &e.severity, false);
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "submit never blocks"
        );
        wait_idle(&a);
        assert!(a.status(&store)["last_error"].is_string());
        assert_eq!(store.get(&e.id).unwrap().unwrap()["analyzed"], false);
        a.stop();
    }
}
