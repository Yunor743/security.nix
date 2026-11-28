//! The engine loop (systemd user service): hot-reload filters, ingest the
//! spool, normalize + filter + store, feed the AI queue, prune, and publish
//! `$XDG_RUNTIME_DIR/minisoc/state.json` (atomic) for the UI.

use crate::ai::analyzer::Analyzer;
use crate::config::Config;
use crate::filters::{EventView, FilterManager};
use crate::store::Store;
use crate::util::{atomic_write, ensure_dir, now_iso, sev_rank};
use crate::{debug, info, ingest, normalize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Spool records per tick (one transaction).
const BUDGET: usize = 2000;

pub struct Engine {
    pub cfg: Arc<Config>,
    pub store: Store,
    pub filters: FilterManager,
    pub analyzer: Option<Analyzer>,
    started_at: String,
    /// The last poll stopped at its budget: more is waiting in the spool.
    backlog: bool,
    /// Alerts created since the last retention pass.
    created: i64,
}

impl Engine {
    pub fn new(cfg: Config) -> Result<Self, String> {
        let cfg = Arc::new(cfg);
        for d in [cfg.state_dir(), cfg.runtime_dir(), cfg.inbox_dir()] {
            ensure_dir(&d, 0o700).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let store = Store::open(&cfg.db_path()).map_err(|e| format!("store: {e}"))?;
        let mut filters = FilterManager::from_config(&cfg);
        filters.seed();
        filters.reload(true);
        store
            .sync_rule_stats(&filters.ruleset)
            .map_err(|e| e.to_string())?;
        store
            .refilter(&filters.ruleset)
            .map_err(|e| e.to_string())?;
        let analyzer =
            (cfg.ai.enable && cfg.ai.analysis.enabled).then(|| Analyzer::start(cfg.clone()));
        crate::ai::review::spawn(cfg.clone());
        if let Some(a) = &analyzer {
            if cfg.ai.analysis.auto_analyze {
                let min = sev_rank(&cfg.ai.analysis.min_severity);
                for id in store
                    .unanalyzed(min, cfg.ai.limits.max_queue)
                    .unwrap_or_default()
                {
                    if let Ok(Some(e)) = store.event(&id) {
                        a.submit(&e.id, &e.fingerprint, &e.severity, false);
                    }
                }
            }
        }
        Ok(Self {
            cfg,
            store,
            filters,
            analyzer,
            started_at: now_iso(),
            backlog: false,
            created: 0,
        })
    }

    /// One iteration; returns true when something changed.
    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if self.filters.reload(false) {
            // New or modified rules count from 0 again.
            let reset = self
                .store
                .sync_rule_stats(&self.filters.ruleset)
                .unwrap_or_default();
            let n = self.store.refilter(&self.filters.ruleset).unwrap_or(0);
            let _ = self.store.history(None, "engine", "rules_reloaded", json!({
                "rules": self.filters.ruleset.rules.len(), "events_changed": n, "counters_reset": reset,
                "status": self.filters.status(),
            }));
            changed = true;
        }
        let dirs = self.cfg.all_spool_dirs();
        let mut to_analyze = vec![];
        let tx = self.store.conn.unchecked_transaction().ok();
        let window = self.cfg.aggregate_window_secs;
        let mut created = 0;
        let n = ingest::poll(&self.store, &dirs, BUDGET, |rec| {
            let e = normalize::normalize(&rec, &self.cfg.sources);
            let view = EventView {
                source: &e.source,
                severity: &e.severity,
                event_type: &e.event_type,
                message: &e.message,
                fields: &e.fields,
            };
            let rule = self.filters.ruleset.matching(&view).map(|r| r.id.clone());
            if self.cfg.filter.debug {
                debug!(
                    "filter {} {} => {}: {}",
                    e.id,
                    e.message,
                    rule.as_deref().unwrap_or("kept"),
                    Value::Array(self.filters.ruleset.explain(&view))
                );
            }
            match self.store.record(&e, rule.as_deref(), window) {
                Ok(true) if rule.is_none() => {
                    created += 1;
                    to_analyze.push((e.id.clone(), e.fingerprint.clone(), e.severity.clone()))
                }
                Ok(true) => created += 1,
                Ok(false) => {}
                Err(err) => crate::error!("store: {err}"),
            }
        });
        if let Some(tx) = tx {
            let _ = tx.commit();
        }
        self.backlog = n >= BUDGET;
        self.created += created;
        if n > 0 {
            debug!("ingested {n} record(s)");
            changed = true;
        }
        if let Some(a) = &self.analyzer {
            for (id, fp, sev) in to_analyze {
                if a.admissible(&sev) {
                    a.submit(&id, &fp, &sev, false);
                }
            }
        }
        for id in self.store.take_analysis_requests().unwrap_or_default() {
            match (&self.analyzer, self.store.event(&id)) {
                (Some(a), Ok(Some(e))) => a.submit(&e.id, &e.fingerprint, &e.severity, true),
                _ => {
                    let _ = self.store.history(
                        Some(&id),
                        "engine",
                        "analysis_unavailable",
                        json!({"reason": "AI disabled"}),
                    );
                }
            }
            changed = true;
        }
        changed
    }

    pub fn state(&self) -> Value {
        let r = &self.cfg.retention;
        let list = |s: &str, n: usize| self.store.list(s, n).unwrap_or_default();
        let stats = self
            .store
            .filter_stats(self.cfg.filter.recent_days)
            .unwrap_or(json!({}));
        let rules: Vec<Value> = self
            .filters
            .ruleset
            .rules
            .iter()
            .map(|rule| {
                let mut v = rule.summary();
                let s = stats.get(&rule.id);
                // Alerts excluded since the rule was created or last changed.
                v["hits"] = s.map(|s| s["hits"].clone()).unwrap_or(json!(0));
                v["since"] = s.map(|s| s["since"].clone()).unwrap_or(Value::Null);
                v["last_hit"] = s.map(|s| s["last_hit"].clone()).unwrap_or(Value::Null);
                v["hidden"] = s.map(|s| s["hidden"].clone()).unwrap_or(json!(0));
                v["recent_hits"] = s.map(|s| s["recent_hits"].clone()).unwrap_or(json!(0));
                v["recent_days"] = json!(self.cfg.filter.recent_days.max(1));
                v["owner"] = json!(self.filters.owner(std::path::Path::new(&rule.origin)));
                v
            })
            .collect();
        let mut filter = self.filters.status();
        filter["user_file"] = json!(self.filters.user_file);
        filter["ai_file"] = json!(self.filters.ai_file);
        filter["list"] = json!(rules);
        filter["debug"] = json!(self.cfg.filter.debug);
        filter["backups"] = json!(crate::filters::list_backups(&self.cfg.backup_dir()).len());
        json!({
            "version": 1,
            "generated_at": now_iso(),
            "engine": {"pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"), "started_at": self.started_at},
            "counts": self.store.counts().unwrap_or(json!({})),
            "pinned": list("pinned", 100),
            "recent": list("active", r.export_recent),
            "closed": list("closed", r.export_discarded),
            "filtered": list("filtered", r.export_filtered),
            "proposals": self.store.proposals(Some("pending"), 50).unwrap_or_default(),
            "filter": filter,
            "ai": self.analyzer.as_ref().map(|a| {
                let mut s = a.status(&self.store);
                s["filter_review"] = crate::ai::review::status(&self.cfg, &self.store);
                s
            }).unwrap_or(json!({"enabled": false})),
        })
    }

    pub fn export(&self) -> std::io::Result<()> {
        let data = serde_json::to_vec(&self.state()).unwrap_or_default();
        atomic_write(&self.cfg.state_json(), &data, 0o600)
    }

    pub fn run(mut self) -> ! {
        info!(
            "MiniSOC engine {} started (spool: {:?}, rules: {})",
            env!("CARGO_PKG_VERSION"),
            self.cfg.all_spool_dirs(),
            self.filters.user_file.display()
        );
        let poll = Duration::from_millis(self.cfg.poll_interval_ms.clamp(100, 60_000));
        let mut last_version = -1;
        let mut last_export = Instant::now() - Duration::from_secs(3600);
        let mut last_prune = Instant::now() - Duration::from_secs(3600);
        loop {
            let changed = self.tick();
            let r = &self.cfg.retention;
            // Hourly, or as soon as a burst of new alerts could exceed the cap.
            if last_prune.elapsed() >= Duration::from_secs(3600)
                || self.created >= (r.max_events / 10).max(1000)
                    && last_prune.elapsed() >= Duration::from_secs(60)
            {
                match self.store.prune(r.days, r.max_events) {
                    Ok(n) if n > 0 => info!("retention: pruned {n} event(s)"),
                    _ => {}
                }
                last_prune = Instant::now();
                self.created = 0;
            }
            let dv = self.store.data_version();
            // Periodic refresh keeps the AI status in the UI current. While
            // catching up a backlog, publish at most once per poll interval.
            let due = !self.backlog || last_export.elapsed() >= poll;
            if due
                && (changed
                    || dv != last_version
                    || last_export.elapsed() >= Duration::from_secs(10))
            {
                if let Err(e) = self.export() {
                    crate::error!("cannot write {}: {e}", self.cfg.state_json().display());
                }
                last_version = dv;
                last_export = Instant::now();
            }
            if !self.backlog {
                std::thread::sleep(poll);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_to_state_without_ai_and_with_hot_reload() {
        let d = std::env::temp_dir().join(format!("minisoc-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let spool = d.join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let mut cfg = Config {
            spool_dirs: vec![spool.to_string_lossy().into()],
            state_dir: d.join("state").to_string_lossy().into(),
            runtime_dir: d.join("run").to_string_lossy().into(),
            inbox_dir: d.join("inbox").to_string_lossy().into(),
            ..Default::default()
        };
        cfg.filter.file = Some(d.join("cfg/alert_filter.yaml").to_string_lossy().into());
        let mut eng = Engine::new(cfg).unwrap();
        // Seeded user file is 0600 in a 0700 dir.
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d.join("cfg/alert_filter.yaml")), 0o600);
        assert_eq!(mode(&d.join("cfg")), 0o700);
        let lines: String = (0..3).map(|i| format!(
            "{{\"minisoc\":{{\"source\":\"snort\",\"parser\":\"json\"}},\"raw\":\"r{i}\",\"parsed\":{{\"event_type\":\"{}\",\"severity\":\"info\",\"message\":\"m{}\",\"source_ip\":\"127.0.0.1\"}}}}\n",
            if i == 0 { "test_alert" } else { "scan" }, ["a", "b", "c"][i])).collect();
        std::fs::write(spool.join("events-2026-11-23.ndjson"), lines).unwrap();
        assert!(eng.tick());
        eng.export().unwrap();
        let st: Value =
            serde_json::from_slice(&std::fs::read(eng.cfg.state_json()).unwrap()).unwrap();
        assert_eq!(st["counts"]["active"], 3);
        assert_eq!(st["ai"]["enabled"], false);
        // Hot reload: a new rule hides matching events, stats count them.
        std::fs::write(d.join("cfg/alert_filter.yaml"),
            "version: 1\nfilters:\n  - id: ignore_test\n    match: {source: snort, event_type: test_alert}\n").unwrap();
        assert!(eng.tick());
        let st = eng.state();
        assert_eq!(st["counts"]["active"], 2);
        assert_eq!(st["filtered"][0]["filtered_by"], "ignore_test");
        // A broken edit does not bring hidden events back nor hide everything.
        std::fs::write(
            d.join("cfg/alert_filter.yaml"),
            "version: 1\nfilters: [ {id: x, match: {} } ]\n",
        )
        .unwrap();
        eng.tick();
        let st = eng.state();
        assert_eq!(st["counts"]["active"], 2);
        assert_eq!(st["filter"]["ok"], false);
    }
}
