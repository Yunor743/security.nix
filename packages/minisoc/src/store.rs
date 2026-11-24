//! Local persistence (SQLite, WAL): event metadata and lifecycle, decision
//! history, AI analyses and proposals, ingestion offsets. Original logs and
//! the collector spool are never modified: closing or filtering only sets
//! flags here.
//!
//! States are independent flags, so an event can be e.g. pinned + analyzed:
//! - active    = not filtered and not closed (or pinned)
//! - pinned    = always visible, never hidden by a rule or an AI decision
//! - closed    = triaged out of the active feed, with a verdict: `tp` (true
//!   positive: real, handled) or `fp` (false positive: noise). The AI may
//!   only close as `fp`. Stored in the historical `discarded*` columns.
//! - filtered  = excluded by a filter rule (`filtered_by` = rule id)
//! - analyzed  = has an AI analysis

use crate::filters::{EventView, RuleSet};
use crate::normalize::Event;
use crate::util::{now_iso, sev_rank};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

pub struct Store {
    pub conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, source TEXT NOT NULL,
  severity TEXT NOT NULL, sev_rank INTEGER NOT NULL, event_type TEXT NOT NULL,
  message TEXT NOT NULL, fields TEXT NOT NULL, raw TEXT NOT NULL,
  fingerprint TEXT NOT NULL, meta TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,
  filtered_by TEXT, pinned INTEGER NOT NULL DEFAULT 0, pinned_at TEXT,
  discarded INTEGER NOT NULL DEFAULT 0, discarded_at TEXT, discarded_by TEXT,
  analyzed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_fp ON events(fingerprint);
CREATE TABLE IF NOT EXISTS analyses (
  event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, provider TEXT, model TEXT,
  result TEXT NOT NULL, confidence REAL, cached INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS analysis_cache (key TEXT PRIMARY KEY, result TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, ts TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS history_event ON history(event_id);
CREATE TABLE IF NOT EXISTS proposals (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, event_id TEXT, fingerprint TEXT,
  created_at TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL,
  reason TEXT, confidence REAL, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS filter_stats (rule_id TEXT PRIMARY KEY, hits INTEGER NOT NULL, last_hit TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS filter_hits_daily (
  rule_id TEXT NOT NULL, day TEXT NOT NULL, hits INTEGER NOT NULL, PRIMARY KEY (rule_id, day)
);
CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ai_usage (day TEXT PRIMARY KEY, requests INTEGER NOT NULL, errors INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS analysis_requests (event_id TEXT PRIMARY KEY, requested_at TEXT NOT NULL);
";

type R<T> = rusqlite::Result<T>;

/// Identity of a rule's definition: any change to it (match, enabled,
/// description...) restarts the rule's counter.
pub fn rule_hash(spec: &Value) -> String {
    crate::util::sha(&[&spec.to_string()], 16)
}

fn js(s: Option<String>) -> Value {
    s.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

impl Store {
    pub fn open(path: &Path) -> R<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        let s = Self { conn };
        // Columns added after the first release.
        s.add_column("events", "verdict", "TEXT")?;
        s.add_column("filter_stats", "rule_hash", "TEXT")?;
        s.add_column("filter_stats", "since", "TEXT")?;
        Ok(s)
    }

    fn add_column(&self, table: &str, col: &str, ty: &str) -> R<()> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let cols: Vec<String> = stmt.query_map([], |r| r.get(1))?.collect::<R<_>>()?;
        if !cols.iter().any(|c| c == col) {
            self.conn
                .execute(&format!("ALTER TABLE {table} ADD COLUMN {col} {ty}"), [])?;
        }
        Ok(())
    }

    pub fn meta_get(&self, key: &str) -> R<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
    }

    pub fn meta_set(&self, key: &str, value: &str) -> R<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Changes when another connection (ctl, AI worker) commits.
    pub fn data_version(&self) -> i64 {
        self.conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap_or(0)
    }

    pub fn history(
        &self,
        event_id: Option<&str>,
        actor: &str,
        action: &str,
        detail: Value,
    ) -> R<()> {
        self.conn.execute(
            "INSERT INTO history(event_id, ts, actor, action, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![event_id, now_iso(), actor, action, detail.to_string()],
        )?;
        Ok(())
    }

    /// Insert or count a repeat. Returns true for a new event.
    pub fn upsert(&self, e: &Event, filtered_by: Option<&str>) -> R<bool> {
        let now = now_iso();
        if let Some(rule) = filtered_by {
            self.conn.execute(
                "INSERT INTO filter_stats(rule_id, hits, last_hit) VALUES (?1, 1, ?2)
                 ON CONFLICT(rule_id) DO UPDATE SET hits = hits + 1, last_hit = ?2",
                params![rule, now],
            )?;
            // Per-day buckets: hits over a sliding window.
            self.conn.execute(
                "INSERT INTO filter_hits_daily(rule_id, day, hits) VALUES (?1, ?2, 1)
                 ON CONFLICT(rule_id, day) DO UPDATE SET hits = hits + 1",
                params![rule, &now[..10]],
            )?;
        }
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO events(id, ts, source, severity, sev_rank, event_type, message, fields, raw,
               fingerprint, meta, first_seen, last_seen, filtered_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?13)",
            params![e.id, e.timestamp, e.source, e.severity, sev_rank(&e.severity) as i64, e.event_type, e.message,
                e.fields.to_string(), e.raw, e.fingerprint, e.meta.to_string(), now, filtered_by],
        )?;
        if n == 0 {
            self.conn.execute(
                "UPDATE events SET occurrences = occurrences + 1, last_seen = ?2 WHERE id = ?1",
                params![e.id, now],
            )?;
        }
        Ok(n == 1)
    }

    /// Re-evaluate every non-pinned event after the rules changed, so a new
    /// rule hides past noise and removing a rule brings events back.
    pub fn refilter(&self, rules: &RuleSet) -> R<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, severity, event_type, message, fields, filtered_by FROM events WHERE pinned = 0",
        )?;
        let rows: Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        )> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<R<_>>()?;
        let tx = self.conn.unchecked_transaction()?;
        let mut changed = 0;
        for (id, source, severity, event_type, message, fields, old) in rows {
            let fields: Value = serde_json::from_str(&fields).unwrap_or(Value::Null);
            let view = EventView {
                source: &source,
                severity: &severity,
                event_type: &event_type,
                message: &message,
                fields: &fields,
            };
            let new = rules.matching(&view).map(|r| r.id.clone());
            if new != old {
                tx.execute(
                    "UPDATE events SET filtered_by = ?2 WHERE id = ?1",
                    params![id, new],
                )?;
                changed += 1;
            }
        }
        tx.commit()?;
        Ok(changed)
    }

    pub fn exists(&self, id: &str) -> R<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM events WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn set_pinned(&self, id: &str, pinned: bool, actor: &str) -> R<bool> {
        let n = self.conn.execute(
            "UPDATE events SET pinned = ?2, pinned_at = CASE WHEN ?2 THEN ?3 ELSE NULL END,
               filtered_by = CASE WHEN ?2 THEN NULL ELSE filtered_by END WHERE id = ?1",
            params![id, pinned, now_iso()],
        )?;
        if n > 0 {
            self.history(
                Some(id),
                actor,
                if pinned { "pin" } else { "unpin" },
                json!({}),
            )?;
        }
        Ok(n > 0)
    }

    /// Close an alert with a verdict (`tp` or `fp`). Nothing is deleted. The
    /// AI may only close as `fp`, and never a pinned alert (the user can). A
    /// closed alert can be re-qualified by the user (tp <-> fp).
    pub fn close(&self, id: &str, verdict: &str, actor: &str, detail: Value) -> R<bool> {
        if verdict != "tp" && verdict != "fp" || actor != "user" && verdict != "fp" {
            return Ok(false);
        }
        // The user may re-qualify, and confirming an AI closure makes it the
        // user's (only the user's judgements are filter review evidence).
        let guard = if actor == "user" {
            "(discarded = 0 OR verdict IS NOT ?4 OR discarded_by IS NOT 'user')"
        } else {
            "discarded = 0 AND pinned = 0"
        };
        let n = self.conn.execute(
            &format!("UPDATE events SET discarded = 1, discarded_at = ?2, discarded_by = ?3, verdict = ?4 WHERE id = ?1 AND {guard}"),
            params![id, now_iso(), actor, verdict],
        )?;
        if n > 0 {
            self.history(Some(id), actor, &format!("close_{verdict}"), detail)?;
        }
        Ok(n > 0)
    }

    /// Close every active alert as false positive (pinned ones are kept).
    /// Each alert gets its own history entry and stays re-openable.
    pub fn close_all_fp(&self, actor: &str, detail: Value) -> R<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM events WHERE discarded = 0 AND filtered_by IS NULL AND pinned = 0",
        )?;
        let ids: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<R<_>>()?;
        let tx = self.conn.unchecked_transaction()?;
        for id in &ids {
            self.close(id, "fp", actor, detail.clone())?;
        }
        tx.commit()?;
        Ok(ids.len())
    }

    /// Re-open a closed alert (its verdict is cleared).
    pub fn restore(&self, id: &str, actor: &str) -> R<bool> {
        let n = self.conn.execute(
            "UPDATE events SET discarded = 0, discarded_at = NULL, discarded_by = NULL, verdict = NULL WHERE id = ?1 AND discarded = 1",
            [id],
        )?;
        if n > 0 {
            self.history(Some(id), actor, "restore", json!({}))?;
        }
        Ok(n > 0)
    }

    const COLS: &'static str = "e.id, e.ts, e.source, e.severity, e.event_type, e.message, e.occurrences, e.pinned,
        e.discarded, e.discarded_by, e.filtered_by, e.analyzed, e.fingerprint, e.first_seen, e.last_seen,
        a.result, a.provider, a.model, e.pinned_at, e.verdict";

    fn summary(r: &Row) -> R<Value> {
        let analysis = js(r.get(15)?);
        let a = if analysis.is_null() {
            Value::Null
        } else {
            json!({
                "summary": analysis.get("summary"), "classification": analysis.get("classification"),
                "confidence": analysis.get("confidence"), "suggested_action": analysis.get("suggested_action"),
                "provider": r.get::<_, Option<String>>(16)?, "model": r.get::<_, Option<String>>(17)?,
            })
        };
        let closed = r.get::<_, bool>(8)?;
        let closed_by = r.get::<_, Option<String>>(9)?;
        // Closures from before verdicts existed were "discards": noise.
        let verdict = r
            .get::<_, Option<String>>(19)?
            .or_else(|| closed.then(|| "fp".to_string()));
        Ok(json!({
            "id": r.get::<_, String>(0)?, "timestamp": r.get::<_, String>(1)?, "source": r.get::<_, String>(2)?,
            "severity": r.get::<_, String>(3)?, "event_type": r.get::<_, String>(4)?, "message": r.get::<_, String>(5)?,
            "occurrences": r.get::<_, i64>(6)?, "pinned": r.get::<_, bool>(7)?,
            "closed": closed, "closed_by": closed_by, "verdict": verdict,
            // Former names, kept for scripts written against them.
            "discarded": closed, "discarded_by": closed_by,
            "filtered_by": r.get::<_, Option<String>>(10)?,
            "analyzed": r.get::<_, bool>(11)?, "fingerprint": r.get::<_, String>(12)?,
            "first_seen": r.get::<_, String>(13)?, "last_seen": r.get::<_, String>(14)?, "analysis": a,
            "pinned_at": r.get::<_, Option<String>>(18)?,
        }))
    }

    /// state: active | pinned | closed (alias discarded) | tp | fp | filtered | analyzed | all
    pub fn list(&self, state: &str, limit: usize) -> R<Vec<Value>> {
        let (cond, order) = match state {
            "pinned" => ("e.pinned = 1 AND e.discarded = 0", "e.pinned_at DESC"),
            "active" => (
                "e.pinned = 0 AND e.discarded = 0 AND e.filtered_by IS NULL",
                "e.ts DESC",
            ),
            "closed" | "discarded" => ("e.discarded = 1", "e.discarded_at DESC"),
            "tp" => ("e.discarded = 1 AND e.verdict = 'tp'", "e.discarded_at DESC"),
            "fp" => (
                "e.discarded = 1 AND COALESCE(e.verdict, 'fp') = 'fp'",
                "e.discarded_at DESC",
            ),
            "filtered" => ("e.filtered_by IS NOT NULL", "e.ts DESC"),
            "analyzed" => ("e.analyzed = 1", "e.ts DESC"),
            _ => ("1", "e.ts DESC"),
        };
        let sql = format!(
            "SELECT {} FROM events e LEFT JOIN analyses a ON a.event_id = e.id WHERE {cond} ORDER BY {order} LIMIT ?1",
            Self::COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([limit as i64], Self::summary)?.collect();
        rows
    }

    pub fn counts(&self) -> R<Value> {
        let mut by_sev = serde_json::Map::new();
        for s in crate::util::SEVERITIES {
            by_sev.insert(s.into(), json!(0));
        }
        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM events WHERE discarded = 0 AND (filtered_by IS NULL OR pinned = 1) GROUP BY severity",
        )?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (s, n) = row?;
            by_sev.insert(s, json!(n));
        }
        let q = |sql: &str| -> R<i64> { self.conn.query_row(sql, [], |r| r.get(0)) };
        Ok(json!({
            "active_by_severity": by_sev,
            "active": q("SELECT COUNT(*) FROM events WHERE discarded = 0 AND (filtered_by IS NULL OR pinned = 1)")?,
            "pinned": q("SELECT COUNT(*) FROM events WHERE pinned = 1")?,
            "closed": q("SELECT COUNT(*) FROM events WHERE discarded = 1")?,
            "closed_tp": q("SELECT COUNT(*) FROM events WHERE discarded = 1 AND verdict = 'tp'")?,
            "closed_fp": q("SELECT COUNT(*) FROM events WHERE discarded = 1 AND COALESCE(verdict, 'fp') = 'fp'")?,
            "closed_by_ai": q("SELECT COUNT(*) FROM events WHERE discarded = 1 AND discarded_by = 'ai'")?,
            // Former names.
            "discarded": q("SELECT COUNT(*) FROM events WHERE discarded = 1")?,
            "discarded_by_ai": q("SELECT COUNT(*) FROM events WHERE discarded = 1 AND discarded_by = 'ai'")?,
            "filtered": q("SELECT COUNT(*) FROM events WHERE filtered_by IS NOT NULL AND pinned = 0")?,
            "analyzed": q("SELECT COUNT(*) FROM events WHERE analyzed = 1")?,
            "total": q("SELECT COUNT(*) FROM events")?,
        }))
    }

    /// Per rule: `hits` = alerts it excluded since the rule was last created
    /// or modified (`since`), `recent_hits` = over the last `recent_days`
    /// days (and since that change), `last_hit`, and `hidden` = stored
    /// alerts it currently hides.
    pub fn filter_stats(&self, recent_days: i64) -> R<Value> {
        let from = crate::util::format_ts(
            chrono::Utc::now() - chrono::Duration::days(recent_days.max(1) - 1),
        );
        let mut stmt = self.conn.prepare(
            "SELECT f.rule_id, f.hits, f.last_hit, f.since,
               (SELECT COUNT(*) FROM events e WHERE e.filtered_by = f.rule_id AND e.pinned = 0),
               (SELECT COALESCE(SUM(d.hits), 0) FROM filter_hits_daily d WHERE d.rule_id = f.rule_id AND d.day >= ?1)
             FROM filter_stats f",
        )?;
        let mut m = serde_json::Map::new();
        for row in stmt.query_map([&from[..10]], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })? {
            let (id, hits, last, since, hidden, recent) = row?;
            m.insert(
                id,
                json!({"hits": hits, "recent_hits": recent, "recent_days": recent_days.max(1),
                       "last_hit": last, "since": since, "hidden": hidden}),
            );
        }
        Ok(Value::Object(m))
    }

    /// Align the counters with the effective rules: a new rule, or a rule
    /// whose definition changed, starts again from 0; removed rules are
    /// forgotten. Returns the ids whose counter was reset.
    pub fn sync_rule_stats(&self, rules: &RuleSet) -> R<Vec<String>> {
        let now = now_iso();
        let mut reset = vec![];
        let tx = self.conn.unchecked_transaction()?;
        for r in &rules.rules {
            let hash = rule_hash(&r.spec);
            let known: Option<Option<String>> = tx
                .query_row(
                    "SELECT rule_hash FROM filter_stats WHERE rule_id = ?1",
                    [&r.id],
                    |row| row.get(0),
                )
                .optional()?;
            if known.as_ref().and_then(|h| h.as_deref()) != Some(hash.as_str()) {
                tx.execute(
                    "INSERT INTO filter_stats(rule_id, hits, last_hit, rule_hash, since) VALUES (?1, 0, NULL, ?2, ?3)
                     ON CONFLICT(rule_id) DO UPDATE SET hits = 0, last_hit = NULL, rule_hash = ?2, since = ?3",
                    params![r.id, hash, now],
                )?;
                tx.execute("DELETE FROM filter_hits_daily WHERE rule_id = ?1", [&r.id])?;
                reset.push(r.id.clone());
            }
        }
        let ids: Vec<String> = rules.rules.iter().map(|r| r.id.clone()).collect();
        let mut stmt = tx.prepare("SELECT rule_id FROM filter_stats")?;
        let stale: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<R<Vec<String>>>()?
            .into_iter()
            .filter(|id| !ids.contains(id))
            .collect();
        drop(stmt);
        for id in stale {
            tx.execute("DELETE FROM filter_stats WHERE rule_id = ?1", [&id])?;
            tx.execute("DELETE FROM filter_hits_daily WHERE rule_id = ?1", [&id])?;
        }
        tx.commit()?;
        Ok(reset)
    }

    /// Closed alerts with a given verdict (`fp` includes pre-verdict
    /// closures), newest first. `by_user`: only the user's own judgements
    /// (the AI never learns from its own closures).
    pub fn closed_events(
        &self,
        verdict: &str,
        by_user: bool,
        since: &str,
        limit: usize,
    ) -> R<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM events WHERE discarded = 1 AND COALESCE(verdict, 'fp') = ?1
               AND (?2 = 0 OR discarded_by = 'user') AND discarded_at >= ?3
             ORDER BY discarded_at DESC LIMIT ?4",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![verdict, by_user, since, limit as i64], |r| r.get(0))?
            .collect::<R<_>>()?;
        Ok(ids
            .iter()
            .filter_map(|i| self.event(i).ok().flatten())
            .collect())
    }

    /// Recent events with their protection status, for checking what a
    /// candidate rule would hide: (event, pinned, verdict).
    pub fn recent_with_verdict(&self, limit: usize) -> R<Vec<(Event, bool, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pinned, CASE WHEN discarded = 1 THEN COALESCE(verdict, 'fp') END
             FROM events ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows: Vec<(String, bool, Option<String>)> = stmt
            .query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<R<_>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(i, p, v)| self.event(&i).ok().flatten().map(|e| (e, p, v)))
            .collect())
    }

    /// Full record for the details view.
    pub fn get(&self, id: &str) -> R<Option<Value>> {
        let base = self.conn.query_row(
            &format!("SELECT {}, e.fields, e.raw, e.meta FROM events e LEFT JOIN analyses a ON a.event_id = e.id WHERE e.id = ?1", Self::COLS),
            [id],
            |r| {
                let mut v = Self::summary(r)?;
                v["fields"] = js(r.get(20)?);
                v["raw"] = json!(r.get::<_, String>(21)?);
                v["meta"] = js(r.get(22)?);
                Ok(v)
            },
        ).optional()?;
        let Some(mut v) = base else { return Ok(None) };
        v["analysis_full"] = self.analysis(id)?.unwrap_or(Value::Null);
        let mut stmt = self.conn.prepare(
            "SELECT ts, actor, action, detail FROM history WHERE event_id = ?1 ORDER BY id",
        )?;
        let hist: Vec<Value> = stmt
            .query_map([id], |r| {
                Ok(json!({
                    "ts": r.get::<_, String>(0)?, "actor": r.get::<_, String>(1)?,
                    "action": r.get::<_, String>(2)?, "detail": js(r.get(3)?),
                }))
            })?
            .collect::<R<_>>()?;
        v["history"] = json!(hist);
        let mut stmt = self.conn.prepare("SELECT id, kind, status, reason, confidence, payload FROM proposals WHERE event_id = ?1 ORDER BY id")?;
        let props: Vec<Value> = stmt.query_map([id], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "status": r.get::<_, String>(2)?,
            "reason": r.get::<_, Option<String>>(3)?, "confidence": r.get::<_, Option<f64>>(4)?,
            "payload": js(r.get(5)?),
        })))?.collect::<R<_>>()?;
        v["proposals"] = json!(props);
        v["similar"] = json!(self.fingerprint_stats(v["fingerprint"].as_str().unwrap_or(""))?);
        Ok(Some(v))
    }

    pub fn event(&self, id: &str) -> R<Option<Event>> {
        self.conn.query_row(
            "SELECT id, ts, source, severity, event_type, message, fields, raw, fingerprint, meta FROM events WHERE id = ?1",
            [id],
            |r| Ok(Event {
                id: r.get(0)?, timestamp: r.get(1)?, source: r.get(2)?, severity: r.get(3)?, event_type: r.get(4)?,
                message: r.get(5)?, fields: js(r.get(6)?), raw: r.get(7)?, fingerprint: r.get(8)?, meta: js(r.get(9)?),
            }),
        ).optional()
    }

    pub fn is_pinned(&self, id: &str) -> R<bool> {
        Ok(self
            .conn
            .query_row("SELECT pinned FROM events WHERE id = ?1", [id], |r| {
                r.get::<_, bool>(0)
            })
            .optional()?
            .unwrap_or(false))
    }

    // ------------------------------------------------------------- analyses

    pub fn set_analysis(
        &self,
        id: &str,
        provider: &str,
        model: &str,
        result: &Value,
        cached: bool,
    ) -> R<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO analyses(event_id, created_at, provider, model, result, confidence, cached)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, now_iso(), provider, model, result.to_string(), result.get("confidence").and_then(Value::as_f64), cached],
        )?;
        self.conn
            .execute("UPDATE events SET analyzed = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn analysis(&self, id: &str) -> R<Option<Value>> {
        self.conn.query_row(
            "SELECT result, provider, model, created_at, cached FROM analyses WHERE event_id = ?1",
            [id],
            |r| Ok(json!({
                "result": js(r.get(0)?), "provider": r.get::<_, Option<String>>(1)?,
                "model": r.get::<_, Option<String>>(2)?, "created_at": r.get::<_, String>(3)?,
                "cached": r.get::<_, bool>(4)?,
            })),
        ).optional()
    }

    pub fn cache_get(&self, key: &str, ttl_hours: i64) -> R<Option<Value>> {
        let cutoff =
            crate::util::format_ts(chrono::Utc::now() - chrono::Duration::hours(ttl_hours));
        Ok(self
            .conn
            .query_row(
                "SELECT result FROM analysis_cache WHERE key = ?1 AND created_at >= ?2",
                params![key, cutoff],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub fn cache_put(&self, key: &str, result: &Value) -> R<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO analysis_cache(key, result, created_at) VALUES (?1, ?2, ?3)",
            params![key, result.to_string(), now_iso()],
        )?;
        Ok(())
    }

    /// Occurrences of a similarity group and how many of its analyses
    /// concluded "benign" (a cautious model rarely writes "discard", so the
    /// verdict is judged on the classification).
    pub fn fingerprint_stats(&self, fp: &str) -> R<Value> {
        let (events, occ): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(occurrences), 0) FROM events WHERE fingerprint = ?1",
            [fp],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let benign: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM analyses a JOIN events e ON e.id = a.event_id WHERE e.fingerprint = ?1
               AND json_extract(a.result, '$.classification') IN ('benign', 'false_positive')
               AND json_extract(a.result, '$.false_positive_likelihood') = 'high'",
            [fp], |r| r.get(0),
        )?;
        Ok(json!({"events": events, "occurrences": occ, "benign_analyses": benign}))
    }

    pub fn events_by_fingerprint(&self, fp: &str, limit: usize) -> R<Vec<Event>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM events WHERE fingerprint = ?1 ORDER BY ts DESC LIMIT ?2")?;
        let ids: Vec<String> = stmt
            .query_map(params![fp, limit as i64], |r| r.get(0))?
            .collect::<R<_>>()?;
        Ok(ids
            .iter()
            .filter_map(|i| self.event(i).ok().flatten())
            .collect())
    }

    /// Recent events (for checking a candidate rule's blast radius).
    pub fn recent_events(&self, source: Option<&str>, limit: usize) -> R<Vec<(Event, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pinned FROM events WHERE (?1 IS NULL OR source = ?1) ORDER BY ts DESC LIMIT ?2",
        )?;
        let ids: Vec<(String, bool)> = stmt
            .query_map(params![source, limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<R<_>>()?;
        Ok(ids
            .into_iter()
            .filter_map(|(i, p)| self.event(&i).ok().flatten().map(|e| (e, p)))
            .collect())
    }

    /// Events never analyzed, most severe and most recent first (startup
    /// recovery of the AI queue).
    pub fn unanalyzed(&self, min_rank: usize, limit: usize) -> R<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM events WHERE analyzed = 0 AND discarded = 0 AND filtered_by IS NULL
               AND (CASE WHEN severity = 'unknown' THEN 3 ELSE sev_rank END) >= ?1
             ORDER BY sev_rank DESC, ts DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![min_rank as i64, limit as i64], |r| r.get(0))?
            .collect();
        rows
    }

    pub fn take_analysis_requests(&self) -> R<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_id FROM analysis_requests ORDER BY requested_at")?;
        let ids: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<R<_>>()?;
        self.conn.execute("DELETE FROM analysis_requests", [])?;
        Ok(ids)
    }

    pub fn request_analysis(&self, id: &str) -> R<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO analysis_requests(event_id, requested_at) VALUES (?1, ?2)",
            params![id, now_iso()],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------ proposals

    pub fn add_proposal(
        &self,
        kind: &str,
        event_id: &str,
        fp: &str,
        payload: &Value,
        reason: &str,
        confidence: f64,
        status: &str,
    ) -> R<i64> {
        self.conn.execute(
            "INSERT INTO proposals(kind, event_id, fingerprint, created_at, status, payload, reason, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![kind, event_id, fp, now_iso(), status, payload.to_string(), reason, confidence],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn has_proposal(&self, kind: &str, fp: &str) -> R<bool> {
        Ok(self.conn.query_row(
            "SELECT 1 FROM proposals WHERE kind = ?1 AND fingerprint = ?2 AND (status IN ('pending', 'applied', 'accepted', 'rejected')
               OR (status = 'invalid' AND created_at >= ?3))",
            params![kind, fp, crate::util::format_ts(chrono::Utc::now() - chrono::Duration::hours(6))], |_| Ok(()),
        ).optional()?.is_some())
    }

    pub fn proposals(&self, status: Option<&str>, limit: usize) -> R<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.kind, p.event_id, p.created_at, p.status, p.payload, p.reason, p.confidence, e.message, e.severity, e.source
             FROM proposals p LEFT JOIN events e ON e.id = p.event_id
             WHERE (?1 IS NULL OR p.status = ?1) ORDER BY p.id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![status, limit as i64], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "event_id": r.get::<_, Option<String>>(2)?,
            "created_at": r.get::<_, String>(3)?, "status": r.get::<_, String>(4)?, "payload": js(r.get(5)?),
            "reason": r.get::<_, Option<String>>(6)?, "confidence": r.get::<_, Option<f64>>(7)?,
            "message": r.get::<_, Option<String>>(8)?, "severity": r.get::<_, Option<String>>(9)?,
            "source": r.get::<_, Option<String>>(10)?,
        })))?.collect();
        rows
    }

    pub fn proposal(&self, id: i64) -> R<Option<Value>> {
        Ok(self
            .proposals(None, 100000)?
            .into_iter()
            .find(|p| p["id"] == id))
    }

    pub fn set_proposal_status(&self, id: i64, status: &str) -> R<()> {
        self.conn.execute(
            "UPDATE proposals SET status = ?2, decided_at = ?3 WHERE id = ?1",
            params![id, status, now_iso()],
        )?;
        Ok(())
    }

    // ------------------------------------------------- offsets, usage, prune

    pub fn offset(&self, path: &str) -> R<Option<(u64, u64)>> {
        self.conn
            .query_row(
                "SELECT inode, offset FROM offsets WHERE path = ?1",
                [path],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )
            .optional()
    }

    pub fn set_offset(&self, path: &str, inode: u64, offset: u64) -> R<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO offsets(path, inode, offset) VALUES (?1, ?2, ?3)",
            params![path, inode as i64, offset as i64],
        )?;
        Ok(())
    }

    pub fn usage_today(&self) -> R<(i64, i64)> {
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        Ok(self
            .conn
            .query_row(
                "SELECT requests, errors FROM ai_usage WHERE day = ?1",
                [day],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0)))
    }

    pub fn count_usage(&self, error: bool) -> R<()> {
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.conn.execute(
            "INSERT INTO ai_usage(day, requests, errors) VALUES (?1, 1, ?2)
             ON CONFLICT(day) DO UPDATE SET requests = requests + 1, errors = errors + ?2",
            params![day, error as i64],
        )?;
        Ok(())
    }

    /// Retention: drop old / excess events (never pinned ones) and their data.
    pub fn prune(&self, days: i64, max_events: i64) -> R<usize> {
        let cutoff = crate::util::format_ts(chrono::Utc::now() - chrono::Duration::days(days));
        let mut n = self.conn.execute(
            "DELETE FROM events WHERE pinned = 0 AND last_seen < ?1",
            [&cutoff],
        )?;
        n += self.conn.execute(
            "DELETE FROM events WHERE pinned = 0 AND id NOT IN (SELECT id FROM events ORDER BY ts DESC LIMIT ?1)",
            [max_events],
        )?;
        self.conn.execute(
            "DELETE FROM analyses WHERE event_id NOT IN (SELECT id FROM events)",
            [],
        )?;
        self.conn.execute("DELETE FROM history WHERE ts < ?1 AND (event_id IS NULL OR event_id NOT IN (SELECT id FROM events))", [&cutoff])?;
        self.conn.execute(
            "DELETE FROM analysis_cache WHERE created_at < ?1",
            [&cutoff],
        )?;
        // Day buckets beyond any useful window.
        let old_day = crate::util::format_ts(chrono::Utc::now() - chrono::Duration::days(days.max(90)));
        self.conn.execute(
            "DELETE FROM filter_hits_daily WHERE day < ?1",
            [&old_day[..10]],
        )?;
        self.conn.execute(
            "DELETE FROM proposals WHERE created_at < ?1 AND status != 'pending'",
            [&cutoff],
        )?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::parse_document;
    use std::collections::BTreeMap;

    pub fn mem() -> Store {
        let d = std::env::temp_dir().join(format!(
            "minisoc-store-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&d).unwrap();
        Store::open(&d.join("db.sqlite3")).unwrap()
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    pub fn event(source: &str, sev: &str, msg: &str) -> Event {
        let rec = json!({"minisoc": {"source": source}, "raw": format!("{source}|{sev}|{msg}"),
            "parsed": {"severity": sev, "message": msg, "event_type": "test_alert"}});
        crate::normalize::normalize(&rec, &BTreeMap::new())
    }

    #[test]
    fn dedup_counts_occurrences() {
        let s = mem();
        let e = event("a", "low", "x");
        assert!(s.upsert(&e, None).unwrap());
        assert!(!s.upsert(&e, None).unwrap());
        assert_eq!(s.list("active", 10).unwrap()[0]["occurrences"], 2);
    }

    #[test]
    fn pin_close_reopen_lifecycle_persists() {
        let d = std::env::temp_dir().join(format!("minisoc-life-{}", rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        let db = d.join("db.sqlite3");
        let e = event("a", "medium", "y");
        {
            let s = Store::open(&db).unwrap();
            s.upsert(&e, None).unwrap();
            assert!(s.set_pinned(&e.id, true, "user").unwrap());
        }
        // Reopen: pin survives a restart.
        let s = Store::open(&db).unwrap();
        assert_eq!(s.list("pinned", 10).unwrap().len(), 1);
        // AI cannot close a pinned alert, nor ever as TP; the user can.
        assert!(!s.close(&e.id, "fp", "ai", json!({})).unwrap());
        assert!(!s.close(&e.id, "tp", "ai", json!({})).unwrap());
        assert!(s.close(&e.id, "fp", "user", json!({"reason": "seen"})).unwrap());
        assert_eq!(s.list("fp", 10).unwrap().len(), 1);
        // Re-qualified by the user: FP -> TP.
        assert!(s.close(&e.id, "tp", "user", json!({})).unwrap());
        assert!(!s.close(&e.id, "tp", "user", json!({})).unwrap(), "same verdict: no-op");
        let tp = s.list("tp", 10).unwrap();
        assert_eq!((tp.len(), tp[0]["verdict"].as_str()), (1, Some("tp")));
        assert_eq!(s.list("fp", 10).unwrap().len(), 0);
        assert!(s.restore(&e.id, "user").unwrap());
        assert_eq!(s.list("closed", 10).unwrap().len(), 0);
        assert!(s.list("pinned", 10).unwrap()[0]["verdict"].is_null());
        let full = s.get(&e.id).unwrap().unwrap();
        let actions: Vec<&str> = full["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions, ["pin", "close_fp", "close_tp", "restore"]);
    }

    #[test]
    fn refilter_never_hides_pinned() {
        let s = mem();
        let a = event("snort", "low", "noise");
        let b = event("snort", "low", "noise 2");
        s.upsert(&a, None).unwrap();
        s.upsert(&b, None).unwrap();
        s.set_pinned(&b.id, true, "user").unwrap();
        let rules = RuleSet {
            rules: parse_document(
                "version: 1\nfilters:\n  - id: r\n    match: {source: snort}\n",
                "t",
            )
            .unwrap(),
        };
        assert_eq!(s.refilter(&rules).unwrap(), 1);
        assert_eq!(s.list("active", 10).unwrap().len(), 0);
        assert_eq!(
            s.list("pinned", 10).unwrap().len(),
            1,
            "pinned stays visible"
        );
        assert_eq!(s.list("filtered", 10).unwrap().len(), 1);
        // Removing the rule brings the event back.
        assert_eq!(s.refilter(&RuleSet::default()).unwrap(), 1);
        assert_eq!(s.list("active", 10).unwrap().len(), 1);
    }

    #[test]
    fn close_all_fp_keeps_pinned_and_is_reopenable() {
        let s = mem();
        let evs: Vec<Event> = (0..4)
            .map(|i| event("a", "medium", &format!("bulk{i}")))
            .collect();
        for e in &evs {
            s.upsert(e, None).unwrap();
        }
        s.set_pinned(&evs[0].id, true, "user").unwrap();
        assert_eq!(s.close_all_fp("user", json!({"bulk": true})).unwrap(), 3);
        assert_eq!(s.counts().unwrap()["closed_fp"], 3);
        assert_eq!(s.list("active", 10).unwrap().len(), 0);
        assert_eq!(s.list("pinned", 10).unwrap().len(), 1, "pinned kept");
        assert_eq!(s.counts().unwrap()["active"], 1);
        assert!(s.restore(&evs[1].id, "user").unwrap());
        assert_eq!(s.list("active", 10).unwrap().len(), 1);
    }

    #[test]
    fn rule_counters_restart_when_the_rule_changes() {
        let s = mem();
        let rs = |m: &str| RuleSet {
            rules: parse_document(&format!("version: 1\nfilters:\n  - id: r\n    match: {m}\n"), "t")
                .unwrap(),
        };
        let v1 = rs("{source: snort}");
        assert_eq!(s.sync_rule_stats(&v1).unwrap(), ["r"], "new rule");
        s.upsert(&event("snort", "low", "a"), Some("r")).unwrap();
        s.upsert(&event("snort", "low", "b"), Some("r")).unwrap();
        assert!(s.sync_rule_stats(&v1).unwrap().is_empty(), "unchanged");
        let st = s.filter_stats(14).unwrap();
        assert_eq!((st["r"]["hits"].as_i64(), st["r"]["hidden"].as_i64()), (Some(2), Some(2)));
        let since = st["r"]["since"].clone();
        assert!(since.is_string());
        assert_eq!(st["r"]["recent_hits"], 2);
        // Hits older than the window leave the recent counter, not the total.
        s.conn
            .execute("UPDATE filter_hits_daily SET day = '2000-01-01'", [])
            .unwrap();
        let st = s.filter_stats(14).unwrap();
        assert_eq!((st["r"]["hits"].as_i64(), st["r"]["recent_hits"].as_i64()), (Some(2), Some(0)));
        // Modified definition: the counter starts again.
        assert_eq!(s.sync_rule_stats(&rs("{source: suricata}")).unwrap(), ["r"]);
        assert_eq!(s.filter_stats(14).unwrap()["r"]["hits"], 0);
        // Removed rule: forgotten.
        s.sync_rule_stats(&RuleSet::default()).unwrap();
        assert!(s.filter_stats(14).unwrap().get("r").is_none());
    }

    #[test]
    fn closed_events_learning_set_is_the_users() {
        let s = mem();
        let a = event("a", "low", "user fp");
        let b = event("a", "low", "ai fp");
        let c = event("a", "low", "user tp");
        for e in [&a, &b, &c] {
            s.upsert(e, None).unwrap();
        }
        s.close(&a.id, "fp", "user", json!({})).unwrap();
        s.close(&b.id, "fp", "ai", json!({})).unwrap();
        s.close(&c.id, "tp", "user", json!({})).unwrap();
        let fp = s.closed_events("fp", true, "2000", 10).unwrap();
        assert_eq!(fp.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), [a.id.as_str()]);
        assert_eq!(s.closed_events("fp", false, "2000", 10).unwrap().len(), 2);
        assert_eq!(s.closed_events("tp", true, "2000", 10).unwrap()[0].id, c.id);
        // The user confirming an AI closure makes it evidence.
        assert!(s.close(&b.id, "fp", "user", json!({})).unwrap());
        assert_eq!(s.closed_events("fp", true, "2000", 10).unwrap().len(), 2);
        let rv = s.recent_with_verdict(10).unwrap();
        assert!(rv.iter().any(|(e, _, v)| e.id == c.id && v.as_deref() == Some("tp")));
    }

    #[test]
    fn invalid_proposals_only_block_for_a_while() {
        let s = mem();
        s.add_proposal("filter", "evt-x", "fp1", &json!({}), "r", 0.5, "invalid")
            .unwrap();
        assert!(
            s.has_proposal("filter", "fp1").unwrap(),
            "recent policy rejection blocks retries"
        );
        s.conn
            .execute(
                "UPDATE proposals SET created_at = '2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        assert!(
            !s.has_proposal("filter", "fp1").unwrap(),
            "old rejection no longer blocks"
        );
        s.add_proposal("filter", "evt-x", "fp1", &json!({}), "r", 0.9, "rejected")
            .unwrap();
        s.conn
            .execute(
                "UPDATE proposals SET created_at = '2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        assert!(
            s.has_proposal("filter", "fp1").unwrap(),
            "a user refusal is final"
        );
    }

    #[test]
    fn retention_keeps_pinned() {
        let s = mem();
        for i in 0..5 {
            let e = event("a", "low", &format!("m{i}"));
            s.upsert(&e, None).unwrap();
            if i == 0 {
                s.set_pinned(&e.id, true, "user").unwrap();
            }
        }
        s.prune(30, 2).unwrap();
        let c = s.counts().unwrap();
        assert!(c["total"].as_i64().unwrap() <= 3);
        assert_eq!(c["pinned"], 1);
    }
}
