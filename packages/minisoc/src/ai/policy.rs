//! Code-enforced guardrails for automatic AI decisions. The model only
//! provides data (a validated analysis or a candidate rule); whether anything
//! happens is decided here, from the Nix configuration, which the model can
//! neither read nor modify.

use crate::config::{AutoDiscardCfg, AutoFilterCfg};
use crate::filters::{EventView, Rule};
use crate::normalize::Event;
use crate::util::{now_iso, sev_rank, SEVERITIES};
use serde_json::{json, Map, Value};

#[derive(Debug, PartialEq)]
pub enum Decision {
    Keep(String),
    Suggest(Vec<String>),
    Discard(Vec<String>),
}

/// Severity levels the AI may ever act on. `critical` never; `high` only if
/// explicitly configured; `unknown` never (uncertain => stays visible).
pub fn max_auto_rank(configured: &str) -> usize {
    sev_rank(configured).min(sev_rank("high"))
}

pub fn auto_discard(
    event_sev: &str,
    pinned: bool,
    analysis: &Value,
    stats: &Value,
    cfg: &AutoDiscardCfg,
) -> Decision {
    let keep = |why: &str| Decision::Keep(why.to_string());
    if cfg.mode != "suggest" && cfg.mode != "automatic" {
        return keep("auto-discard disabled");
    }
    if pinned {
        return keep("pinned alerts are protected");
    }
    if event_sev == "critical" {
        return keep("critical alerts are never discarded automatically");
    }
    if event_sev == "unknown" {
        return keep("unknown severity: stays visible");
    }
    if sev_rank(event_sev) > max_auto_rank(&cfg.maximum_severity) {
        return keep("severity above the configured maximum");
    }
    if analysis["suggested_action"] != "discard" {
        return keep("the analysis does not suggest discarding");
    }
    if matches!(
        analysis["classification"].as_str(),
        Some("malicious" | "suspicious" | "unknown" | "reconnaissance")
    ) {
        return keep("classification is not benign");
    }
    if analysis["false_positive_likelihood"] != "high" {
        return keep("false-positive likelihood is not high");
    }
    let benign = analysis["benign_confidence"].as_f64().unwrap_or(0.0);
    if benign < cfg.minimum_confidence {
        return keep("benign confidence below threshold");
    }
    if cfg.require_repeated_benign_pattern {
        let occ = stats["occurrences"].as_i64().unwrap_or(0);
        let benign_n = stats["benign_analyses"].as_i64().unwrap_or(0);
        if occ < cfg.minimum_occurrences || benign_n < 2 {
            return keep("no repeated benign pattern yet");
        }
    }
    let reasons = vec![
        format!(
            "severity {event_sev} <= {}",
            SEVERITIES[max_auto_rank(&cfg.maximum_severity)]
        ),
        format!(
            "benign_confidence {benign:.2} >= {:.2}",
            cfg.minimum_confidence
        ),
        "false_positive_likelihood high".into(),
        format!(
            "pattern seen {} times, {} benign analyses",
            stats["occurrences"], stats["benign_analyses"]
        ),
    ];
    if cfg.mode == "automatic" {
        Decision::Discard(reasons)
    } else {
        Decision::Suggest(reasons)
    }
}

/// Severities an AI-generated rule is allowed to hide.
pub fn allowed_severities(cfg: &AutoFilterCfg) -> Vec<&'static str> {
    SEVERITIES
        .iter()
        .copied()
        .filter(|s| *s != "unknown" && *s != "critical" && *s != "high")
        .filter(|s| !cfg.protect_severity.iter().any(|p| p == s))
        .collect()
}

fn literal_chars(pattern: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in pattern.chars() {
        if esc {
            esc = false;
            if c.is_ascii_alphanumeric() {
                continue; // \d, \w, ...
            }
            n += 1;
        } else if c == '\\' {
            esc = true;
        } else if c.is_alphanumeric() || " /_-:.".contains(c) {
            n += 1;
        }
    }
    n
}

fn check_matcher(m: &Value, w: &str) -> Result<(), String> {
    match m {
        Value::String(s) if s.chars().count() >= 3 => Ok(()),
        Value::Number(_) | Value::Bool(_) => Ok(()),
        Value::Array(a) if !a.is_empty() && a.len() <= 10 => {
            a.iter().try_for_each(|x| check_matcher(x, w))
        }
        Value::Object(o) if !o.is_empty() => {
            for (op, arg) in o {
                match op.as_str() {
                    "equals" => check_matcher(arg, w)?,
                    "in" => match arg {
                        Value::Array(a) if !a.is_empty() && a.len() <= 10 => {
                            a.iter().try_for_each(|x| check_matcher(x, w))?
                        }
                        _ => return Err(format!("{w}.in: 1..10 values")),
                    },
                    "contains" | "prefix" | "suffix" => {
                        if arg.as_str().is_none_or(|s| s.chars().count() < 6) {
                            return Err(format!("{w}.{op}: at least 6 characters"));
                        }
                    }
                    "regex" => {
                        let p = arg.as_str().ok_or(format!("{w}.regex: string expected"))?;
                        if literal_chars(p) < 8 {
                            return Err(format!(
                                "{w}.regex: too generic (needs >= 8 literal characters)"
                            ));
                        }
                        if regex::Regex::new(p).map(|r| r.is_match("")).unwrap_or(true) {
                            return Err(format!("{w}.regex: invalid or matches the empty string"));
                        }
                    }
                    other => {
                        return Err(format!("{w}: operator '{other}' not allowed for AI rules"))
                    }
                }
            }
            Ok(())
        }
        _ => Err(format!("{w}: value too short or unsupported")),
    }
}

/// Validate a rule proposed by the model and turn it into a safe rule:
/// - only `source` + `event_type` (exact) + `message`/`fields` conditions;
/// - `severity` is injected by MiniSOC so critical/high (and every protected
///   level) can never be hidden;
/// - it must match the triggering event and nothing outside its similarity
///   group, and no pinned event, among recent events.
pub fn build_ai_rule(
    proposal: &Value,
    trigger: &Event,
    recent: &[(Event, bool)],
    cfg: &AutoFilterCfg,
    provider: &str,
    model: &str,
) -> Result<Value, String> {
    let m = proposal
        .get("match")
        .and_then(Value::as_object)
        .ok_or("proposal has no `match` mapping")?;
    let mut clean = Map::new();
    for (k, v) in m {
        match k.as_str() {
            "source" | "event_type" => {}
            "message" => check_matcher(v, "message")?,
            "fields" => {
                let f = v
                    .as_object()
                    .filter(|f| !f.is_empty() && f.len() <= 8)
                    .ok_or("fields: 1..8 entries")?;
                for (p, mv) in f {
                    check_matcher(mv, &format!("fields.{p}"))?;
                }
            }
            other => return Err(format!("key '{other}' is not allowed in AI rules")),
        }
        clean.insert(k.clone(), v.clone());
    }
    if m.get("source").and_then(Value::as_str) != Some(trigger.source.as_str()) {
        return Err("`source` must be exactly the event source".into());
    }
    if m.get("event_type").and_then(Value::as_str) != Some(trigger.event_type.as_str()) {
        return Err("`event_type` must be exactly the event type".into());
    }
    if !m.contains_key("message") && !m.contains_key("fields") {
        return Err("a `message` or `fields` condition is required (no source-wide rules)".into());
    }
    let allowed = allowed_severities(cfg);
    if allowed.is_empty() || !allowed.contains(&trigger.severity.as_str()) {
        return Err(format!("severity '{}' is protected", trigger.severity));
    }
    clean.insert("severity".into(), json!({"in": allowed}));

    let confidence = proposal
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let reason = crate::util::truncate(
        proposal.get("reason").and_then(Value::as_str).unwrap_or(""),
        500,
    );
    let created = now_iso();
    let rule = json!({
        "id": format!("ai-{}-{}", &trigger.fingerprint[..8.min(trigger.fingerprint.len())], created.replace([':', '-', '.'], "")),
        "enabled": true,
        "description": crate::util::truncate(proposal.get("description").and_then(Value::as_str).unwrap_or("AI-generated exclusion"), 200),
        "match": Value::Object(clean),
        "action": "exclude",
        "metadata": {
            "generated_by": "minisoc-ai", "provider": provider, "model": model,
            "confidence": confidence, "created_at": created, "reason": reason,
            "fingerprint": trigger.fingerprint, "source_event": trigger.id,
        },
    });
    let compiled = Rule::new(&rule, "ai-proposal", 0)?;
    let view = |e: &Event| -> bool {
        compiled.matches(&EventView {
            source: &e.source,
            severity: &e.severity,
            event_type: &e.event_type,
            message: &e.message,
            fields: &e.fields,
        })
    };
    if !view(trigger) {
        return Err("the rule does not match the alert it was generated for".into());
    }
    for (e, pinned) in recent {
        if !view(e) {
            continue;
        }
        if *pinned {
            return Err(format!("the rule would hide pinned alert {}", e.id));
        }
        if e.fingerprint != trigger.fingerprint {
            return Err(format!(
                "too broad: it would also hide a different alert pattern ({})",
                e.id
            ));
        }
        if sev_rank(&e.severity) >= sev_rank("high") {
            return Err("the rule would hide a high/critical alert".into());
        }
    }
    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(action: &str, fp: &str, benign: f64) -> Value {
        json!({"suggested_action": action, "classification": "benign", "false_positive_likelihood": fp, "benign_confidence": benign})
    }

    fn auto(mode: &str) -> AutoDiscardCfg {
        AutoDiscardCfg {
            mode: mode.into(),
            ..Default::default()
        }
    }

    fn repeated() -> Value {
        json!({"occurrences": 10, "benign_analyses": 3})
    }

    #[test]
    fn critical_and_high_never_auto_discarded() {
        let mut cfg = auto("automatic");
        cfg.maximum_severity = "critical".into(); // even if misconfigured
        let an = a("discard", "high", 1.0);
        assert!(matches!(
            auto_discard("critical", false, &an, &repeated(), &cfg),
            Decision::Keep(_)
        ));
        cfg.maximum_severity = "low".into();
        assert!(matches!(
            auto_discard("high", false, &an, &repeated(), &cfg),
            Decision::Keep(_)
        ));
        assert!(matches!(
            auto_discard("low", false, &an, &repeated(), &cfg),
            Decision::Discard(_)
        ));
    }

    #[test]
    fn pinned_uncertain_and_low_confidence_stay() {
        let cfg = auto("automatic");
        assert!(matches!(
            auto_discard("low", true, &a("discard", "high", 1.0), &repeated(), &cfg),
            Decision::Keep(_)
        ));
        assert!(matches!(
            auto_discard(
                "unknown",
                false,
                &a("discard", "high", 1.0),
                &repeated(),
                &cfg
            ),
            Decision::Keep(_)
        ));
        assert!(matches!(
            auto_discard("low", false, &a("discard", "high", 0.9), &repeated(), &cfg),
            Decision::Keep(_)
        ));
        assert!(matches!(
            auto_discard(
                "low",
                false,
                &a("discard", "medium", 1.0),
                &repeated(),
                &cfg
            ),
            Decision::Keep(_)
        ));
        assert!(matches!(
            auto_discard(
                "low",
                false,
                &a("investigate", "high", 1.0),
                &repeated(),
                &cfg
            ),
            Decision::Keep(_)
        ));
        // A confident *detection* is not a confident *benign* verdict.
        let detection_only = json!({"suggested_action": "discard", "classification": "benign",
            "false_positive_likelihood": "high", "confidence": 0.99, "benign_confidence": 0.2});
        assert!(matches!(
            auto_discard("low", false, &detection_only, &repeated(), &cfg),
            Decision::Keep(_)
        ));
        // Not repeated yet.
        assert!(matches!(
            auto_discard(
                "low",
                false,
                &a("discard", "high", 1.0),
                &json!({"occurrences": 1, "benign_analyses": 1}),
                &cfg
            ),
            Decision::Keep(_)
        ));
    }

    #[test]
    fn suggest_mode_only_suggests() {
        assert!(matches!(
            auto_discard(
                "info",
                false,
                &a("discard", "high", 1.0),
                &repeated(),
                &auto("suggest")
            ),
            Decision::Suggest(_)
        ));
        assert!(matches!(
            auto_discard(
                "info",
                false,
                &a("discard", "high", 1.0),
                &repeated(),
                &auto("off")
            ),
            Decision::Keep(_)
        ));
    }

    fn ev(source: &str, sev: &str, et: &str, msg: &str, exe: &str) -> Event {
        let rec = json!({"minisoc": {"source": source}, "raw": format!("{source}{sev}{et}{msg}{exe}"),
            "parsed": {"severity": sev, "event_type": et, "message": msg, "process": {"executable": exe}}});
        crate::normalize::normalize(&rec, &Default::default())
    }

    #[test]
    fn ai_rules_are_specific_and_protect_severities() {
        let cfg = AutoFilterCfg::default();
        let t = ev(
            "edr",
            "low",
            "sigma_match",
            "Whoami Execution",
            "/run/current-system/sw/bin/whoami",
        );
        let other = ev(
            "edr",
            "low",
            "sigma_match",
            "Netcat listener",
            "/usr/bin/nc",
        );
        let good = json!({"match": {"source": "edr", "event_type": "sigma_match",
            "message": {"equals": "Whoami Execution"}, "fields": {"process.executable": {"suffix": "/bin/whoami"}}},
            "confidence": 0.99, "reason": "admin habit"});
        let rule = build_ai_rule(
            &good,
            &t,
            &[(t.clone(), false), (other.clone(), false)],
            &cfg,
            "ollama",
            "m",
        )
        .unwrap();
        assert_eq!(
            rule["match"]["severity"],
            json!({"in": ["info", "low", "medium"]})
        );
        assert_eq!(rule["metadata"]["generated_by"], "minisoc-ai");

        let source_wide = json!({"match": {"source": "edr", "event_type": "sigma_match"}});
        assert!(build_ai_rule(&source_wide, &t, &[], &cfg, "p", "m").is_err());
        let severity_wide = json!({"match": {"source": "edr", "event_type": "sigma_match", "message": {"contains": "Whoami"}, "severity": "low"}});
        assert!(build_ai_rule(&severity_wide, &t, &[], &cfg, "p", "m").is_err());
        let generic_regex = json!({"match": {"source": "edr", "event_type": "sigma_match", "message": {"regex": ".*"}}});
        assert!(build_ai_rule(&generic_regex, &t, &[], &cfg, "p", "m").is_err());
        let combinator = json!({"match": {"source": "edr", "event_type": "sigma_match", "any": [{"message": "x"}]}});
        assert!(build_ai_rule(&combinator, &t, &[], &cfg, "p", "m").is_err());
        // Too broad: also matches another pattern.
        let broad = json!({"match": {"source": "edr", "event_type": "sigma_match", "fields": {"process.executable": {"prefix": "/run/current-system"}}}});
        let nc2 = ev(
            "edr",
            "low",
            "sigma_match",
            "Netcat listener",
            "/run/current-system/sw/bin/nc",
        );
        assert!(build_ai_rule(
            &broad,
            &t,
            &[(t.clone(), false), (nc2, false)],
            &cfg,
            "p",
            "m"
        )
        .unwrap_err()
        .contains("too broad"));
        // Would hide a pinned alert of the same pattern.
        assert!(build_ai_rule(&good, &t, &[(t.clone(), true)], &cfg, "p", "m").is_err());
        // High alerts: refused outright.
        let h = ev(
            "edr",
            "high",
            "sigma_match",
            "Whoami Execution",
            "/run/current-system/sw/bin/whoami",
        );
        assert!(build_ai_rule(&good, &h, &[], &cfg, "p", "m").is_err());
    }
}
