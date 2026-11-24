//! Optional LLM layer (SOC N1 analysis, auto-discard, auto-filter).
//!
//! Everything the model returns is treated as untrusted data: responses are
//! parsed into a fixed schema (unknown keys dropped, types and ranges
//! checked), and every automatic decision goes through code-enforced
//! policies (`policy.rs`) the model cannot alter.

pub mod analyzer;
pub mod policy;
pub mod prompts;
pub mod providers;
pub mod redact;
pub mod review;

use crate::util::{is_severity, truncate};
use serde_json::{json, Map, Value};

pub const CLASSIFICATIONS: [&str; 8] = [
    "benign",
    "false_positive",
    "suspicious",
    "malicious",
    "reconnaissance",
    "policy_violation",
    "misconfiguration",
    "unknown",
];
pub const ACTIONS: [&str; 4] = ["investigate", "monitor", "escalate", "discard"];
pub const LIKELIHOOD: [&str; 4] = ["low", "medium", "high", "unknown"];

/// JSON shape requested from the model (inserted in the prompt).
pub const ANALYSIS_SCHEMA: &str = r#"{
  "summary": "one or two sentences, human readable",
  "classification": "benign | false_positive | suspicious | malicious | reconnaissance | policy_violation | misconfiguration | unknown",
  "severity_assessment": "critical | high | medium | low | info | unknown",
  "confidence": 0.0,
  "benign_confidence": 0.0,
  "context": "what happened, from the alert data only",
  "facts": ["confirmed facts present in the alert data"],
  "hypotheses": ["clearly labelled hypotheses"],
  "missing_information": ["what would be needed to conclude"],
  "indicators": ["suspicious indicators found in the data"],
  "impact": "potential impact",
  "recommended_investigations": ["next investigation steps (no remediation)"],
  "false_positive_likelihood": "low | medium | high | unknown",
  "suggested_action": "investigate | monitor | escalate | discard"
}
"confidence" is your confidence in this analysis; "benign_confidence" is your
confidence that the event is benign. They are different: a low-quality
detection does not make an event benign."#;

/// Extract the first JSON object from a model reply (tolerates code fences
/// and surrounding prose).
pub fn extract_json(text: &str) -> Option<Value> {
    if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(text.trim()) {
        return Some(v);
    }
    let start = text.find('{')?;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (i, c) in text[start..].char_indices() {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return serde_json::from_str(&text[start..start + i + 1])
                        .ok()
                        .filter(Value::is_object);
                }
            }
            _ => {}
        }
    }
    None
}

fn str_field(m: &Map<String, Value>, k: &str, limit: usize) -> Option<String> {
    m.get(k)
        .and_then(Value::as_str)
        .map(|s| truncate(s.trim(), limit))
        .filter(|s| !s.is_empty())
}

fn enum_field(m: &Map<String, Value>, k: &str, allowed: &[&str], default: &str) -> String {
    m.get(k)
        .and_then(Value::as_str)
        .map(|s| s.trim().to_lowercase())
        .filter(|s| allowed.contains(&s.as_str()))
        .unwrap_or_else(|| default.into())
}

fn list_field(m: &Map<String, Value>, k: &str) -> Vec<String> {
    match m.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .map(|s| truncate(s.trim(), 300))
            .filter(|s| !s.is_empty())
            .take(12)
            .collect(),
        Some(Value::String(s)) if !s.trim().is_empty() => vec![truncate(s.trim(), 300)],
        _ => vec![],
    }
}

fn prob(m: &Map<String, Value>, k: &str) -> Option<f64> {
    let v = m.get(k)?;
    let f = v
        .as_f64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))?;
    (0.0..=1.0).contains(&f).then_some(f)
}

/// Validate a model reply into the fixed analysis schema. A reply without a
/// summary or confidence is rejected; doubtful enum values fall back to the
/// most conservative choice ("unknown" / "investigate").
pub fn validate_analysis(reply: &str) -> Result<Value, String> {
    let v = extract_json(reply).ok_or("no JSON object in the model reply")?;
    let m = v.as_object().unwrap();
    let summary = str_field(m, "summary", 500).ok_or("missing `summary`")?;
    let confidence =
        prob(m, "confidence").ok_or("missing or out-of-range `confidence` (expected 0..1)")?;
    let sev = enum_field(
        m,
        "severity_assessment",
        &crate::util::SEVERITIES,
        "unknown",
    );
    Ok(json!({
        "summary": summary,
        "classification": enum_field(m, "classification", &CLASSIFICATIONS, "unknown"),
        "severity_assessment": if is_severity(&sev) { sev } else { "unknown".into() },
        "confidence": confidence,
        "benign_confidence": prob(m, "benign_confidence").unwrap_or(0.0),
        "context": str_field(m, "context", 2000),
        "facts": list_field(m, "facts"),
        "hypotheses": list_field(m, "hypotheses"),
        "missing_information": list_field(m, "missing_information"),
        "indicators": list_field(m, "indicators"),
        "impact": str_field(m, "impact", 1000),
        "recommended_investigations": list_field(m, "recommended_investigations"),
        "false_positive_likelihood": enum_field(m, "false_positive_likelihood", &LIKELIHOOD, "unknown"),
        "suggested_action": enum_field(m, "suggested_action", &ACTIONS, "investigate"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_sanitizes_replies() {
        let reply = "Sure! ```json\n{\"summary\": \"Port scan\", \"confidence\": 0.87, \"classification\": \"reconnaissance\",
            \"suggested_action\": \"rm -rf /\", \"severity_assessment\": \"MEDIUM\", \"indicators\": [\"many ports\", 3],
            \"extra\": \"ignored\", \"benign_confidence\": 7}\n```";
        let a = validate_analysis(reply).unwrap();
        assert_eq!(a["summary"], "Port scan");
        assert_eq!(a["classification"], "reconnaissance");
        assert_eq!(a["severity_assessment"], "medium");
        assert_eq!(
            a["suggested_action"], "investigate",
            "unknown action falls back to investigate"
        );
        assert_eq!(a["benign_confidence"], 0.0, "out of range => 0");
        assert_eq!(a["indicators"], json!(["many ports"]));
        assert!(a.get("extra").is_none());
    }

    #[test]
    fn rejects_unusable_replies() {
        assert!(validate_analysis("I cannot help with that").is_err());
        assert!(
            validate_analysis("{\"summary\": \"x\"}").is_err(),
            "confidence required"
        );
        assert!(validate_analysis("{\"summary\": \"x\", \"confidence\": 1.5}").is_err());
        assert!(
            validate_analysis("{\"confidence\": 0.5}").is_err(),
            "summary required"
        );
    }
}
