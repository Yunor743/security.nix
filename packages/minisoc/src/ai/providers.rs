//! Provider-independent completion call. Adding a provider = one more arm
//! in `request()` (URL, headers, body) and in `extract()` (reply text).
//!
//! Implemented: openai, anthropic, gemini, ollama, openai-compatible, custom.
//! The API key is read from `api_key_file` at each call and never logged.

use crate::config::AiCfg;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug)]
pub struct CallError {
    pub message: String,
    pub retryable: bool,
    pub retry_after: Option<u64>,
}

impl CallError {
    fn fatal(m: impl Into<String>) -> Self {
        Self {
            message: m.into(),
            retryable: false,
            retry_after: None,
        }
    }
}

pub fn default_endpoint(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("https://api.openai.com/v1"),
        "anthropic" => Some("https://api.anthropic.com/v1/messages"),
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta"),
        "ollama" => Some("http://127.0.0.1:11434"),
        "openrouter" => Some("https://openrouter.ai/api/v1"),
        _ => None,
    }
}

pub fn endpoint(cfg: &AiCfg) -> Option<String> {
    let p = cfg.provider.as_deref().unwrap_or("");
    cfg.endpoint
        .clone()
        .or_else(|| default_endpoint(p).map(String::from))
        .map(|e| e.trim_end_matches('/').to_string())
}

/// True when the endpoint is on this machine (loopback).
pub fn is_local(url: &str) -> bool {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(h) = authority.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Whether sending events with this configuration leaves the machine.
pub fn is_remote(cfg: &AiCfg) -> bool {
    endpoint(cfg).map(|e| !is_local(&e)).unwrap_or(true)
}

fn api_key(cfg: &AiCfg) -> Result<Option<String>, CallError> {
    let Some(path) = cfg.api_key_file.as_deref() else {
        return Ok(None);
    };
    let k = std::fs::read_to_string(crate::config::expand(path))
        .map_err(|e| CallError::fatal(format!("cannot read api_key_file: {}", e.kind())))?;
    let k = k.trim().to_string();
    if k.is_empty() {
        return Err(CallError::fatal("api_key_file is empty"));
    }
    Ok(Some(k))
}

fn request(
    cfg: &AiCfg,
    system: &str,
    user: &str,
    key: Option<&str>,
) -> Result<(String, Vec<(String, String)>, Value), CallError> {
    let provider = cfg.provider.as_deref().unwrap_or("");
    let model = cfg.model.clone().unwrap_or_default();
    let ep = endpoint(cfg)
        .ok_or_else(|| CallError::fatal(format!("provider '{provider}' needs an endpoint")))?;
    let max_tokens = cfg.limits.max_output_tokens;
    let bearer = |h: &mut Vec<(String, String)>| {
        if let Some(k) = key {
            h.push(("Authorization".into(), format!("Bearer {k}")));
        }
    };
    let mut headers = vec![];
    let (url, body) = match provider {
        "openai" | "openai-compatible" | "openrouter" => {
            bearer(&mut headers);
            if provider == "openrouter" {
                // Optional attribution headers (OpenRouter app ranking).
                headers.push(("X-Title".into(), "MiniSOC".into()));
                headers.push((
                    "HTTP-Referer".into(),
                    "https://github.com/Yunor743/security.nix".into(),
                ));
            }
            let url = if ep.ends_with("/chat/completions") {
                ep
            } else {
                format!("{ep}/chat/completions")
            };
            let mut body = json!({
                "model": model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "max_tokens": max_tokens, "temperature": 0.1,
            });
            if provider == "openai" {
                body["response_format"] = json!({"type": "json_object"});
            }
            (url, body)
        }
        "anthropic" => {
            if let Some(k) = key {
                headers.push(("x-api-key".into(), k.to_string()));
            }
            headers.push(("anthropic-version".into(), "2023-06-01".into()));
            (
                ep,
                json!({
                    "model": model, "max_tokens": max_tokens, "system": system,
                    "messages": [{"role": "user", "content": user}],
                }),
            )
        }
        "gemini" => {
            if let Some(k) = key {
                headers.push(("x-goog-api-key".into(), k.to_string()));
            }
            (
                format!("{ep}/models/{model}:generateContent"),
                json!({
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": max_tokens, "temperature": 0.1},
                }),
            )
        }
        "ollama" => {
            bearer(&mut headers);
            let url = if ep.ends_with("/api/chat") {
                ep
            } else {
                format!("{ep}/api/chat")
            };
            (
                url,
                json!({
                    "model": model, "stream": false, "format": "json",
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "options": {"temperature": 0.1, "num_predict": max_tokens},
                }),
            )
        }
        "custom" => {
            bearer(&mut headers);
            (
                ep,
                json!({"model": model, "system": system, "prompt": user, "max_tokens": max_tokens}),
            )
        }
        other => return Err(CallError::fatal(format!("unknown provider '{other}'"))),
    };
    Ok((url, headers, body))
}

fn extract(provider: &str, v: &Value) -> Option<String> {
    let s = match provider {
        "openai" | "openai-compatible" | "openrouter" => v
            .pointer("/choices/0/message/content")?
            .as_str()?
            .to_string(),
        "anthropic" => v
            .get("content")?
            .as_array()?
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        "gemini" => v
            .pointer("/candidates/0/content/parts")?
            .as_array()?
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        "ollama" => v.pointer("/message/content")?.as_str()?.to_string(),
        // custom: {"output": "..."} / {"response": "..."} / the object itself.
        _ => ["output", "response", "content", "text"]
            .iter()
            .find_map(|k| v.get(*k).and_then(Value::as_str))
            .map(String::from)
            .unwrap_or_else(|| v.to_string()),
    };
    Some(s)
}

/// One completion call (no retry; see `complete_with_retry`).
pub fn complete(cfg: &AiCfg, system: &str, user: &str) -> Result<String, CallError> {
    let provider = cfg.provider.as_deref().unwrap_or("");
    if !cfg.allow_remote && is_remote(cfg) {
        return Err(CallError::fatal(
            "refusing to send data to a remote endpoint: set ai.allowRemote = true",
        ));
    }
    let key = api_key(cfg)?;
    let (url, headers, body) = request(cfg, system, user, key.as_deref())?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(cfg.limits.timeout_secs.max(1)))
        .user_agent(concat!("minisoc/", env!("CARGO_PKG_VERSION")))
        .build();
    let mut req = agent.post(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    match req.send_json(body) {
        Ok(resp) => {
            let v: Value = resp.into_json().map_err(|e| CallError {
                message: format!("invalid JSON reply: {e}"),
                retryable: true,
                retry_after: None,
            })?;
            // Some gateways (OpenRouter) report upstream failures with
            // HTTP 200 and an `error` object.
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                let msg = err
                    .get("message")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .unwrap_or_else(|| err.to_string());
                return Err(CallError {
                    message: format!("provider error: {}", crate::util::truncate(&msg, 200)),
                    retryable: true,
                    retry_after: None,
                });
            }
            let stop = v
                .pointer("/choices/0/finish_reason")
                .or_else(|| v.get("stop_reason"))
                .or_else(|| v.pointer("/candidates/0/finishReason"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if matches!(stop, "length" | "max_tokens" | "MAX_TOKENS") {
                return Err(CallError::fatal(format!(
                    "reply truncated at {} tokens: raise ai.limits.maxOutputTokens",
                    cfg.limits.max_output_tokens
                )));
            }
            extract(provider, &v).ok_or_else(|| {
                CallError::fatal(format!(
                    "unexpected reply shape from provider: {}",
                    crate::util::truncate(&v.to_string(), 300)
                ))
            })
        }
        Err(ureq::Error::Status(code, resp)) => {
            let retry_after = resp
                .header("retry-after")
                .and_then(|s| s.trim().parse().ok());
            let body = resp.into_string().unwrap_or_default();
            Err(CallError {
                // Keep error text short; it never contains the key.
                message: format!("HTTP {code}: {}", crate::util::truncate(&body, 200)),
                retryable: code == 429 || code >= 500,
                retry_after,
            })
        }
        Err(ureq::Error::Transport(t)) => Err(CallError {
            message: format!("transport: {}", t.kind()),
            retryable: true,
            retry_after: None,
        }),
    }
}

pub fn complete_with_retry(
    cfg: &AiCfg,
    system: &str,
    user: &str,
    mut on_attempt: impl FnMut(bool),
) -> Result<String, CallError> {
    let mut attempt = 0;
    loop {
        let r = complete(cfg, system, user);
        on_attempt(r.is_err());
        match r {
            Ok(s) => return Ok(s),
            Err(e) if e.retryable && attempt < cfg.limits.max_retries => {
                let wait = e
                    .retry_after
                    .map(|s| s as f64)
                    .unwrap_or(cfg.limits.backoff_base_secs * 2f64.powi(attempt as i32))
                    .min(300.0);
                crate::warn!("AI request failed ({}), retry in {wait:.1}s", e.message);
                std::thread::sleep(Duration::from_secs_f64(wait));
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// Minimal HTTP server answering every request with `reply` (status,
    /// JSON body); `delay` simulates a hanging provider.
    pub fn mock_server(
        reply: impl Fn(&Value) -> (u16, Value) + Send + 'static,
        delay: Duration,
    ) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                std::thread::sleep(delay);
                let (code, v) = reply(&req);
                let b = v.to_string();
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len());
            }
        });
        format!("http://{addr}")
    }

    fn cfg(provider: &str, ep: &str) -> AiCfg {
        let mut c = AiCfg {
            enable: true,
            provider: Some(provider.into()),
            model: Some("test-model".into()),
            endpoint: Some(ep.into()),
            ..Default::default()
        };
        c.limits.timeout_secs = 2;
        c.limits.max_retries = 0;
        c
    }

    #[test]
    fn locality() {
        assert!(is_local("http://127.0.0.1:11434"));
        assert!(is_local("http://localhost/api"));
        assert!(is_local("http://[::1]:8080/x"));
        assert!(!is_local("https://api.openai.com/v1"));
        assert!(!is_local("http://127.0.0.1.evil.com/"));
        let mut c = AiCfg {
            provider: Some("openai".into()),
            ..Default::default()
        };
        assert!(is_remote(&c));
        c.provider = Some("ollama".into());
        assert!(!is_remote(&c));
        c.provider = Some("openrouter".into());
        assert!(is_remote(&c), "openrouter is remote by default");
    }

    #[test]
    fn remote_refused_without_opt_in() {
        let c = AiCfg {
            provider: Some("anthropic".into()),
            model: Some("m".into()),
            ..Default::default()
        };
        let e = complete(&c, "s", "u").unwrap_err();
        assert!(e.message.contains("allowRemote"));
    }

    #[test]
    fn ollama_and_openai_shapes() {
        let url = mock_server(
            |req| {
                assert_eq!(req["model"], "test-model");
                if req.get("stream").is_some() {
                    (200, json!({"message": {"content": "{\"ok\":1}"}}))
                } else {
                    (
                        200,
                        json!({"choices": [{"message": {"content": "{\"ok\":2}"}}]}),
                    )
                }
            },
            Duration::ZERO,
        );
        assert_eq!(
            complete(&cfg("ollama", &url), "s", "u").unwrap(),
            "{\"ok\":1}"
        );
        assert_eq!(
            complete(&cfg("openai-compatible", &url), "s", "u").unwrap(),
            "{\"ok\":2}"
        );
        // OpenRouter speaks the OpenAI chat format.
        let mut or = cfg("openrouter", &url);
        or.allow_remote = true;
        assert_eq!(complete(&or, "s", "u").unwrap(), "{\"ok\":2}");
    }

    #[test]
    fn timeout_is_enforced() {
        let url = mock_server(|_| (200, json!({})), Duration::from_secs(10));
        let t = std::time::Instant::now();
        let e = complete(&cfg("ollama", &url), "s", "u").unwrap_err();
        assert!(
            t.elapsed() < Duration::from_secs(6),
            "returned after {:?}",
            t.elapsed()
        );
        assert!(e.retryable);
    }

    #[test]
    fn retries_on_5xx_then_gives_up() {
        let url = mock_server(|_| (503, json!({"error": "busy"})), Duration::ZERO);
        let mut c = cfg("ollama", &url);
        c.limits.max_retries = 2;
        c.limits.backoff_base_secs = 0.01;
        let mut attempts = 0;
        assert!(complete_with_retry(&c, "s", "u", |_| attempts += 1).is_err());
        assert_eq!(attempts, 3);
    }
}
