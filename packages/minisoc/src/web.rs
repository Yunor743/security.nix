//! `minisoc web`: the browser UI, the same model as the Quickshell widget.
//! It reads the state the engine publishes ($XDG_RUNTIME_DIR/minisoc/
//! state.json) and runs every action through the `minisoc` CLI as the
//! current user; it holds no state of its own.
//!
//! Exposure: a loopback address only. Other local users can reach a loopback
//! port, so every API call carries a bearer token kept in the runtime dir
//! (0600, stable while the user is logged in); `minisoc web --url` prints the
//! address with the token in the fragment, which browsers never send. The
//! Host header must name the loopback address (DNS rebinding), a POST from
//! another origin is refused, and the page runs under a strict CSP.

use crate::config::{expand, Config};
use crate::util::{atomic_write, ensure_dir};
use crate::{info, warn};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE_CSS: &str = include_str!("../web/style.css");
const ICON_SVG: &str = include_str!("../web/icon.svg");

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 32;
const CLI_TIMEOUT: Duration = Duration::from_secs(60);

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; \
                   base-uri 'none'; form-action 'none'";

pub fn listen_addr(cfg: &Config) -> Result<SocketAddr, String> {
    let raw = std::env::var("MINISOC_WEB_LISTEN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| cfg.web.listen.clone());
    let addr: SocketAddr = raw
        .parse()
        .map_err(|e| format!("web.listen {raw:?}: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "web.listen {addr}: loopback addresses only (the UI acts on your alerts and rules)"
        ));
    }
    Ok(addr)
}

fn token_path(cfg: &Config) -> PathBuf {
    cfg.runtime_dir().join("web.token")
}
fn url_path(cfg: &Config) -> PathBuf {
    cfg.runtime_dir().join("web.url")
}

fn valid_token(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The existing token (a restart keeps open tabs working) or a new one.
fn load_or_create_token(cfg: &Config) -> Result<String, String> {
    let path = token_path(cfg);
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if valid_token(&t) {
            return Ok(t);
        }
    }
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    let t: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    ensure_dir(&cfg.runtime_dir(), 0o700).map_err(|e| e.to_string())?;
    atomic_write(&path, t.as_bytes(), 0o600).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(t)
}

fn page_url(addr: &SocketAddr, token: &str) -> String {
    format!("http://{addr}/#token={token}")
}

/// The address of the running UI, token included.
fn running_url(cfg: &Config) -> Result<String, String> {
    let path = url_path(cfg);
    let url = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "{}: {e} (is the minisoc-web user service running? systemctl --user status minisoc-web)",
            path.display()
        )
    })?;
    Ok(url.trim().to_string())
}

/// `minisoc web --open`: the UI in the default browser. Not the URL on the
/// command line: a process' arguments are readable by every local user
/// (/proc/<pid>/cmdline) and the browser may keep them for its lifetime. It
/// opens a 0600 page of the runtime dir that redirects to the URL instead.
pub fn open(cfg: &Config) -> Result<(), String> {
    let url = running_url(cfg)?;
    let page = cfg.runtime_dir().join("open.html");
    let target = serde_json::to_string(&url).map_err(|e| e.to_string())?;
    let html = format!(
        "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer>\
         <title>MiniSOC</title><script>location.replace({target});</script>\n"
    );
    atomic_write(&page, html.as_bytes(), 0o600).map_err(|e| format!("{}: {e}", page.display()))?;
    let status = Command::new("xdg-open")
        .arg(&page)
        .status()
        .map_err(|e| format!("xdg-open: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("xdg-open {}: {status}", page.display()))
    }
}

/// `minisoc web --url`: the address of the running UI, token included.
pub fn print_url(cfg: &Config) -> Result<(), String> {
    println!("{}", running_url(cfg)?);
    Ok(())
}

struct Ctx {
    token: String,
    hosts: Vec<String>,
    origins: Vec<String>,
    exe: PathBuf,
    config_arg: Option<String>,
    state_json: PathBuf,
    ui_json: PathBuf,
    user_rules: PathBuf,
    ai_rules: PathBuf,
}

pub fn serve(cfg: &Config, config_arg: Option<String>) -> Result<(), String> {
    let addr = listen_addr(cfg)?;
    let token = load_or_create_token(cfg)?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    let port = addr.port();
    let mut hosts = vec![format!("{addr}")];
    if addr.ip().is_ipv4() {
        hosts.push(format!("localhost:{port}"));
    }
    let origins = hosts.iter().map(|h| format!("http://{h}")).collect();
    let ui_json = std::env::var("MINISOC_UI_CONFIG")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| expand("$XDG_CONFIG_HOME/minisoc/ui.json"));
    let ctx = Arc::new(Ctx {
        token,
        hosts,
        origins,
        exe: std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?,
        config_arg,
        state_json: cfg.state_json(),
        ui_json,
        user_rules: cfg.user_filter_file(),
        ai_rules: cfg.ai_filter_file(),
    });
    let url = page_url(&addr, &ctx.token);
    atomic_write(&url_path(cfg), format!("{url}\n").as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", url_path(cfg).display()))?;
    info!("web UI on http://{addr}/ (minisoc web --url prints the address with its token)");

    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("web: accept: {e}");
                continue;
            }
        };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let ctx = ctx.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let _ = handle(&ctx, stream);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

// ------------------------------------------------------------------ HTTP

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Response {
    status: u16,
    ctype: &'static str,
    body: Vec<u8>,
    csp: bool,
}

impl Response {
    fn new(status: u16, ctype: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            ctype,
            body: body.into(),
            csp: false,
        }
    }
    fn json(status: u16, v: &Value) -> Self {
        Self::new(status, "application/json", v.to_string())
    }
    fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &json!({ "error": msg }))
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request, (u16, &'static str)> {
    let mut reader = BufReader::new(stream.take((MAX_HEADER + MAX_BODY) as u64));
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|_| (408, "timeout"))?;
        if n == 0 {
            return Err((400, "incomplete request"));
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEADER {
            return Err((431, "headers too large"));
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let req = parse_head(&head)?;
    let len: usize = match req.header("content-length") {
        Some(v) => v.trim().parse().map_err(|_| (400, "bad content-length"))?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err((413, "body too large"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| (400, "incomplete body"))?;
    Ok(Request { body, ..req })
}

fn parse_head(head: &[u8]) -> Result<Request, (u16, &'static str)> {
    let text = std::str::from_utf8(head).map_err(|_| (400, "not UTF-8"))?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let first = lines.next().ok_or((400, "empty request"))?;
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if !parts.next().unwrap_or("").starts_with("HTTP/1.") || !path.starts_with('/') {
        return Err((400, "bad request line"));
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once(':').ok_or((400, "bad header"))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(Request {
        method,
        path,
        headers,
        body: Vec::new(),
    })
}

fn write_response(stream: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n",
        r.status,
        r.ctype,
        r.body.len()
    );
    if r.csp {
        head.push_str(&format!("Content-Security-Policy: {CSP}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&r.body)?;
    stream.flush()
}

fn handle(ctx: &Ctx, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let resp = match read_request(&mut stream) {
        Ok(req) => route(ctx, &req),
        Err((status, msg)) => Response::error(status, msg),
    };
    write_response(&mut stream, &resp)
}

/// Constant-time comparison: the token must not leak through timing.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn route(ctx: &Ctx, req: &Request) -> Response {
    // DNS rebinding: a page of another site resolving its name to 127.0.0.1
    // sends its own Host.
    match req.header("host") {
        Some(h) if ctx.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) => {}
        _ => return Response::error(421, "unexpected Host"),
    }
    let path = req.path.split('?').next().unwrap_or("");
    if !path.starts_with("/api/") {
        if req.method != "GET" && req.method != "HEAD" {
            return Response::error(405, "method not allowed");
        }
        let mut r = match path {
            "/" | "/index.html" => Response::new(200, "text/html", INDEX_HTML),
            "/app.js" => Response::new(200, "text/javascript", APP_JS),
            "/style.css" => Response::new(200, "text/css", STYLE_CSS),
            "/icon.svg" => Response::new(200, "image/svg+xml", ICON_SVG),
            _ => return Response::error(404, "not found"),
        };
        r.csp = true;
        return r;
    }
    let auth = req
        .header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !same(auth.trim(), &ctx.token) {
        return Response::error(401, "missing or invalid token (minisoc web --url)");
    }
    if req.method == "POST" {
        if let Some(o) = req.header("origin") {
            if !ctx.origins.iter().any(|x| x.eq_ignore_ascii_case(o)) {
                return Response::error(403, "cross-origin request refused");
            }
        }
    }
    let seg: Vec<&str> = path["/api/".len()..].split('/').collect();
    match (req.method.as_str(), seg.as_slice()) {
        ("GET", ["state"]) => match std::fs::read(&ctx.state_json) {
            Ok(b) => Response::new(200, "application/json", b),
            Err(_) => Response::error(
                503,
                "no state yet: is the minisoc-engine user service running?",
            ),
        },
        ("GET", ["ui"]) => match std::fs::read_to_string(&ctx.ui_json) {
            Ok(s) if serde_json::from_str::<Value>(&s).is_ok() => {
                Response::new(200, "application/json", s)
            }
            _ => Response::json(200, &json!({})),
        },
        ("GET", ["show", id]) if valid_id(id) => cli_json(ctx, &["show", id, "--json"]),
        ("GET", ["explain", id]) if valid_id(id) => cli_json(ctx, &["explain", id, "--json"]),
        ("GET", ["draft", id]) if valid_id(id) => cli_text(ctx, &["filter", "draft", id]),
        ("GET", ["prompt", name]) if valid_id(name) => cli_text(ctx, &["prompts", "show", name]),
        ("GET", ["rules", which]) => {
            let p = match *which {
                "user" => &ctx.user_rules,
                "ai" => &ctx.ai_rules,
                _ => return Response::error(404, "not found"),
            };
            match std::fs::read_to_string(p) {
                Ok(s) => Response::new(200, "text/plain", s),
                Err(e) => Response::error(404, &format!("{}: {e}", p.display())),
            }
        }
        ("POST", ["action"]) => action(ctx, &req.body),
        (_, ["show" | "explain" | "draft" | "prompt", _]) => Response::error(400, "invalid id"),
        _ => Response::error(404, "not found"),
    }
}

/// Event ids, rule ids, prompt names: never an option (`--all`) nor a path.
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        && !s.contains("..")
}

/// The whitelisted user actions, as `minisoc` arguments.
fn action_args(v: &Value) -> Result<(Vec<String>, bool), String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let name = s("action");
    let id = s("id");
    let reason = s("reason");
    let need_id = || -> Result<String, String> {
        if valid_id(&id) {
            Ok(id.clone())
        } else {
            Err("invalid id".into())
        }
    };
    let with_reason = |mut a: Vec<String>| {
        if !reason.trim().is_empty() {
            a.push("--reason".into());
            a.push(reason.chars().take(500).collect());
        }
        a
    };
    // (arguments, run in the background: the request returns at once)
    Ok(match name.as_str() {
        "pin" | "unpin" | "reopen" | "analyze" => (vec![name.clone(), need_id()?], false),
        "tp" | "fp" => (with_reason(vec![name.clone(), need_id()?]), false),
        "fp-all" => (with_reason(vec!["fp".into(), "--all".into()]), false),
        "create-filter" => (vec!["filter".into(), "create".into(), need_id()?], false),
        "rollback" => (vec!["filter".into(), "rollback".into()], false),
        "accept" | "reject" => {
            let n = v
                .get("id")
                .and_then(|x| {
                    x.as_i64()
                        .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
                })
                .ok_or("invalid proposal id")?;
            (vec!["proposal".into(), name.clone(), n.to_string()], false)
        }
        "review" => (vec!["review".into()], true),
        "review-dry-run" => (
            vec!["review".into(), "--dry-run".into(), "--json".into()],
            false,
        ),
        _ => return Err(format!("unknown action {name:?}")),
    })
}

fn action(ctx: &Ctx, body: &[u8]) -> Response {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "JSON body expected"),
    };
    let (args, background) = match action_args(&v) {
        Ok(a) => a,
        Err(e) => return Response::error(400, &e),
    };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    if background {
        return match command(ctx, &refs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                // Reap it without blocking the request.
                std::thread::spawn(move || child.wait());
                Response::json(202, &json!({ "ok": true, "output": "started" }))
            }
            Err(e) => Response::error(502, &e.to_string()),
        };
    }
    match run(ctx, &refs) {
        Ok((true, out, err)) => {
            Response::json(200, &json!({ "ok": true, "output": out, "stderr": err }))
        }
        Ok((false, out, err)) => {
            Response::json(422, &json!({ "ok": false, "error": cli_error(&out, &err) }))
        }
        Err(e) => Response::error(502, &e),
    }
}

fn command(ctx: &Ctx, args: &[&str]) -> Command {
    let mut c = Command::new(&ctx.exe);
    if let Some(cfg) = &ctx.config_arg {
        c.arg("--config").arg(cfg);
    }
    c.args(args).stdin(Stdio::null());
    c
}

/// Run `minisoc <args>`: (success, stdout, stderr), bounded in time.
fn run(ctx: &Ctx, args: &[&str]) -> Result<(bool, String, String), String> {
    let mut child = command(ctx, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut out_pipe = child.stdout.take().unwrap();
    let mut err_pipe = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out_pipe.read_to_string(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_pipe.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() > CLI_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("minisoc {} timed out", args.join(" ")));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = out_t.join().unwrap_or_default();
    let err = err_t.join().unwrap_or_default();
    Ok((status.success(), out, err))
}

fn cli_json(ctx: &Ctx, args: &[&str]) -> Response {
    match run(ctx, args) {
        Ok((true, out, _)) => match serde_json::from_str::<Value>(&out) {
            Ok(v) => Response::json(200, &v),
            Err(_) => Response::error(502, "unexpected output"),
        },
        Ok((false, out, err)) => Response::error(404, &cli_error(&out, &err)),
        Err(e) => Response::error(502, &e),
    }
}

fn cli_text(ctx: &Ctx, args: &[&str]) -> Response {
    match run(ctx, args) {
        Ok((true, out, _)) => Response::new(200, "text/plain", out),
        Ok((false, out, err)) => Response::error(422, &cli_error(&out, &err)),
        Err(e) => Response::error(502, &e),
    }
}

/// The CLI's error message, without its `minisoc: ` prefix.
fn cli_error(out: &str, err: &str) -> String {
    let e = err.trim().trim_start_matches("minisoc: ").trim();
    if e.is_empty() {
        out.trim().to_string()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    fn ctx() -> Ctx {
        Ctx {
            token: "a".repeat(64),
            hosts: vec!["127.0.0.1:8743".into(), "localhost:8743".into()],
            origins: vec![
                "http://127.0.0.1:8743".into(),
                "http://localhost:8743".into(),
            ],
            exe: PathBuf::from("/nonexistent/minisoc"),
            config_arg: None,
            state_json: PathBuf::from("/nonexistent/state.json"),
            ui_json: PathBuf::from("/nonexistent/ui.json"),
            user_rules: PathBuf::from("/nonexistent/u.yaml"),
            ai_rules: PathBuf::from("/nonexistent/a.yaml"),
        }
    }

    #[test]
    fn parses_request_head() {
        let r = parse_head(
            b"GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:8743\r\nAuthorization: Bearer x\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/state");
        assert_eq!(r.header("HOST"), Some("127.0.0.1:8743"));
        assert!(parse_head(b"GET api HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_head(b"GET / SPDY\r\n\r\n").is_err());
    }

    #[test]
    fn loopback_only() {
        let mut cfg = Config::default();
        std::env::remove_var("MINISOC_WEB_LISTEN");
        assert!(listen_addr(&cfg).is_ok());
        cfg.web.listen = "[::1]:9000".into();
        assert!(listen_addr(&cfg).is_ok());
        cfg.web.listen = "0.0.0.0:8743".into();
        assert!(listen_addr(&cfg).is_err());
        cfg.web.listen = "192.168.1.2:8743".into();
        assert!(listen_addr(&cfg).is_err());
    }

    #[test]
    fn host_token_and_origin_are_checked() {
        let c = ctx();
        let tok = format!("Bearer {}", "a".repeat(64));
        // Static page: no token needed, CSP set.
        let r = route(&c, &req("GET", "/", &[("Host", "127.0.0.1:8743")]));
        assert_eq!(r.status, 200);
        assert!(r.csp);
        // DNS rebinding: foreign Host.
        let r = route(&c, &req("GET", "/", &[("Host", "evil.example:8743")]));
        assert_eq!(r.status, 421);
        let r = route(&c, &req("GET", "/api/state", &[("Host", "127.0.0.1:8743")]));
        assert_eq!(r.status, 401);
        let r = route(
            &c,
            &req(
                "GET",
                "/api/state",
                &[("Host", "localhost:8743"), ("Authorization", "Bearer bad")],
            ),
        );
        assert_eq!(r.status, 401);
        let r = route(
            &c,
            &req(
                "GET",
                "/api/state",
                &[("Host", "localhost:8743"), ("Authorization", &tok)],
            ),
        );
        assert_eq!(r.status, 503); // authorized; no state file here
        let r = route(
            &c,
            &req(
                "GET",
                "/api/ui",
                &[("Host", "localhost:8743"), ("Authorization", &tok)],
            ),
        );
        assert_eq!((r.status, r.body.as_slice()), (200, b"{}".as_slice()));
        let r = route(
            &c,
            &req(
                "POST",
                "/api/action",
                &[
                    ("Host", "localhost:8743"),
                    ("Authorization", &tok),
                    ("Origin", "http://evil.example"),
                ],
            ),
        );
        assert_eq!(r.status, 403);
        let r = route(
            &c,
            &req(
                "GET",
                "/api/show/--all",
                &[("Host", "localhost:8743"), ("Authorization", &tok)],
            ),
        );
        assert_eq!(r.status, 400);
    }

    #[test]
    fn actions_are_whitelisted() {
        let a = |v: Value| action_args(&v).map(|(a, bg)| (a.join(" "), bg));
        assert_eq!(
            a(json!({"action": "fp", "id": "evt-1"})).unwrap().0,
            "fp evt-1"
        );
        assert_eq!(
            a(json!({"action": "tp", "id": "evt-1", "reason": "seen"}))
                .unwrap()
                .0,
            "tp evt-1 --reason seen"
        );
        assert_eq!(a(json!({"action": "fp-all"})).unwrap().0, "fp --all");
        assert_eq!(
            a(json!({"action": "accept", "id": 7})).unwrap().0,
            "proposal accept 7"
        );
        assert_eq!(
            a(json!({"action": "accept", "id": "7"})).unwrap().0,
            "proposal accept 7"
        );
        assert!(a(json!({"action": "review"})).unwrap().1);
        assert!(a(json!({"action": "fp", "id": "--all"})).is_err());
        assert!(a(json!({"action": "pin", "id": "../x"})).is_err());
        assert!(a(json!({"action": "accept", "id": "1; rm"})).is_err());
        assert!(a(json!({"action": "ingest"})).is_err());
        assert!(a(json!({"action": "prompts"})).is_err());
    }

    #[test]
    fn token_comparison() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        assert!(valid_token(&"0f".repeat(32)));
        assert!(!valid_token("short"));
    }
}
