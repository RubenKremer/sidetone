//! Local web UI + HTTP API. Same frontend as the WASM build, but analysis,
//! AI requests and test calls run natively on this machine.

use crate::aihttp;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use sidetone_core::ai::AiConfig;
use sidetone_core::export::{export_pcapng, ExportOptions};
use sidetone_core::ladder::{render_svg, LadderOptions};
use sidetone_core::redact::RedactOptions;
use sidetone_core::{analyze_bytes, Report};
use sidetone_ua::{AudioSource, CallOptions, Profile, Tap, Ua};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX: &str = include_str!("../../../web/index.html");
const APP_JS: &str = include_str!("../../../web/app.js");
const STYLE: &str = include_str!("../../../web/style.css");
const WEBPHONE_JS: &str = include_str!("../../../web/webphone.js");

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

fn query(url: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some((_, q)) = url.split_once('?') {
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            m.insert(k.to_string(), urldecode(v));
        }
    }
    m
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

fn call_param(r: &Report, q: &HashMap<String, String>) -> Option<usize> {
    q.get("call")
        .filter(|c| !c.is_empty())
        .and_then(|c| r.find_call(c))
}

fn flag(q: &HashMap<String, String>, k: &str) -> bool {
    matches!(q.get(k).map(|s| s.as_str()), Some("1") | Some("true"))
}

type Resp = Response<std::io::Cursor<Vec<u8>>>;

fn ok_bytes(data: Vec<u8>, ctype: &str) -> Resp {
    Response::from_data(data).with_header(header("Content-Type", ctype))
}

fn err(code: u16, msg: impl std::fmt::Display) -> Resp {
    Response::from_data(json!({"error": msg.to_string()}).to_string().into_bytes())
        .with_status_code(code)
        .with_header(header("Content-Type", "application/json"))
}

fn ua_from(v: &Value) -> Result<Ua> {
    let mut p: Profile = match v.get("profile") {
        Some(p) if !p.is_null() => {
            serde_json::from_value(p.clone()).map_err(|e| anyhow!("profile: {e}"))?
        }
        _ => Profile::default(),
    };
    if let Some(d) = v
        .get("domain")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.domain = d.into();
    }
    if let Some(u) = v
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.user = u.into();
    }
    if let Some(pw) = v
        .get("password")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.password = Some(pw.into());
    }
    Ua::new(p, Tap::new()).map_err(|e| anyhow!("{e}"))
}

/// Native "save as" hook supplied by the desktop app: (suggested name, bytes) -> saved path.
pub type SaveHook = std::sync::Arc<dyn Fn(&str, &[u8]) -> Result<Option<PathBuf>> + Send + Sync>;

fn handle(
    req: &mut Request,
    web: &Option<PathBuf>,
    token: &Option<String>,
    save: &Option<SaveHook>,
) -> Resp {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let q = query(&url);
    if let (Some(t), true) = (token, path.starts_with("/api/")) {
        let hdr = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("x-sidetone-token"))
            .map(|h| h.value.as_str().to_string());
        if hdr.as_deref() != Some(t.as_str()) && q.get("token") != Some(t) {
            return err(
                403,
                "missing or wrong token (open the URL printed at startup)",
            );
        }
    }
    let method = req.method().clone();
    let mut body = Vec::new();
    if method == Method::Post {
        if let Err(e) = req.as_reader().read_to_end(&mut body) {
            return err(400, e);
        }
    }
    let analyze = |b: &[u8]| analyze_bytes(b).map_err(|e| e.to_string());
    match (method, path.as_str()) {
        (Method::Get, "/api/info") => {
            let mut features = vec!["analyze", "export", "ai-proxy", "ua"];
            if save.is_some() {
                features.push("native-save");
            }
            ok_bytes(json!({"mode": "server", "version": env!("CARGO_PKG_VERSION"), "features": features}).to_string().into_bytes(), "application/json")
        }
        (Method::Post, "/api/save") => match save {
            Some(f) => match f(
                q.get("name").map(|s| s.as_str()).unwrap_or("sidetone.bin"),
                &body,
            ) {
                Ok(Some(p)) => ok_bytes(
                    json!({"saved": p.display().to_string()})
                        .to_string()
                        .into_bytes(),
                    "application/json",
                ),
                Ok(None) => ok_bytes(
                    json!({"saved": null}).to_string().into_bytes(),
                    "application/json",
                ),
                Err(e) => err(500, e),
            },
            None => err(404, "native save not available"),
        },
        (Method::Get, "/api/sample") => match sidetone_core::synth::generate(
            q.get("name").map(|s| s.as_str()).unwrap_or("demo"),
        ) {
            Some(b) => ok_bytes(b, "application/octet-stream"),
            None => err(404, "unknown sample"),
        },
        (Method::Post, "/api/sip-log-capture") => {
            let log: sidetone_core::synth::SipLog = match serde_json::from_slice(&body) {
                Ok(l) => l,
                Err(e) => return err(400, e),
            };
            match sidetone_core::synth::capture_from_log(&log) {
                Ok(b) => ok_bytes(b, "application/octet-stream"),
                Err(e) => err(400, e),
            }
        }
        (Method::Post, "/api/analyze") => match analyze(&body) {
            Ok(r) => ok_bytes(r.to_json().into_bytes(), "application/json"),
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/ladder") => match analyze(&body) {
            Ok(r) => {
                let c = call_param(&r, &q);
                ok_bytes(
                    render_svg(
                        &r,
                        &LadderOptions {
                            call: c,
                            ..Default::default()
                        },
                    )
                    .into_bytes(),
                    "image/svg+xml",
                )
            }
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/export") => match analyze(&body) {
            Ok(r) => {
                let opts = ExportOptions {
                    annotate: !flag(&q, "no_annotate"),
                    redact: if flag(&q, "redact") {
                        Some(RedactOptions::default())
                    } else {
                        None
                    },
                    call: call_param(&r, &q),
                    sip_only: flag(&q, "sip_only"),
                };
                ok_bytes(export_pcapng(&r, &opts), "application/octet-stream")
            }
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/prompt") => {
            match analyze(&body) {
                Ok(r) => {
                    let red = if flag(&q, "redact") {
                        Some(RedactOptions::default())
                    } else {
                        None
                    };
                    let lang = q.get("lang").cloned().unwrap_or_else(|| "English".into());
                    let prompt = sidetone_core::ai::build_prompt(
                        &r,
                        call_param(&r, &q),
                        red.as_ref(),
                        q.get("question").map(|s| s.as_str()),
                    );
                    ok_bytes(json!({"system": sidetone_core::ai::system_prompt(&lang), "prompt": prompt}).to_string().into_bytes(), "application/json")
                }
                Err(e) => err(422, e),
            }
        }
        (Method::Post, "/api/ai") => {
            let v: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return err(400, e),
            };
            let cfg: AiConfig =
                match serde_json::from_value(v.get("config").cloned().unwrap_or(Value::Null)) {
                    Ok(c) => c,
                    Err(e) => return err(400, format!("config: {e}")),
                };
            let prompt = v.get("prompt").and_then(|p| p.as_str()).unwrap_or("");
            match aihttp::ask(&cfg, prompt) {
                Ok(text) => ok_bytes(
                    json!({"text": text}).to_string().into_bytes(),
                    "application/json",
                ),
                Err(e) => err(502, e),
            }
        }
        (Method::Post, "/api/options") | (Method::Post, "/api/call") => {
            let v: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return err(400, e),
            };
            let mut ua = match ua_from(&v) {
                Ok(u) => u,
                Err(e) => return err(400, e),
            };
            let target = v
                .get("target")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if v.get("register").and_then(|x| x.as_bool()).unwrap_or(false) {
                let _ = ua.register(None);
            }
            let result: Result<Value> = if path == "/api/options" {
                ua.options(&target)
                    .map(|r| json!({"status": r.map(|x| x.0), "rtt_ms": r.map(|x| x.1)}))
                    .map_err(|e| anyhow!("{e}"))
            } else {
                let dur = v
                    .get("duration")
                    .and_then(|d| d.as_u64())
                    .unwrap_or(10)
                    .min(600);
                let audio = match v.get("audio").and_then(|a| a.as_str()) {
                    Some("echo") => AudioSource::Echo,
                    Some("silence") => AudioSource::Silence,
                    _ => AudioSource::Tone(440.0),
                };
                ua.call(&CallOptions {
                    target,
                    duration: Duration::from_secs(dur),
                    ring_timeout: Duration::from_secs(60),
                    audio,
                    dtmf: v
                        .get("dtmf")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string()),
                })
                .map(|o| {
                    let wav = o.wav.as_ref().map(|w| b64(w));
                    json!({"outcome": o, "wav_b64": wav})
                })
                .map_err(|e| anyhow!("{e}"))
            };
            match result {
                Ok(mut r) => {
                    r["events"] = serde_json::to_value(&ua.events).unwrap_or(Value::Null);
                    r["local"] = json!(ua.local.to_string());
                    r["pcap_b64"] = json!(b64(&ua.tap.to_pcapng()));
                    ok_bytes(r.to_string().into_bytes(), "application/json")
                }
                Err(e) => err(500, e),
            }
        }
        (Method::Get, p) => {
            let file = if p == "/" {
                "index.html"
            } else {
                p.trim_start_matches('/')
            };
            if file.contains("..") {
                return err(400, "bad path");
            }
            if let Some(dir) = web {
                if let Ok(data) = std::fs::read(dir.join(file)) {
                    return ok_bytes(data, mime(file));
                }
            }
            match file {
                "index.html" => ok_bytes(INDEX.as_bytes().to_vec(), "text/html; charset=utf-8"),
                "app.js" => ok_bytes(APP_JS.as_bytes().to_vec(), "text/javascript"),
                "style.css" => ok_bytes(STYLE.as_bytes().to_vec(), "text/css"),
                "webphone.js" => ok_bytes(WEBPHONE_JS.as_bytes().to_vec(), "text/javascript"),
                _ => err(404, "not found"),
            }
        }
        _ => err(405, "method not allowed"),
    }
}

fn mime(f: &str) -> &'static str {
    match f.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}

fn new_token() -> String {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(7)
        ^ (std::process::id() as u64).rotate_left(32);
    let mut s = String::new();
    for _ in 0..4 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push_str(&format!("{x:016x}"));
    }
    s
}

/// Starts the server on a background thread. Returns the URL to open (with the access token).
pub fn spawn(
    listen: &str,
    web: Option<PathBuf>,
    use_token: bool,
    save: Option<SaveHook>,
) -> Result<(String, std::thread::JoinHandle<()>)> {
    let server = Server::http(listen).map_err(|e| anyhow!("cannot listen on {listen}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("no IP address"))?;
    let token = if use_token { Some(new_token()) } else { None };
    let url = match &token {
        Some(t) => format!("http://{addr}/?token={t}"),
        None => format!("http://{addr}/"),
    };
    let h = std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let resp = handle(&mut req, &web, &token, &save);
            let _ = req.respond(resp);
        }
    });
    Ok((url, h))
}

pub fn run(listen: &str, web: Option<PathBuf>, use_token: bool) -> Result<()> {
    let (url, h) = spawn(listen, web, use_token, None)?;
    eprintln!(
        "Sidetone UI: {url}\n(the token protects the API from other local pages; Ctrl+C to stop)"
    );
    let _ = h.join();
    Ok(())
}
