//! Local web UI + HTTP API. Same frontend as the WASM build, but analysis,
//! AI requests and test calls run natively on this machine.

use crate::aihttp;
use crate::phone;
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
const CONTROLLERS_JS: &str = include_str!("../../../web/controllers.js");
const I18N_JS: &str = include_str!("../../../web/i18n.js");
const HELP_JS: &str = include_str!("../../../web/help.js");
const EXPLAIN_JS: &str = include_str!("../../../web/explain.js");
const FILTER_JS: &str = include_str!("../../../web/filter.js");

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
            let mut features = vec!["analyze", "export", "ai-proxy", "ua", "phone", "sniff"];
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
        (Method::Post, "/api/rtp_audio") => {
            let id = q
                .get("stream")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            match rtp_wav(&body, id) {
                Ok((wav, info)) => Response::from_data(wav)
                    .with_header(header("Content-Type", "audio/wav"))
                    .with_header(header("X-Sidetone-Audio", &info)),
                Err(e) => err(422, e),
            }
        }
        (Method::Post, "/api/ladder") => match analyze(&body) {
            Ok(r) => {
                let c = call_param(&r, &q);
                ok_bytes(
                    render_svg(
                        &r,
                        &LadderOptions {
                            call: c,
                            // calls=0,2,5: several dialogs (call legs) in one ladder.
                            calls: q
                                .get("calls")
                                .map(|v| {
                                    v.split(',').filter_map(|x| x.trim().parse().ok()).collect()
                                })
                                .unwrap_or_default(),
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
        (Method::Post, "/api/options")
        | (Method::Post, "/api/call")
        | (Method::Post, "/api/register") => {
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
            if path != "/api/register"
                && v.get("register").and_then(|x| x.as_bool()).unwrap_or(false)
            {
                let _ = ua.register(None);
            }
            let result: Result<Value> = if path == "/api/register" {
                ua.register(None)
                    .map(|st| json!({"status": st}))
                    .map_err(|e| anyhow!("{e}"))
            } else if path == "/api/options" {
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
        (m, p) if p.starts_with("/api/sniff/") => sniff_api(&m, p, &q, &body),
        (m, p)
            if p.starts_with("/api/phone/")
                || p.starts_with("/api/audio/")
                || p.starts_with("/api/diag/") =>
        {
            phone_api(&m, p, &q, &body)
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
                "controllers.js" => ok_bytes(CONTROLLERS_JS.as_bytes().to_vec(), "text/javascript"),
                "i18n.js" => ok_bytes(I18N_JS.as_bytes().to_vec(), "text/javascript"),
                "help.js" => ok_bytes(HELP_JS.as_bytes().to_vec(), "text/javascript"),
                "explain.js" => ok_bytes(EXPLAIN_JS.as_bytes().to_vec(), "text/javascript"),
                "filter.js" => ok_bytes(FILTER_JS.as_bytes().to_vec(), "text/javascript"),
                _ => err(404, "not found"),
            }
        }
        _ => err(405, "method not allowed"),
    }
}

fn json_resp(v: Value) -> Resp {
    ok_bytes(v.to_string().into_bytes(), "application/json")
}

fn body_json(body: &[u8]) -> std::result::Result<Value, Resp> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|e| err(400, format!("bad JSON: {e}")))
}

/// Softphone, sound card and diagnostics endpoints.
fn phone_api(m: &Method, path: &str, q: &HashMap<String, String>, body: &[u8]) -> Resp {
    use sidetone_ua::{audio, dns, stun};
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok());
    match (m, path) {
        (Method::Get, "/api/phone/state") => {
            let p = phone::get();
            let since = num("since").unwrap_or(0);
            let tsince = num("trace_since");
            let mut v = json!({
                "state": p.engine.state(),
                "events": p.engine.events_since(since),
            });
            if let Some(t) = tsince {
                v["trace"] = json!(p.engine.trace_since(t, 500));
            }
            json_resp(v)
        }
        (Method::Get, "/api/phone/trace") => {
            let p = phone::get();
            let since = num("since").unwrap_or(0);
            let limit = num("limit").unwrap_or(2000) as usize;
            json_resp(json!(p.engine.trace_since(since, limit)))
        }
        (Method::Post, "/api/phone/cmd") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            match phone::get().command(&v) {
                Ok(r) => json_resp(r),
                Err(e) => err(400, e),
            }
        }
        (Method::Get, "/api/phone/config") => json_resp(json!(phone::get().config())),
        (Method::Post, "/api/phone/config") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            match phone::get().set_config(&v) {
                Ok(()) => json_resp(json!({"ok": true, "config": phone::get().config()})),
                Err(e) => err(400, e),
            }
        }
        (Method::Get, "/api/phone/history") => json_resp(json!(phone::get().engine.history())),
        (Method::Post, "/api/phone/history/clear") => {
            phone::get().clear_history();
            json_resp(json!({"ok": true}))
        }
        (Method::Get, "/api/phone/capture") => {
            let b = phone::get().engine.capture();
            ok_bytes(b, "application/octet-stream")
        }
        (Method::Get, "/api/phone/recording") => {
            match num("line").and_then(|l| phone::get().engine.recording(l as u32)) {
                Some(w) => ok_bytes(w, "audio/wav"),
                None => err(
                    404,
                    "no recording for this line (turn Record on during the call)",
                ),
            }
        }
        (Method::Get, "/api/audio/devices") => {
            let d = audio::list();
            let st = phone::get().audio_status();
            json_resp(json!({"devices": d, "audio": st}))
        }
        (Method::Get, "/api/audio/status") => json_resp(phone::get().audio_status()),
        (Method::Post, "/api/audio/tone") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let hz = v.get("hz").and_then(|x| x.as_f64()).unwrap_or(440.0) as f32;
            let ms = v
                .get("ms")
                .and_then(|x| x.as_u64())
                .unwrap_or(1500)
                .min(10_000);
            match phone::get().audio_tone(hz.clamp(50.0, 7000.0), ms) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Post, "/api/audio/record_test") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let secs = v.get("seconds").and_then(|x| x.as_u64()).unwrap_or(4);
            match phone::get().audio_record_test(secs) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Post, "/api/audio/loopback") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let on = v.get("on").and_then(|x| x.as_bool()).unwrap_or(false);
            match phone::get().audio_loopback(on) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Get, "/api/diag/dns") => {
            let host = q.get("host").cloned().unwrap_or_default();
            if host.trim().is_empty() {
                return err(400, "missing host");
            }
            json_resp(json!(dns::report(&host)))
        }
        (Method::Post, "/api/diag/stun") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let servers: Vec<String> = v
                .get("servers")
                .and_then(|s| serde_json::from_value(s.clone()).ok())
                .unwrap_or_else(|| {
                    vec![
                        "stun.l.google.com:19302".into(),
                        "stun.cloudflare.com:3478".into(),
                    ]
                });
            json_resp(json!(stun::test(&servers, None)))
        }
        (Method::Post, "/api/diag/options") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let acc = v
                .get("account")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let target = v
                .get("target")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            match phone::get().engine.options(acc, target) {
                Some((code, rtt, summary)) => {
                    json_resp(json!({"code": code, "rtt_ms": rtt, "summary": summary}))
                }
                None => json_resp(
                    json!({"code": null, "summary": "no response (check the account is ready, the server address and the firewall)"}),
                ),
            }
        }
        _ => err(404, "unknown phone endpoint"),
    }
}

/// One RTP stream of a capture as a WAV: G.711 decoded by the core, Opus by
/// libopus. The second value is a short JSON with codec, packets and gaps.
fn rtp_wav(bytes: &[u8], id: usize) -> std::result::Result<(Vec<u8>, String), String> {
    use sidetone_core::audio::{stream_audio, wav_mono};
    let a = stream_audio(bytes, id)?;
    let info = |a: &sidetone_core::audio::StreamAudio| serde_json::to_string(a).unwrap_or_default();
    if !a.pcm.is_empty() {
        return Ok((wav_mono(&a.pcm, a.rate), info(&a)));
    }
    if a.codec.to_ascii_uppercase().contains("OPUS") && !a.frames.is_empty() {
        let rate = 16000u32;
        let mut dec = opus::Decoder::new(rate, opus::Channels::Mono).map_err(|e| e.to_string())?;
        let mut pcm: Vec<i16> = Vec::new();
        let mut buf = vec![0i16; 5760];
        for (pos, f) in &a.frames {
            // RTP clock is 48 kHz; place each frame where its timestamp says.
            let at = (*pos as u64 * rate as u64 / 48000) as usize;
            if pcm.len() < at {
                pcm.resize(at, 0);
            }
            if let Ok(n) = dec.decode(f, &mut buf, false) {
                pcm.extend_from_slice(&buf[..n]);
            }
        }
        return Ok((wav_mono(&pcm, rate), info(&a)));
    }
    Err(a
        .note
        .unwrap_or_else(|| format!("{} cannot be played", a.codec)))
}

/// Passive capture on a network interface (libpcap / Npcap loaded at run time).
fn sniff_api(m: &Method, path: &str, q: &HashMap<String, String>, body: &[u8]) -> Resp {
    use sidetone_ua::sniff;
    match (m, path) {
        (Method::Get, "/api/sniff/interfaces") => match sniff::interfaces() {
            Ok((list, version)) => json_resp(json!({"interfaces": list, "library": version})),
            Err(e) => json_resp(json!({"interfaces": [], "error": e})),
        },
        (Method::Post, "/api/sniff/start") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let iface = v
                .get("iface")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let filter = v
                .get("filter")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if iface.is_empty() {
                return err(400, "choose an interface");
            }
            match sniff::global().lock().unwrap().start(&iface, &filter) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(400, e),
            }
        }
        (Method::Post, "/api/sniff/stop") => {
            sniff::global().lock().unwrap().stop_capture();
            json_resp(json!({"ok": true}))
        }
        (Method::Get, "/api/sniff/status") => {
            let since = q
                .get("since")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let s = sniff::global().lock().unwrap();
            json_resp(json!({"status": s.status(), "sip": s.sip_since(since, 300)}))
        }
        (Method::Get, "/api/sniff/pcap") => ok_bytes(
            sniff::global().lock().unwrap().to_pcapng(),
            "application/octet-stream",
        ),
        _ => err(404, "unknown capture endpoint"),
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
        // One thread per request: diagnostics can take seconds while the UI keeps polling.
        let ctx = std::sync::Arc::new((web, token, save));
        for mut req in server.incoming_requests() {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let resp = handle(&mut req, &ctx.0, &ctx.1, &ctx.2);
                let _ = req.respond(resp);
            });
        }
    });
    Ok((url, h))
}

pub fn run(listen: &str, web: Option<PathBuf>, use_token: bool) -> Result<()> {
    let (url, h) = spawn(listen, web, use_token, None)?;
    // Ctrl+C or SIGTERM: hang up and unregister before leaving.
    let _ = ctrlc::set_handler(|| {
        phone::shutdown();
        std::process::exit(0);
    });
    eprintln!(
        "Sidetone UI: {url}\n(the token protects the API from other local pages; Ctrl+C to stop)"
    );
    let _ = h.join();
    Ok(())
}
