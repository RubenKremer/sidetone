//! Browser bindings. Every function is stateless from the caller's view;
//! the last analyzed capture is cached so repeated calls on the same bytes are cheap.

use serde_json::json;
use sidetone_core::ai::{
    build_prompt, build_request, parse_response, system_prompt, AiConfig, Provider,
};
use sidetone_core::export::{export_pcapng, ExportOptions};
use sidetone_core::ladder::{render_svg, LadderOptions, TimeMode};
use sidetone_core::redact::RedactOptions;
use sidetone_core::{analyze_bytes, Report};
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

thread_local! {
    static CACHE: RefCell<Option<(u64, usize, Report)>> = const { RefCell::new(None) };
}

fn fingerprint(b: &[u8]) -> u64 {
    // FNV-1a over a sample of the data plus length: cheap and good enough for a one-entry cache.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let step = (b.len() / 4096).max(1);
    for x in b.iter().step_by(step) {
        h ^= *x as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn with_report<T>(bytes: &[u8], f: impl FnOnce(&Report) -> T) -> Result<T, JsError> {
    let fp = fingerprint(bytes);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let hit = matches!(&*c, Some((h, l, _)) if *h == fp && *l == bytes.len());
        if !hit {
            let r = analyze_bytes(bytes).map_err(|e| JsError::new(&e.to_string()))?;
            *c = Some((fp, bytes.len(), r));
        }
        Ok(f(&c.as_ref().unwrap().2))
    })
}

fn call_opt(r: &Report, call: i32) -> Option<usize> {
    if call >= 0 && (call as usize) < r.calls.len() {
        Some(call as usize)
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Full report as JSON.
#[wasm_bindgen]
pub fn analyze(bytes: &[u8]) -> Result<String, JsError> {
    with_report(bytes, |r| r.to_json())
}

/// Ladder SVG for one call (`call` < 0 draws everything).
#[wasm_bindgen]
pub fn ladder_svg(bytes: &[u8], call: i32) -> Result<String, JsError> {
    with_report(bytes, |r| {
        render_svg(
            r,
            &LadderOptions {
                call: call_opt(r, call),
                ..Default::default()
            },
        )
    })
}

/// Ladder SVG for several calls at once (call legs), `calls` like "0,2,5".
#[wasm_bindgen]
pub fn ladder_svg_calls(bytes: &[u8], calls: &str) -> Result<String, JsError> {
    with_report(bytes, |r| {
        render_svg(
            r,
            &LadderOptions {
                calls: calls
                    .split(',')
                    .filter_map(|x| x.trim().parse().ok())
                    .filter(|c: &usize| *c < r.calls.len())
                    .collect(),
                ..Default::default()
            },
        )
    })
}

/// Ladder SVG with options: one call (-1 = all) or several ("0,2,5"), and
/// RTP streams in time order or after the SIP.
#[wasm_bindgen]
pub fn ladder_svg_opts(
    bytes: &[u8],
    call: i32,
    calls: &str,
    rtp_at_end: bool,
) -> Result<String, JsError> {
    with_report(bytes, |r| {
        render_svg(
            r,
            &LadderOptions {
                call: call_opt(r, call),
                calls: calls
                    .split(',')
                    .filter_map(|x| x.trim().parse().ok())
                    .filter(|c: &usize| *c < r.calls.len())
                    .collect(),
                rtp_at_end,
                ..Default::default()
            },
        )
    })
}

/// Ladder SVG with every view option as bit flags: 1 RTP after the SIP,
/// 2 fold retransmissions, 4 time since the row above, 8 clock time.
#[wasm_bindgen]
pub fn ladder_svg_flags(
    bytes: &[u8],
    call: i32,
    calls: &str,
    flags: u32,
) -> Result<String, JsError> {
    with_report(bytes, |r| {
        render_svg(
            r,
            &LadderOptions {
                call: call_opt(r, call),
                calls: calls
                    .split(',')
                    .filter_map(|x| x.trim().parse().ok())
                    .filter(|c: &usize| *c < r.calls.len())
                    .collect(),
                rtp_at_end: flags & 1 != 0,
                collapse_retransmissions: flags & 2 != 0,
                time: if flags & 8 != 0 {
                    TimeMode::Absolute
                } else if flags & 4 != 0 {
                    TimeMode::Delta
                } else {
                    TimeMode::Relative
                },
                ..Default::default()
            },
        )
    })
}

/// One RTP stream as a WAV when it is G.711; otherwise an error whose
/// message is JSON {"codec", "frames": [[ts_offset, base64], ...]} for
/// decoding in the page (Opus through WebCodecs).
#[wasm_bindgen]
pub fn rtp_audio(bytes: &[u8], stream: u32) -> Result<Vec<u8>, JsError> {
    use base64::Engine as _;
    let a =
        sidetone_core::audio::stream_audio(bytes, stream as usize).map_err(|e| JsError::new(&e))?;
    if !a.pcm.is_empty() {
        return Ok(sidetone_core::audio::wav_mono(&a.pcm, a.rate));
    }
    let frames: Vec<serde_json::Value> = a
        .frames
        .iter()
        .map(|(t, f)| json!([t, base64::engine::general_purpose::STANDARD.encode(f)]))
        .collect();
    Err(JsError::new(
        &json!({"codec": a.codec, "clock": a.clock_rate, "frames": frames, "note": a.note})
            .to_string(),
    ))
}

/// Annotated pcapng. `opts_json`: {"annotate":true,"redact":bool,"call":n|null,"sip_only":bool}
#[wasm_bindgen]
pub fn export_capture(bytes: &[u8], opts_json: &str) -> Result<Vec<u8>, JsError> {
    let v: serde_json::Value = serde_json::from_str(opts_json).unwrap_or(json!({}));
    with_report(bytes, |r| {
        let call = v
            .get("call")
            .and_then(|c| c.as_i64())
            .map(|c| c as i32)
            .and_then(|c| call_opt(r, c));
        let opts = ExportOptions {
            annotate: v.get("annotate").and_then(|x| x.as_bool()).unwrap_or(true),
            redact: if v.get("redact").and_then(|x| x.as_bool()).unwrap_or(false) {
                Some(RedactOptions::default())
            } else {
                None
            },
            call,
            sip_only: v.get("sip_only").and_then(|x| x.as_bool()).unwrap_or(false),
        };
        export_pcapng(r, &opts)
    })
}

/// {"system": ..., "prompt": ...} for the AI request.
#[wasm_bindgen]
pub fn ai_prompt(
    bytes: &[u8],
    call: i32,
    redact: bool,
    language: &str,
    question: &str,
) -> Result<String, JsError> {
    with_report(bytes, |r| {
        let red = if redact {
            Some(RedactOptions::default())
        } else {
            None
        };
        let q = if question.trim().is_empty() {
            None
        } else {
            Some(question)
        };
        json!({"system": system_prompt(language), "prompt": build_prompt(r, call_opt(r, call), red.as_ref(), q)}).to_string()
    })
}

/// HTTP request (url, headers, body) for the provider, to be sent with fetch().
#[wasm_bindgen]
pub fn ai_request(config_json: &str, system: &str, prompt: &str) -> Result<String, JsError> {
    let cfg: AiConfig =
        serde_json::from_str(config_json).map_err(|e| JsError::new(&format!("config: {e}")))?;
    Ok(serde_json::to_string(&build_request(&cfg, system, prompt, true)).unwrap())
}

/// Extracts the text from a provider response.
#[wasm_bindgen]
pub fn ai_parse(provider: &str, body: &str) -> Result<String, JsError> {
    let p = match provider {
        "anthropic" => Provider::Anthropic,
        "ollama" => Provider::Ollama,
        _ => Provider::Openai,
    };
    parse_response(p, body).map_err(|e| JsError::new(&e))
}

/// Synthetic sample capture by name.
#[wasm_bindgen]
pub fn sample(name: &str) -> Result<Vec<u8>, JsError> {
    sidetone_core::synth::generate(name).ok_or_else(|| JsError::new("unknown sample"))
}

/// [{"name":..., "description":...}]
#[wasm_bindgen]
pub fn samples() -> String {
    let v: Vec<serde_json::Value> = sidetone_core::synth::SCENARIOS
        .iter()
        .map(|(n, d)| json!({"name": n, "description": d}))
        .collect();
    serde_json::Value::Array(v).to_string()
}

/// Verified provisioning XML → account JSON (`kind`: `"native"` or `"browser"`).
#[wasm_bindgen]
pub fn parse_provision(xml: &str, kind: &str) -> Result<String, JsError> {
    sidetone_core::provision::parse(xml, kind)
        .map(|v| v.to_string())
        .map_err(|e| JsError::new(&e))
}

/// Builds a pcapng from a web phone SIP log (see `synth::SipLog`).
#[wasm_bindgen]
pub fn capture_from_sip_log(log_json: &str) -> Result<Vec<u8>, JsError> {
    let log: sidetone_core::synth::SipLog =
        serde_json::from_str(log_json).map_err(|e| JsError::new(&e.to_string()))?;
    sidetone_core::synth::capture_from_log(&log).map_err(|e| JsError::new(&e))
}
