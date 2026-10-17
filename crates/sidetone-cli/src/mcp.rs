//! Model Context Protocol server over stdio (JSON-RPC 2.0, one message per line).
//! Lets any MCP-capable AI client analyze captures and run test calls.

use crate::report_text;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use sidetone_core::export::{export_pcapng, ExportOptions};
use sidetone_core::ladder::{render_svg, render_text, LadderOptions};
use sidetone_core::redact::RedactOptions;
use sidetone_core::{analyze_bytes, Report};
use sidetone_ua::{AudioSource, CallOptions, Profile, Tap, Ua};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::time::Duration;

const INSTRUCTIONS: &str = "Sidetone analyzes SIP/RTP captures (pcap/pcapng) and can place test calls. \
Start with analyze_capture to get calls and deterministic findings, then get_ladder or get_call_context for one call. \
Findings are measured facts; build explanations on them and cite message numbers (#n).";

fn tools() -> Value {
    let path =
        json!({"type": "string", "description": "Path to a .pcap or .pcapng file on this machine"});
    let call =
        json!({"type": "string", "description": "Call index (from analyze_capture) or Call-ID"});
    let ua_props = json!({
        "profile": {"type": "string", "description": "Path to a Sidetone UA profile JSON"},
        "domain": {"type": "string", "description": "Registrar/domain host[:port]"},
        "user": {"type": "string"},
        "password": {"type": "string"},
        "outbound_proxy": {"type": "string"}
    });
    let mut call_props = ua_props.as_object().unwrap().clone();
    call_props.insert(
        "target".into(),
        json!({"type": "string", "description": "Number, user@host or SIP URI"}),
    );
    call_props.insert("duration".into(), json!({"type": "integer", "description": "Seconds to stay connected (default 10, max 120)"}));
    call_props.insert("dtmf".into(), json!({"type": "string"}));
    call_props.insert(
        "pcap_out".into(),
        json!({"type": "string", "description": "Where to save the call capture"}),
    );
    let mut opt_props = ua_props.as_object().unwrap().clone();
    opt_props.insert("target".into(), json!({"type": "string"}));
    json!([
        {"name": "analyze_capture", "description": "Summary of a capture: calls, RTP streams and findings (errors first).",
         "inputSchema": {"type": "object", "properties": {"path": path, "call": call}, "required": ["path"]}},
        {"name": "get_ladder", "description": "Ladder diagram of one call or the whole capture, as text or SVG (SVG is written to `out`).",
         "inputSchema": {"type": "object", "properties": {"path": path, "call": call, "format": {"type": "string", "enum": ["text", "svg"]}, "out": {"type": "string"}}, "required": ["path"]}},
        {"name": "get_message", "description": "Raw text of one SIP message by its index (#n).",
         "inputSchema": {"type": "object", "properties": {"path": path, "index": {"type": "integer"}}, "required": ["path", "index"]}},
        {"name": "get_call_context", "description": "Everything needed to diagnose a call: summary, ladder, findings, RTP stats and relevant raw messages.",
         "inputSchema": {"type": "object", "properties": {"path": path, "call": call, "redact": {"type": "boolean"}}, "required": ["path"]}},
        {"name": "export_pcapng", "description": "Write an annotated pcapng (findings as packet comments), optionally redacted or filtered to one call.",
         "inputSchema": {"type": "object", "properties": {"path": path, "out": {"type": "string"}, "call": call, "redact": {"type": "boolean"}, "sip_only": {"type": "boolean"}}, "required": ["path", "out"]}},
        {"name": "generate_sample", "description": "Write a synthetic capture with known problems: good-call, nat-one-way, codec-488, bad-quality, register-timeout, srtp-mismatch, demo.",
         "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "out": {"type": "string"}}, "required": ["name", "out"]}},
        {"name": "sip_options", "description": "Send a SIP OPTIONS ping from this machine and analyze the exchange.",
         "inputSchema": {"type": "object", "properties": Value::Object(opt_props), "required": ["target"]}},
        {"name": "get_test_suite_format", "description": "Reference of the JSON test suite format and known rule ids, to write suites for run_test_suite.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "run_test_suite", "description": "Run an automated SIP test suite (JSON file path, or inline JSON in `suite_json`) and return pass/fail per check.",
         "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "suite_json": {"type": "string"}, "out": {"type": "string", "description": "Results directory"}}}},
        {"name": "test_call", "description": "Place a real test call (tone audio) from this machine and return the outcome plus analysis.",
         "inputSchema": {"type": "object", "properties": Value::Object(call_props), "required": ["target"]}}
    ])
}

struct State {
    cache: HashMap<String, Report>,
}

impl State {
    fn report(&mut self, path: &str) -> Result<&Report> {
        if !self.cache.contains_key(path) {
            let bytes = std::fs::read(path).map_err(|e| anyhow!("{path}: {e}"))?;
            let r = analyze_bytes(&bytes).map_err(|e| anyhow!("{path}: {e}"))?;
            self.cache.insert(path.to_string(), r);
        }
        Ok(&self.cache[path])
    }
}

fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str())
}

fn call_of(r: &Report, a: &Value) -> Result<Option<usize>> {
    match a.get("call") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let k = v
                .as_str()
                .map(|x| x.to_string())
                .unwrap_or_else(|| v.to_string());
            r.find_call(&k)
                .map(Some)
                .ok_or_else(|| anyhow!("no call {k}"))
        }
    }
}

fn ua_from(a: &Value) -> Result<Ua> {
    let mut p = match s(a, "profile") {
        Some(path) => {
            Profile::from_json(&std::fs::read_to_string(path)?).map_err(|e| anyhow!(e))?
        }
        None => Profile::default(),
    };
    if let Some(d) = s(a, "domain") {
        p.account.domain = d.into();
    }
    if let Some(u) = s(a, "user") {
        p.account.user = u.into();
    }
    if let Some(pw) = s(a, "password") {
        p.account.password = Some(pw.into());
    }
    if let Some(o) = s(a, "outbound_proxy") {
        p.account.outbound_proxy = Some(o.into());
    }
    Ua::new(p, Tap::new()).map_err(|e| anyhow!("{e}"))
}

fn call_tool(st: &mut State, name: &str, a: &Value) -> Result<String> {
    match name {
        "analyze_capture" => {
            let path = s(a, "path")
                .ok_or_else(|| anyhow!("path required"))?
                .to_string();
            let r = st.report(&path)?;
            let c = call_of(r, a)?;
            Ok(report_text(r, c, false))
        }
        "get_ladder" => {
            let path = s(a, "path")
                .ok_or_else(|| anyhow!("path required"))?
                .to_string();
            let r = st.report(&path)?;
            let c = call_of(r, a)?;
            if s(a, "format") == Some("svg") {
                let svg = render_svg(
                    r,
                    &LadderOptions {
                        call: c,
                        ..Default::default()
                    },
                );
                match s(a, "out") {
                    Some(out) => {
                        std::fs::write(out, &svg)?;
                        Ok(format!("SVG written to {out}"))
                    }
                    None => Ok(svg),
                }
            } else {
                Ok(render_text(r, c))
            }
        }
        "get_message" => {
            let path = s(a, "path")
                .ok_or_else(|| anyhow!("path required"))?
                .to_string();
            let i = a
                .get("index")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("index required"))? as usize;
            let r = st.report(&path)?;
            let m = r
                .messages
                .get(i)
                .ok_or_else(|| anyhow!("no message #{i}"))?;
            Ok(format!(
                "#{} frame {} {} -> {} +{:.3}s {:?}\n\n{}",
                m.index, m.frame, m.src, m.dst, m.rel_s, m.transport, m.raw
            ))
        }
        "get_call_context" => {
            let path = s(a, "path")
                .ok_or_else(|| anyhow!("path required"))?
                .to_string();
            let r = st.report(&path)?;
            let c = call_of(r, a)?;
            let red = if a.get("redact").and_then(|v| v.as_bool()).unwrap_or(false) {
                Some(RedactOptions::default())
            } else {
                None
            };
            Ok(sidetone_core::ai::build_prompt(r, c, red.as_ref(), None))
        }
        "export_pcapng" => {
            let path = s(a, "path")
                .ok_or_else(|| anyhow!("path required"))?
                .to_string();
            let out = s(a, "out")
                .ok_or_else(|| anyhow!("out required"))?
                .to_string();
            let r = st.report(&path)?;
            let c = call_of(r, a)?;
            let redact = a.get("redact").and_then(|v| v.as_bool()).unwrap_or(false);
            let bytes = export_pcapng(
                r,
                &ExportOptions {
                    annotate: true,
                    redact: if redact {
                        Some(RedactOptions::default())
                    } else {
                        None
                    },
                    call: c,
                    sip_only: a.get("sip_only").and_then(|v| v.as_bool()).unwrap_or(false),
                },
            );
            std::fs::write(&out, &bytes)?;
            Ok(format!("wrote {} bytes to {out}", bytes.len()))
        }
        "generate_sample" => {
            let n = s(a, "name").ok_or_else(|| anyhow!("name required"))?;
            let out = s(a, "out").ok_or_else(|| anyhow!("out required"))?;
            let bytes =
                sidetone_core::synth::generate(n).ok_or_else(|| anyhow!("unknown sample {n}"))?;
            std::fs::write(out, bytes)?;
            Ok(format!("sample {n} written to {out}"))
        }
        "sip_options" => {
            let target = s(a, "target").ok_or_else(|| anyhow!("target required"))?;
            let mut ua = ua_from(a)?;
            let res = ua.options(target).map_err(|e| anyhow!("{e}"))?;
            let r = analyze_bytes(&ua.tap.to_pcapng()).map_err(|e| anyhow!("{e}"))?;
            let head = match res {
                Some((code, ms)) => {
                    format!("OPTIONS {target}: {code} in {ms} ms from {}", ua.local)
                }
                None => format!("OPTIONS {target}: no response (sent from {})", ua.local),
            };
            Ok(format!("{head}\n\n{}", report_text(&r, None, true)))
        }
        "test_call" => {
            let target = s(a, "target")
                .ok_or_else(|| anyhow!("target required"))?
                .to_string();
            let dur = a
                .get("duration")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .min(120);
            let mut ua = ua_from(a)?;
            let out = ua
                .call(&CallOptions {
                    target,
                    duration: Duration::from_secs(dur),
                    ring_timeout: Duration::from_secs(60),
                    audio: AudioSource::Tone(440.0),
                    dtmf: s(a, "dtmf").map(|x| x.to_string()),
                })
                .map_err(|e| anyhow!("{e}"))?;
            let pcap = ua.tap.to_pcapng();
            if let Some(p) = s(a, "pcap_out") {
                std::fs::write(p, &pcap)?;
            }
            let r = analyze_bytes(&pcap).map_err(|e| anyhow!("{e}"))?;
            Ok(format!(
                "{}\n\n{}",
                serde_json::to_string_pretty(&out)?,
                report_text(&r, None, true)
            ))
        }
        "get_test_suite_format" => Ok(crate::testrun::SUITE_FORMAT.to_string()),
        "run_test_suite" => {
            let out = std::path::PathBuf::from(s(a, "out").unwrap_or("sidetone-results"));
            std::fs::create_dir_all(&out)?;
            let path = match (s(a, "path"), s(a, "suite_json")) {
                (Some(p), _) => std::path::PathBuf::from(p),
                (None, Some(j)) => {
                    crate::testrun::parse_suite(j)?;
                    let p = out.join("suite.json");
                    std::fs::write(&p, j)?;
                    p
                }
                _ => return Err(anyhow!("path or suite_json required")),
            };
            // run_suite prints to stdout, which is the MCP channel: run it in a child process.
            let exe = std::env::current_exe()?;
            let o = std::process::Command::new(exe)
                .arg("test")
                .arg(&path)
                .arg("--out")
                .arg(&out)
                .output()?;
            Ok(format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ))
        }
        other => Err(anyhow!("unknown tool {other}")),
    }
}

pub fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut st = State {
        cache: HashMap::new(),
    };
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}});
                writeln!(stdout, "{err}")?;
                stdout.flush()?;
                continue;
            }
        };
        let Some(id) = req.get("id").cloned() else {
            continue;
        }; // notification
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let result: std::result::Result<Value, (i64, String)> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18"),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "sidetone", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                match call_tool(&mut st, name, &args) {
                    Ok(text) => Ok(json!({"content": [{"type": "text", "text": text}]})),
                    Err(e) => Ok(
                        json!({"content": [{"type": "text", "text": e.to_string()}], "isError": true}),
                    ),
                }
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        let resp = match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, msg)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
            }
        };
        writeln!(stdout, "{resp}")?;
        stdout.flush()?;
    }
    Ok(())
}
