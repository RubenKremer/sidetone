//! Provider-neutral AI layer: builds the prompt from deterministic analysis
//! and shapes HTTP requests/responses. Transport is left to the caller
//! (native HTTP client, browser fetch, Tauri), so this compiles to WASM.

use crate::analysis::Report;
use crate::ladder;
use crate::redact::{RedactOptions, Redactor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anthropic Messages API.
    Anthropic,
    /// Any OpenAI-compatible chat completions endpoint (OpenAI, Azure via proxy, LM Studio, vLLM...).
    Openai,
    /// Local Ollama through its OpenAI-compatible endpoint.
    Ollama,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: Provider,
    #[serde(default)]
    pub base_url: Option<String>,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_lang")]
    pub language: String,
    #[serde(default = "default_tokens")]
    pub max_tokens: u32,
    /// Redaction applied to everything placed in the prompt.
    #[serde(default)]
    pub redact: Option<RedactOptions>,
}

fn default_lang() -> String {
    "English".into()
}
fn default_tokens() -> u32 {
    2000
}

pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-5-5";

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Builds the HTTP request for the configured provider.
pub fn build_request(cfg: &AiConfig, system: &str, user: &str, browser: bool) -> HttpRequest {
    match cfg.provider {
        Provider::Anthropic => {
            let base = cfg
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.anthropic.com".into());
            let mut headers = vec![
                ("content-type".into(), "application/json".into()),
                ("anthropic-version".into(), "2023-06-01".into()),
                ("x-api-key".into(), cfg.api_key.clone().unwrap_or_default()),
            ];
            if browser {
                headers.push((
                    "anthropic-dangerous-direct-browser-access".into(),
                    "true".into(),
                ));
            }
            let body = json!({
                "model": cfg.model,
                "max_tokens": cfg.max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            });
            HttpRequest {
                url: format!("{}/v1/messages", base.trim_end_matches('/')),
                headers,
                body: body.to_string(),
            }
        }
        Provider::Openai | Provider::Ollama => {
            let base = cfg.base_url.clone().unwrap_or_else(|| {
                if cfg.provider == Provider::Ollama {
                    "http://localhost:11434".into()
                } else {
                    "https://api.openai.com".into()
                }
            });
            let base = base.trim_end_matches('/');
            let url = if base.ends_with("/v1") {
                format!("{base}/chat/completions")
            } else {
                format!("{base}/v1/chat/completions")
            };
            let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
            if let Some(k) = cfg.api_key.as_ref().filter(|k| !k.is_empty()) {
                headers.push(("authorization".into(), format!("Bearer {k}")));
            }
            let body = json!({
                "model": cfg.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ],
            });
            HttpRequest {
                url,
                headers,
                body: body.to_string(),
            }
        }
    }
}

/// Extracts the assistant text from a provider response body.
pub fn parse_response(provider: Provider, body: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("invalid JSON from provider: {e}: {}", truncate(body, 300)))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| err.to_string());
        return Err(msg);
    }
    let text = match provider {
        Provider::Anthropic => v.get("content").and_then(|c| c.as_array()).map(|a| {
            a.iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        }),
        _ => v
            .pointer("/choices/0/message/content")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string()),
    };
    text.filter(|t| !t.is_empty())
        .ok_or_else(|| format!("no text in provider response: {}", truncate(body, 300)))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

pub fn system_prompt(language: &str) -> String {
    format!(
        "You are a senior VoIP/SIP troubleshooting engineer (carrier, SBC and contact center experience). \
You receive the output of Sidetone, a SIP/RTP analyzer: deterministic findings, a ladder of SIP messages, RTP statistics and raw messages. \
Treat the findings and statistics as measured facts; do not contradict them, but you may judge their relevance. \
Your job: 1) state the most probable root cause, 2) cite the evidence by message number (#n) and header/SDP line, \
3) give concrete fixes (which element, which setting), 4) list secondary issues and improvements worth making even if the call worked. \
If the data is insufficient, say exactly what extra capture or log would settle it. Be direct and concise, no generic advice. \
Answer in {language}. Use short sections and plain text with minimal markdown."
    )
}

/// Builds the user prompt for one call (or the whole capture).
pub fn build_prompt(
    r: &Report,
    call: Option<usize>,
    redact: Option<&RedactOptions>,
    question: Option<&str>,
) -> String {
    let mut red = redact.cloned().map(Redactor::new);
    let mut p = String::new();
    let _ = writeln!(p, "# Capture");
    let _ = writeln!(
        p,
        "packets={} sip_messages={} calls={} rtp_streams={} duration={:.1}s tls_records={}",
        r.summary.packets,
        r.summary.sip_messages,
        r.summary.calls,
        r.summary.rtp_streams,
        r.summary.duration_s,
        r.summary.tls_packets
    );

    let calls: Vec<usize> = match call {
        Some(c) => vec![c],
        None => (0..r.calls.len()).take(20).collect(),
    };
    for &ci in &calls {
        let c = &r.calls[ci];
        let _ = writeln!(p, "\n# Call {} ({})", ci, c.kind);
        let _ = writeln!(
            p,
            "call_id={} from=sip:{} to=sip:{} state={:?} final={} {} pdd_ms={} setup_ms={} talk_s={} ended_by={} reason={}",
            c.call_id,
            c.from,
            c.to,
            c.state,
            c.final_status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            c.final_reason.clone().unwrap_or_default(),
            c.pdd_ms.map(|v| format!("{v:.0}")).unwrap_or_else(|| "-".into()),
            c.setup_ms.map(|v| format!("{v:.0}")).unwrap_or_else(|| "-".into()),
            c.talk_s.map(|v| format!("{v:.1}")).unwrap_or_else(|| "-".into()),
            c.ended_by.clone().unwrap_or_else(|| "-".into()),
            c.reason.clone().unwrap_or_else(|| "-".into()),
        );
        let _ = writeln!(p, "user_agents={:?}", c.user_agents);
        let _ = writeln!(
            p,
            "offer_codecs={:?} answer_codecs={:?}",
            c.offer_codecs, c.answer_codecs
        );
        let _ = writeln!(p, "\n## Ladder\n{}", ladder::render_text(r, Some(ci)));
    }

    let findings: Vec<&crate::analysis::Finding> = r
        .findings
        .iter()
        .filter(|f| call.is_none() || f.call == call || f.call.is_none())
        .collect();
    let _ = writeln!(p, "\n# Findings ({})", findings.len());
    for f in &findings {
        let refs = if f.messages.is_empty() {
            String::new()
        } else {
            format!(" msgs={:?}", f.messages)
        };
        let _ = writeln!(
            p,
            "- [{:?}] {} ({}){}: {}",
            f.severity, f.title, f.rule, refs, f.detail
        );
    }

    // Raw messages: referenced by findings, carrying SDP, final responses and requests that start transactions.
    let mut wanted: Vec<usize> = Vec::new();
    for f in &findings {
        wanted.extend(&f.messages);
    }
    for &ci in &calls {
        for &mi in &r.calls[ci].messages {
            let m = &r.messages[mi];
            if m.retransmission {
                continue;
            }
            if m.sdp.is_some()
                || m.status.map(|s| s >= 200).unwrap_or(false)
                || m.method.as_deref().map(|x| x != "ACK").unwrap_or(false)
            {
                wanted.push(mi);
            }
        }
    }
    wanted.sort_unstable();
    wanted.dedup();
    // Redact the summary part now; raw messages are redacted individually below.
    let mut p = match red.as_mut() {
        Some(rd) => rd.text(&p),
        None => p,
    };
    let _ = writeln!(p, "\n# Raw SIP messages");
    let budget = 60_000usize;
    for mi in wanted {
        let m = &r.messages[mi];
        let raw = match red.as_mut() {
            Some(rd) => rd.sip_message(&m.raw),
            None => m.raw.clone(),
        };
        let head = format!("--- #{} {} -> {} (+{:.3}s)", m.index, m.src, m.dst, m.rel_s);
        let head = match red.as_mut() {
            Some(rd) => rd.text(&head),
            None => head,
        };
        let block = format!("\n{head}\n{}\n", truncate(&raw, 4000));
        if p.len() + block.len() > budget {
            let _ = writeln!(p, "\n[further messages omitted to fit the prompt]");
            break;
        }
        p.push_str(&block);
    }
    if let Some(q) = question.filter(|q| !q.trim().is_empty()) {
        let _ = writeln!(p, "\n# Question from the engineer\n{q}");
    }
    p
}
