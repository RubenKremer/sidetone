//! Native HTTP transport for the AI layer (honors HTTPS_PROXY).

use anyhow::{anyhow, Result};
use sidetone_core::ai::{build_request, parse_response, system_prompt, AiConfig};

pub fn ask(cfg: &AiConfig, prompt: &str) -> Result<String> {
    ask_with_system(cfg, &system_prompt(&cfg.language), prompt)
}

pub fn ask_with_system(cfg: &AiConfig, system: &str, prompt: &str) -> Result<String> {
    let req = build_request(cfg, system, prompt, false);
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(use_proxy(&req.url))
        .timeout(std::time::Duration::from_secs(180))
        .build();
    let mut r = agent.post(&req.url);
    for (k, v) in &req.headers {
        r = r.set(k, v);
    }
    let body = match r.send_string(&req.body) {
        Ok(resp) => resp.into_string()?,
        Err(ureq::Error::Status(code, resp)) => {
            let b = resp.into_string().unwrap_or_default();
            return Err(anyhow!(
                "provider returned HTTP {code}: {}",
                parse_response(cfg.provider, &b).err().unwrap_or(b)
            ));
        }
        Err(e) => return Err(anyhow!("request to {} failed: {e}", req.url)),
    };
    parse_response(cfg.provider, &body).map_err(|e| anyhow!(e))
}

/// Proxy env vars apply except for loopback and NO_PROXY hosts (e.g. a local Ollama).
fn use_proxy(url: &str) -> bool {
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    use_proxy_with(url, &no_proxy)
}

fn use_proxy_with(url: &str, no_proxy: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?'])
        .next()
        .unwrap_or("");
    let host = if host.starts_with('[') {
        host.trim_start_matches('[').split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    }
    .to_ascii_lowercase();
    if host == "localhost" || host.starts_with("127.") || host == "::1" {
        return false;
    }
    !no_proxy
        .split(',')
        .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
        .any(|e| !e.is_empty() && (e == "*" || host == e || host.ends_with(&format!(".{e}"))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_skips_proxy() {
        assert!(!super::use_proxy(
            "http://127.0.0.1:11434/v1/chat/completions"
        ));
        assert!(!super::use_proxy_with("http://localhost:11434/v1", ""));
        assert!(super::use_proxy_with(
            "https://api.anthropic.com/v1/messages",
            ""
        ));
        assert!(!super::use_proxy_with(
            "https://llm.corp.example/v1",
            "localhost,.corp.example"
        ));
    }
}

/// Downloads a provisioning file (sidetone-config JSON) over HTTP(S).
pub fn fetch_config(url: &str) -> Result<serde_json::Value> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(anyhow!("the address must start with http:// or https://"));
    }
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(use_proxy(url))
        .timeout(std::time::Duration::from_secs(20))
        .build();
    let body = match agent.get(url).set("Accept", "application/json").call() {
        Ok(r) => r.into_string()?,
        Err(ureq::Error::Status(code, _)) => return Err(anyhow!("{url} returned HTTP {code}")),
        Err(e) => return Err(anyhow!("{url}: {e}")),
    };
    serde_json::from_str(&body).map_err(|e| anyhow!("{url} is not JSON: {e}"))
}
