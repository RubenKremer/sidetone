//! HTTP download of native provisioning XML and merge helpers.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sidetone_ua::engine::AccountCfg;
use sidetone_ua::profile::Profile;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use ureq::{AgentBuilder, RedirectAuthHeaders};

const MAX_BODY: usize = 256 * 1024;
const USER_AGENT: &str = concat!("Sidetone/", env!("CARGO_PKG_VERSION"));

/// Downloads provisioning XML and returns native `parse` JSON (does not persist).
pub fn fetch_provision(url: &str, tls_verify: bool) -> Result<Value> {
    let (fetch_url, auth, https) = prepare_fetch_url(url)?;
    let agent = build_agent(tls_verify, https);
    let mut req = agent.get(&fetch_url);
    if let Some((user, pass)) = &auth {
        req = req.set("Authorization", &basic_authorization(user, pass));
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _r)) => {
            return Err(anyhow!(
                "provisioning HTTP {} from {}",
                code,
                redact_url(url)
            ));
        }
        Err(e) => {
            return Err(anyhow!(
                "provisioning request to {} failed: {e}",
                redact_url(url)
            ));
        }
    };
    let mut limited = resp.into_reader().take((MAX_BODY as u64) + 1);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|e| anyhow!("provisioning read failed: {e}"))?;
    if body.len() > MAX_BODY {
        return Err(anyhow!("provisioning body exceeds {} bytes", MAX_BODY));
    }
    let xml = String::from_utf8(body).map_err(|e| anyhow!("provisioning body is not UTF-8: {e}"))?;
    sidetone_core::provision::parse(&xml, "native").map_err(|e| anyhow!("{e}"))
}

fn build_agent(tls_verify: bool, https: bool) -> ureq::Agent {
    let mut b = AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent(USER_AGENT)
        .redirect_auth_headers(RedirectAuthHeaders::SameHost);
    if https {
        b = b.https_only(true);
    }
    b.tls_config(Arc::new(sidetone_ua::transport::tls_config(tls_verify)))
        .build()
}

struct ParsedHttpUrl {
    fetch_url: String,
    auth: Option<(String, String)>,
    https: bool,
}

fn prepare_fetch_url(url: &str) -> Result<(String, Option<(String, String)>, bool)> {
    let p = parse_http_url(url).map_err(|e| anyhow!("{e}"))?;
    Ok((p.fetch_url, p.auth, p.https))
}

fn parse_http_url(url: &str) -> Result<ParsedHttpUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("unsupported URL scheme in {}", redact_url(url)))?;
    let https = scheme.eq_ignore_ascii_case("https");
    if !https && !scheme.eq_ignore_ascii_case("http") {
        return Err(format!(
            "provisioning URL must be http or https, not {}",
            scheme
        ));
    }
    let scheme_lower = if https { "https" } else { "http" };
    let (authority, after_auth) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (auth, hostport) = match authority.rfind('@') {
        Some(at) => {
            let userinfo = &authority[..at];
            let (user, pass) = userinfo
                .split_once(':')
                .map(|(u, p)| (percent_decode(u), percent_decode(p)))
                .ok_or_else(|| "URL userinfo must be user:password".to_string())?;
            (Some((user, pass)), &authority[at + 1..])
        }
        None => (None, authority),
    };
    if hostport.is_empty() {
        return Err("missing host in provisioning URL".into());
    }
    let fetch_url = format!("{scheme_lower}://{hostport}{after_auth}");
    Ok(ParsedHttpUrl {
        fetch_url,
        auth,
        https,
    })
}

pub(crate) fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let Some(at) = rest.find('@') else {
        return url.to_string();
    };
    let after = rest[at + 1..].find('/').map(|i| at + 1 + i).unwrap_or(rest.len());
    format!("{}://***@{}", scheme, &rest[after..])
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn basic_authorization(user: &str, pass: &str) -> String {
    format!("Basic {}", base64(&format!("{user}:{pass}")))
}

fn base64(data: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = data.as_bytes();
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
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

#[derive(Debug, Deserialize)]
struct ProvisionNative {
    label: String,
    enabled: bool,
    register: bool,
    retry_s: u32,
    blf: Vec<String>,
    profile: Profile,
}

/// Maps native provision JSON onto an account, preserving id, URL, TLS, and profile name.
pub(crate) fn account_from_provision_json(stored: &AccountCfg, parsed: Value) -> Result<AccountCfg> {
    let mut v = parsed;
    patch_user_agent_if_null(&mut v, &stored.profile.behavior.user_agent);
    let p: ProvisionNative =
        serde_json::from_value(v).map_err(|e| anyhow!("provision JSON: {e}"))?;
    Ok(AccountCfg {
        id: stored.id.clone(),
        label: p.label,
        enabled: p.enabled,
        register: p.register,
        retry_s: p.retry_s,
        blf: p.blf,
        profile: Profile {
            name: stored.profile.name.clone(),
            account: p.profile.account,
            behavior: p.profile.behavior,
        },
        provision_url: stored.provision_url.clone(),
        provision_tls_verify: stored.provision_tls_verify,
    })
}

fn patch_user_agent_if_null(v: &mut Value, stored_ua: &str) {
    let Some(behavior) = v.pointer_mut("/profile/behavior") else {
        return;
    };
    if behavior.get("user_agent").is_some_and(|u| u.is_null()) {
        behavior["user_agent"] = json!(stored_ua);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidetone_ua::engine::AccountCfg;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tiny_http::{Header, Response, Server, StatusCode};

    const MIN_XML: &str = r#"<?xml version="1.0"?><sidetone-provision version="1"><account.1.user>2001</account.1.user><account.1.domain>pbx.example.com</account.1.domain><account.1.display_name>Lab</account.1.display_name></sidetone-provision>"#;

    fn user_agent(req: &tiny_http::Request) -> Option<String> {
        req.headers().iter().find_map(|h| {
            h.field
                .equiv("User-Agent")
                .then(|| h.value.as_str().to_string())
        })
    }

    #[test]
    fn sends_sidetone_user_agent() {
        let seen = Arc::new(Mutex::new(None));
        let seen2 = seen.clone();
        let base = run_server(move |req| {
            *seen2.lock().unwrap() = user_agent(&req);
            let _ = req.respond(Response::from_string(MIN_XML));
        });
        fetch_provision(&format!("{base}/cfg.xml"), true).expect("provision");
        let ua = seen.lock().unwrap().clone().unwrap_or_default();
        assert_eq!(ua, format!("Sidetone/{}", env!("CARGO_PKG_VERSION")));
        assert!(!ua.to_ascii_lowercase().contains("ureq"));
    }

    #[test]
    fn rejects_non_http_scheme_without_server() {
        let err = fetch_provision("ftp://example.com/cfg.xml", true).unwrap_err();
        assert!(err.to_string().contains("http or https"));
    }

    #[test]
    fn rejects_oversized_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            let server = Server::from_listener(listener, None).unwrap();
            loop {
                if *stop_t.lock().unwrap() {
                    break;
                }
                if let Ok(Some(req)) = server.recv_timeout(Duration::from_millis(50)) {
                    let big = vec![b'x'; MAX_BODY + 1];
                    let _ = req.respond(Response::from_data(big));
                }
            }
        });
        let url = format!("http://{addr}/big");
        let err = fetch_provision(&url, true).unwrap_err();
        *stop.lock().unwrap() = true;
        assert!(err.to_string().contains("exceeds"));
    }

    fn has_authorization(req: &tiny_http::Request) -> bool {
        req.headers()
            .iter()
            .any(|h| h.field.equiv("Authorization"))
    }

    fn run_server<F: Fn(tiny_http::Request) + Send + 'static>(handler: F) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let server = Server::from_listener(listener, None).unwrap();
            while let Ok(req) = server.recv() {
                handler(req);
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn same_host_redirect_keeps_authorization() {
        let auth_seen = Arc::new(Mutex::new(false));
        let auth_seen2 = auth_seen.clone();
        let base = run_server(move |req| {
            let path = req.url().to_string();
            if path.ends_with("/cfg") && !path.ends_with("/cfg/") {
                let loc = format!("{}/", path);
                let _ = req.respond(
                    Response::empty(StatusCode(302))
                        .with_header(Header::from_bytes("Location", loc.as_bytes()).unwrap()),
                );
                return;
            }
            if path.ends_with("/cfg/") {
                *auth_seen2.lock().unwrap() = has_authorization(&req);
            }
            let _ = req.respond(Response::from_string(MIN_XML));
        });
        let user = "alice";
        let pass = "secret";
        let authed = format!("http://{user}:{pass}@{}", base.trim_start_matches("http://"));
        let authed = format!("{authed}/cfg");
        let _ = fetch_provision(&authed, true).expect("provision");
        assert!(
            *auth_seen.lock().unwrap(),
            "Authorization must reach same-host redirect target"
        );
    }

    #[test]
    fn cross_host_redirect_drops_authorization() {
        let inner_auth = Arc::new(Mutex::new(false));
        let inner_auth2 = inner_auth.clone();
        let inner_base = run_server(move |req| {
            if req.url().ends_with("/final") {
                *inner_auth2.lock().unwrap() = has_authorization(&req);
            }
            let _ = req.respond(Response::from_string(MIN_XML));
        });
        let outer = run_server(move |req| {
            let loc = format!(
                "http://localhost:{}/final",
                inner_base.rsplit(':').next().unwrap()
            );
            let _ = req.respond(
                Response::empty(StatusCode(302))
                    .with_header(Header::from_bytes("Location", loc.as_bytes()).unwrap()),
            );
        });
        let url = format!(
            "http://alice:secret@{}/x",
            outer.trim_start_matches("http://")
        );
        let _ = fetch_provision(&url, true).expect("provision");
        assert!(
            !*inner_auth.lock().unwrap(),
            "Authorization must not follow cross-host redirect"
        );
    }

    #[test]
    fn merge_preserves_id_url_tls_and_name() {
        let mut stored = AccountCfg::default();
        stored.id = "acc-1".into();
        stored.provision_url = Some("http://p/cfg".into());
        stored.provision_tls_verify = false;
        stored.profile.name = "Desk".into();
        stored.profile.behavior.user_agent = "StoredUA/1".into();
        let parsed = json!({
            "label": "L",
            "enabled": true,
            "register": false,
            "retry_s": 5,
            "blf": [],
            "profile": {
                "name": "Ignored",
                "account": { "user": "u", "domain": "d.example" },
                "behavior": { "transport": "udp", "user_agent": null }
            }
        });
        let merged = account_from_provision_json(&stored, parsed).unwrap();
        assert_eq!(merged.id, "acc-1");
        assert_eq!(merged.provision_url.as_deref(), Some("http://p/cfg"));
        assert!(!merged.provision_tls_verify);
        assert_eq!(merged.profile.name, "Desk");
        assert_eq!(merged.profile.behavior.user_agent, "StoredUA/1");
    }

    #[test]
    fn merge_does_not_insert_missing_id() {
        // Documented at phone layer; merge alone always needs stored anchor.
        let stored = AccountCfg::default();
        let parsed = json!({
            "label": "L",
            "enabled": true,
            "register": true,
            "retry_s": 30,
            "blf": [],
            "profile": {
                "name": "n",
                "account": { "user": "u", "domain": "d" },
                "behavior": { "transport": "udp" }
            }
        });
        let merged = account_from_provision_json(&stored, parsed).unwrap();
        assert_eq!(merged.id, stored.id);
    }
}
