//! Yealink `.cfg` and Polycom (Poly UC Software) XML → Sidetone account keys.
//!
//! The result is a map of `account.1.*` keys in Sidetone's own vocabulary,
//! which the native parser then validates like a `sidetone-provision` file.
//! Phone configurations carry hundreds of settings that mean nothing to a
//! softphone; those are skipped rather than rejected.

use super::codec_name;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Sidetone,
    Yealink,
    Polycom,
    /// Cisco `SEP<MAC>.cnf.xml` (SIP firmware, as Asterisk, FreeSWITCH or
    /// FreePBX serve it) or the older text `SIP<MAC>.cnf` of the 79xx.
    Cisco,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Sidetone => "Sidetone",
            Format::Yealink => "Yealink",
            Format::Polycom => "Polycom",
            Format::Cisco => "Cisco",
        }
    }
}

/// Recognizes the format from the content.
pub fn detect(text: &str) -> Format {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('<') {
        let lower = t.to_ascii_lowercase();
        if lower.contains("<sidetone-provision") {
            return Format::Sidetone;
        }
        if lower.contains("<siplines") || lower.contains("<sipprofile") {
            return Format::Cisco;
        }
        if lower.contains("<polycomconfig")
            || lower.contains(" reg.1.")
            || lower.contains("voipprot.")
        {
            return Format::Polycom;
        }
        return Format::Sidetone;
    }
    if t.lines().any(|l| {
        let l = l.trim_start().to_ascii_lowercase();
        l.starts_with("line1_name") || l.starts_with("proxy1_address")
    }) {
        return Format::Cisco;
    }
    if t.starts_with("#!version") || t.lines().any(|l| l.trim_start().starts_with("account.")) {
        return Format::Yealink;
    }
    Format::Sidetone
}

fn put(out: &mut HashMap<String, String>, key: &str, v: impl Into<String>) {
    out.insert(format!("account.1.{key}"), v.into());
}

fn with_port(host: &str, port: Option<&str>) -> String {
    match port.map(str::trim).filter(|p| !p.is_empty() && *p != "0") {
        Some(p) if !host.contains(':') => format!("{host}:{p}"),
        _ => host.to_string(),
    }
}

fn on(v: Option<&String>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "enabled")
    )
}

// ---------------------------------------------------------------------------
// Yealink

/// Maps the first configured line of a Yealink `.cfg` (`key = value` lines).
pub fn yealink(text: &str) -> Result<HashMap<String, String>, String> {
    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        kv.insert(k.trim().to_ascii_lowercase(), v);
    }
    let get = |k: &str| kv.get(k).filter(|v| !v.is_empty());
    // The line to use: the first enabled account with a user, else the first with a user.
    let idx = (1..=16)
        .find(|i| {
            on(kv.get(&format!("account.{i}.enable")))
                && get(&format!("account.{i}.user_name")).is_some()
        })
        .or_else(|| (1..=16).find(|i| get(&format!("account.{i}.user_name")).is_some()))
        .ok_or("the Yealink file has no account with a user_name")?;
    let a = |k: &str| get(&format!("account.{idx}.{k}"));
    let mut out = HashMap::new();
    let user = a("user_name").cloned().unwrap_or_default();
    put(&mut out, "user", &user);
    if let Some(v) = a("auth_name") {
        put(&mut out, "auth_user", v);
    }
    if let Some(v) = a("password") {
        put(&mut out, "password", v);
    }
    let label = a("label").cloned();
    if let Some(v) = &label {
        put(&mut out, "label", v);
    }
    let display = a("display_name")
        .or(label.as_ref())
        .cloned()
        .unwrap_or(user.clone());
    put(&mut out, "display_name", display);
    if kv.contains_key(&format!("account.{idx}.enable")) {
        put(
            &mut out,
            "enabled",
            if on(kv.get(&format!("account.{idx}.enable"))) {
                "1"
            } else {
                "0"
            },
        );
    }

    // Server: current firmware (sip_server.1.*) or the older sip_server_host.
    let transport = a("sip_server.1.transport_type")
        .or(a("transport"))
        .map(String::as_str);
    let naptr = transport == Some("3");
    let host = a("sip_server.1.address").or(a("sip_server_host"));
    let port = a("sip_server.1.port").or(a("sip_server_port"));
    match host {
        Some(h) => put(
            &mut out,
            "domain",
            if naptr {
                h.clone()
            } else {
                with_port(h, port.map(String::as_str))
            },
        ),
        None => {
            return Err(format!(
                "the Yealink file has no SIP server for account.{idx}"
            ))
        }
    }
    if let Some(t) = transport {
        put(
            &mut out,
            "transport",
            match t {
                "1" => "tcp",
                "2" => "tls",
                _ => "udp",
            },
        );
    }
    if let Some(e) = a("sip_server.1.expires").or(a("expires")) {
        put(&mut out, "expires", e);
    }
    if on(kv.get(&format!("account.{idx}.outbound_proxy_enable"))) {
        if let Some(h) = a("outbound_proxy.1.address").or(a("outbound_host")) {
            let p = a("outbound_proxy.1.port").or(a("outbound_port"));
            put(
                &mut out,
                "outbound_proxy",
                with_port(h, p.map(String::as_str)),
            );
        }
    }
    if let Some(t) = a("dtmf.type") {
        put(
            &mut out,
            "dtmf_mode",
            match t.as_str() {
                "0" => "inband",
                "2" | "3" => "info",
                _ => "rfc4733",
            },
        );
    }
    if let Some(p) = a("dtmf.dtmf_payload") {
        put(&mut out, "dtmf_payload_type", p);
    }
    if let Some(s) = a("srtp_encryption") {
        put(
            &mut out,
            "srtp",
            match s.as_str() {
                "1" => "optional",
                "2" => "mandatory",
                _ => "off",
            },
        );
    }
    if let Some(r) = a("nat.rport") {
        put(&mut out, "rport", if r == "0" { "0" } else { "1" });
    }
    if on(kv.get(&format!("account.{idx}.session_timer.enable"))) {
        put(
            &mut out,
            "session_timer",
            a("session_timer.expires").cloned().unwrap_or("1800".into()),
        );
    }
    if let Some(m) = a("subscribe_mwi") {
        put(&mut out, "mwi", if m == "0" { "0" } else { "1" });
    }
    if let Some(n) = get(&format!("voice_mail.number.{idx}")) {
        put(&mut out, "voicemail", n);
    }

    // Codecs: enabled entries by priority.
    let mut codecs: Vec<(u32, &'static str)> = Vec::new();
    for n in 1..=32 {
        let Some(name) = a(&format!("codec.{n}.payload_type")) else {
            continue;
        };
        if !on(kv.get(&format!("account.{idx}.codec.{n}.enable"))) {
            continue;
        }
        if let Some(c) = codec_name(name) {
            let prio = a(&format!("codec.{n}.priority"))
                .and_then(|p| p.parse().ok())
                .unwrap_or(100 + n);
            codecs.push((prio, c));
        }
    }
    codecs.sort_by_key(|c| c.0);
    let mut seen = Vec::new();
    for (_, c) in codecs {
        if !seen.contains(&c) {
            seen.push(c);
            put(&mut out, &format!("codec.{}", seen.len()), c);
        }
    }

    // BLF line keys (type 16) on this line.
    let mut blf = Vec::new();
    for n in 1..=100 {
        let k = |f: &str| get(&format!("linekey.{n}.{f}"));
        if k("type").map(String::as_str) == Some("16") {
            let line_ok = k("line")
                .map(|l| l == &idx.to_string() || l == "0")
                .unwrap_or(true);
            if let (true, Some(v)) = (line_ok, k("value")) {
                blf.push(v.clone());
            }
        }
    }
    for (i, b) in blf.iter().enumerate() {
        put(&mut out, &format!("blf.{}", i + 1), b);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Polycom

/// Every attribute of every element, keys lower-cased (Poly keys are dotted
/// names carried as attributes, spread over any element layout).
fn polycom_attrs(xml: &str) -> Result<HashMap<String, String>, String> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("DOCTYPE or ENTITY declarations are not allowed".into());
    }
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut out = HashMap::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                for a in e.attributes().flatten() {
                    let k = String::from_utf8_lossy(a.key.as_ref()).to_ascii_lowercase();
                    let v = a
                        .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                        .map(|v| v.into_owned())
                        .map_err(|e| format!("malformed XML: {e}"))?;
                    out.insert(k, v);
                }
            }
            Ok(Event::DocType(_)) => return Err("DOCTYPE is not allowed".into()),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(format!("malformed XML: {e}")),
        }
        buf.clear();
    }
    Ok(out)
}

/// Maps the first registration (`reg.N`) of a Polycom configuration.
pub fn polycom(xml: &str) -> Result<HashMap<String, String>, String> {
    let kv = polycom_attrs(xml)?;
    let get = |k: &str| {
        kv.get(&k.to_ascii_lowercase())
            .filter(|v| !v.trim().is_empty())
    };
    let idx = (1..=34)
        .find(|i| get(&format!("reg.{i}.address")).is_some())
        .ok_or("the Polycom file has no reg.N.address")?;
    let r = |k: &str| get(&format!("reg.{idx}.{k}"));
    let mut out = HashMap::new();

    let address = r("address").cloned().unwrap_or_default();
    let (user, addr_host) = match address.split_once('@') {
        Some((u, h)) => (
            u.trim_start_matches("sip:").to_string(),
            Some(h.to_string()),
        ),
        None => (address.trim_start_matches("sip:").to_string(), None),
    };
    put(&mut out, "user", &user);
    if let Some(v) = r("auth.userId") {
        put(&mut out, "auth_user", v);
    }
    if let Some(v) = r("auth.password") {
        put(&mut out, "password", v);
    }
    let label = r("label").cloned();
    if let Some(v) = &label {
        put(&mut out, "label", v);
    }
    put(
        &mut out,
        "display_name",
        r("displayName")
            .or(label.as_ref())
            .cloned()
            .unwrap_or(user.clone()),
    );

    let server = |k: &str| r(&format!("server.1.{k}")).or(get(&format!("voIpProt.server.1.{k}")));
    let transport = server("transport").map(|t| t.to_ascii_lowercase());
    let naptr = transport.as_deref() == Some("dnsnaptr");
    let host = server("address").cloned().or(addr_host);
    match host {
        Some(h) => put(
            &mut out,
            "domain",
            if naptr {
                h
            } else {
                with_port(&h, server("port").map(String::as_str))
            },
        ),
        None => return Err(format!("the Polycom file has no server for reg.{idx}")),
    }
    if let Some(t) = &transport {
        put(
            &mut out,
            "transport",
            if t.starts_with("tls") {
                "tls"
            } else if t.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            },
        );
    }
    if let Some(e) = server("expires") {
        put(&mut out, "expires", e);
    }
    let proxy = r("outboundProxy.address").or(get("voIpProt.SIP.outboundProxy.address"));
    if let Some(h) = proxy {
        let p = r("outboundProxy.port").or(get("voIpProt.SIP.outboundProxy.port"));
        put(
            &mut out,
            "outbound_proxy",
            with_port(h, p.map(String::as_str)),
        );
    }
    if on(kv.get("sec.srtp.require")) {
        put(&mut out, "srtp", "mandatory");
    } else if on(kv.get("sec.srtp.enable")) && on(kv.get("sec.srtp.offer")) {
        put(&mut out, "srtp", "optional");
    }
    if on(kv.get("voipprot.sip.dtmfviasignaling.rfc2976")) {
        put(&mut out, "dtmf_mode", "info");
    }
    if let Some(p) = get("tone.dtmf.rfc2833Payload") {
        put(&mut out, "dtmf_payload_type", p);
    }
    if let Some(m) = get(&format!("msg.mwi.{idx}.subscribe")) {
        let _ = m;
        put(&mut out, "mwi", "1");
    }
    if let Some(n) = get(&format!("msg.mwi.{idx}.callBack")) {
        put(&mut out, "voicemail", n);
    }

    // voice.codecPref.<name> = priority (0 or empty: off).
    let mut codecs: Vec<(u32, &'static str)> = Vec::new();
    for (k, v) in &kv {
        let Some(name) = k.strip_prefix("voice.codecpref.") else {
            continue;
        };
        let Ok(prio) = v.trim().parse::<u32>() else {
            continue;
        };
        if prio == 0 {
            continue;
        }
        let c = match name {
            "g711_mu" => Some("PCMU"),
            "g711_a" => Some("PCMA"),
            "g722" => Some("G722"),
            "g729_ab" | "g729" => Some("G729"),
            n if n.starts_with("ilbc") => Some("iLBC"),
            "opus" => Some("opus"),
            "lin16.8ksps" => Some("L16/8000"),
            "lin16.16ksps" => Some("L16/16000"),
            "lin16.44_1ksps" => Some("L16/44100"),
            _ => None,
        };
        if let Some(c) = c {
            codecs.push((prio, c));
        }
    }
    codecs.sort();
    let mut seen = Vec::new();
    for (_, c) in codecs {
        if !seen.contains(&c) {
            seen.push(c);
            put(&mut out, &format!("codec.{}", seen.len()), c);
        }
    }

    // Busy lamp list: attendant.resourceList.N.address.
    let mut blf = Vec::new();
    for n in 1..=100 {
        if let Some(a) = get(&format!("attendant.resourceList.{n}.address")) {
            blf.push(a.clone());
        }
    }
    for (i, b) in blf.iter().enumerate() {
        put(&mut out, &format!("blf.{}", i + 1), b);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Cisco

/// Maps the first SIP line of a Cisco configuration, XML or the old text form.
pub fn cisco(text: &str) -> Result<HashMap<String, String>, String> {
    if text.trim_start().starts_with('<') {
        cisco_xml(text)
    } else {
        cisco_text(text)
    }
}

/// Text of every element by its path (`device/sipProfile/...`), first value
/// wins, plus the children of each `<line>` in order.
type CiscoDoc = (HashMap<String, String>, Vec<HashMap<String, String>>);

fn cisco_collect(xml: &str) -> Result<CiscoDoc, String> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("DOCTYPE or ENTITY declarations are not allowed".into());
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut paths: HashMap<String, String> = HashMap::new();
    let mut lines: Vec<HashMap<String, String>> = Vec::new();
    let mut line_depth: Option<usize> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_ascii_lowercase();
                path.push(name.clone());
                if name == "line" && line_depth.is_none() {
                    line_depth = Some(path.len());
                    let mut m = HashMap::new();
                    for a in e.attributes().flatten() {
                        let k = String::from_utf8_lossy(a.key.as_ref()).to_ascii_lowercase();
                        if let Ok(v) = a.normalized_value(quick_xml::XmlVersion::Explicit1_0) {
                            m.insert(format!("@{k}"), v.into_owned());
                        }
                    }
                    lines.push(m);
                }
            }
            Ok(Event::Text(t)) => {
                let v = t
                    .decode()
                    .map_err(|e| format!("malformed XML: {e}"))?
                    .into_owned();
                let key = path.join("/");
                paths.entry(key).or_insert(v.clone());
                if let (Some(d), Some(l)) = (line_depth, lines.last_mut()) {
                    if path.len() == d + 1 {
                        l.entry(path[d].clone()).or_insert(v);
                    }
                }
            }
            Ok(Event::End(_)) => {
                if line_depth == Some(path.len()) {
                    line_depth = None;
                }
                path.pop();
            }
            Ok(Event::DocType(_)) => return Err("DOCTYPE is not allowed".into()),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(format!("malformed XML: {e}")),
        }
        buf.clear();
    }
    Ok((paths, lines))
}

fn cisco_xml(xml: &str) -> Result<HashMap<String, String>, String> {
    let (paths, lines) = cisco_collect(xml)?;
    let find = |suffix: &str| {
        let suffix = suffix.to_ascii_lowercase();
        paths
            .iter()
            .filter(|(k, v)| {
                (k.ends_with(&format!("/{suffix}")) || **k == suffix) && !v.trim().is_empty()
            })
            .min_by_key(|(k, _)| k.len())
            .map(|(_, v)| v.trim().to_string())
    };
    // A line key (featureID 9, or no featureID) with a user name.
    let line = lines
        .iter()
        .find(|l| {
            l.get("featureid").is_none_or(|f| f.trim() == "9")
                && l.get("name").is_some_and(|n| !n.trim().is_empty())
        })
        .ok_or("the Cisco file has no SIP line with a name")?;
    let l = |k: &str| {
        line.get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let mut out = HashMap::new();
    let user = l("name").unwrap_or_default();
    put(&mut out, "user", &user);
    if let Some(v) = l("authname") {
        put(&mut out, "auth_user", v);
    }
    if let Some(v) = l("authpassword") {
        put(&mut out, "password", v);
    }
    let label = l("featurelabel");
    if let Some(v) = &label {
        put(&mut out, "label", v);
    }
    put(
        &mut out,
        "display_name",
        l("displayname").or(label).unwrap_or(user.clone()),
    );
    // The line's own proxy, or the call manager ("USECALLMANAGER").
    let proxy = l("proxy").filter(|p| !p.eq_ignore_ascii_case("usecallmanager"));
    let (host, port) = match proxy {
        Some(p) => (Some(p), l("port")),
        None => (find("processNodeName"), find("sipPort").or(l("port"))),
    };
    match host {
        Some(h) => put(&mut out, "domain", with_port(&h, port.as_deref())),
        None => return Err("the Cisco file has no proxy or processNodeName".into()),
    }
    // transportLayerProtocol: 1 TCP, 2 UDP, 4 TLS.
    if let Some(t) = find("transportLayerProtocol") {
        put(
            &mut out,
            "transport",
            match t.as_str() {
                "1" => "tcp",
                "4" => "tls",
                _ => "udp",
            },
        );
    }
    if let Some(e) = find("registerExpires").or(find("timerRegisterExpires")) {
        put(&mut out, "expires", e);
    }
    if let Some(p) = find("outboundProxy").filter(|p| !p.eq_ignore_ascii_case("usecallmanager")) {
        let port = find("outboundProxyPort");
        put(&mut out, "outbound_proxy", with_port(&p, port.as_deref()));
    }
    if let Some(n) = l("messagesnumber").or(find("messagesNumber")) {
        put(&mut out, "voicemail", n);
    }
    if let Some(v) = find("dtmfAvtPayload") {
        put(&mut out, "dtmf_payload_type", v);
    }
    // Speed dials with BLF (featureID 21) watch other extensions.
    let mut blf = Vec::new();
    for x in &lines {
        if x.get("featureid").map(|f| f.trim()) == Some("21") {
            if let Some(v) = x
                .get("speeddialnumber")
                .or(x.get("name"))
                .filter(|v| !v.trim().is_empty())
            {
                blf.push(v.trim().to_string());
            }
        }
    }
    for (i, b) in blf.iter().enumerate() {
        put(&mut out, &format!("blf.{}", i + 1), b);
    }
    Ok(out)
}

/// The 79xx text form: `key: value` (or `key value`), `#` comments.
fn cisco_text(text: &str) -> Result<HashMap<String, String>, String> {
    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let (k, v) = match l.split_once(':') {
            Some((k, v)) => (k, v),
            None => match l.split_once(char::is_whitespace) {
                Some(x) => x,
                None => continue,
            },
        };
        let v = v.trim().trim_matches('"').to_string();
        kv.insert(k.trim().to_ascii_lowercase(), v);
    }
    let get = |k: &str| {
        kv.get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v != "UNPROVISIONED")
    };
    let idx = (1..=6)
        .find(|i| get(&format!("line{i}_name")).is_some())
        .ok_or("the Cisco file has no lineN_name")?;
    let mut out = HashMap::new();
    let user = get(&format!("line{idx}_name")).unwrap_or_default();
    put(&mut out, "user", &user);
    if let Some(v) = get(&format!("line{idx}_authname")) {
        put(&mut out, "auth_user", v);
    }
    if let Some(v) = get(&format!("line{idx}_password")) {
        put(&mut out, "password", v);
    }
    let label = get(&format!("line{idx}_shortname"));
    if let Some(v) = &label {
        put(&mut out, "label", v);
    }
    put(
        &mut out,
        "display_name",
        get(&format!("line{idx}_displayname"))
            .or(label)
            .unwrap_or(user.clone()),
    );
    let host = get(&format!("proxy{idx}_address")).or(get("proxy1_address"));
    let port = get(&format!("proxy{idx}_port")).or(get("proxy1_port"));
    match host {
        Some(h) => put(&mut out, "domain", with_port(&h, port.as_deref())),
        None => return Err("the Cisco file has no proxyN_address".into()),
    }
    if let Some(p) = get("outbound_proxy") {
        put(
            &mut out,
            "outbound_proxy",
            with_port(&p, get("outbound_proxy_port").as_deref()),
        );
    }
    if let Some(e) = get("timer_register_expires") {
        put(&mut out, "expires", e);
    }
    if let Some(n) = get("messages_uri") {
        put(&mut out, "voicemail", n);
    }
    if let Some(v) = get("dtmf_avt_payload") {
        put(&mut out, "dtmf_payload_type", v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;

    const YEALINK: &str = "#!version:1.0.0.1
## Yealink T54W, account 1 empty, account 2 in use
account.1.enable = 0
account.2.enable = 1
account.2.label = Reception
account.2.display_name = Front desk
account.2.auth_name = 2001
account.2.user_name = 2001
account.2.password = secret
account.2.sip_server.1.address = pbx.example.com
account.2.sip_server.1.port = 5061
account.2.sip_server.1.transport_type = 2
account.2.sip_server.1.expires = 600
account.2.dtmf.type = 1
account.2.srtp_encryption = 1
account.2.subscribe_mwi = 1
voice_mail.number.2 = *97
account.2.codec.1.enable = 1
account.2.codec.1.payload_type = PCMU
account.2.codec.1.priority = 2
account.2.codec.2.enable = 1
account.2.codec.2.payload_type = G722
account.2.codec.2.priority = 1
account.2.codec.3.enable = 0
account.2.codec.3.payload_type = G729
account.2.codec.4.enable = 1
account.2.codec.4.payload_type = AMR-WB
linekey.1.type = 16
linekey.1.line = 2
linekey.1.value = 3001
lcd_logo.mode = 1
";

    const POLYCOM: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<polycomConfig xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <reg reg.1.address="2001" reg.1.label="2001" reg.1.displayName="Lab 2001"
       reg.1.auth.userId="2001" reg.1.auth.password="secret"
       reg.1.server.1.address="pbx.example.com" reg.1.server.1.port="5060"
       reg.1.server.1.transport="TCPOnly" reg.1.server.1.expires="3600"/>
  <msg msg.mwi.1.subscribe="2001" msg.mwi.1.callBack="*97" msg.mwi.1.callBackMode="contact"/>
  <voice voice.codecPref.G711_Mu="2" voice.codecPref.G711_A="3" voice.codecPref.G722="1" voice.codecPref.G729_AB="0" voice.codecPref.Siren14.48ksps="4"/>
  <attendant attendant.resourceList.1.address="3001" attendant.resourceList.1.label="Ana"/>
  <device device.set="1"/>
</polycomConfig>"#;

    const CISCO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<device>
  <deviceProtocol>SIP</deviceProtocol>
  <devicePool>
    <callManagerGroup><members><member priority="0"><callManager>
      <ports><ethernetPhonePort>2000</ethernetPhonePort><sipPort>5070</sipPort></ports>
      <processNodeName>10.0.0.5</processNodeName>
    </callManager></member></members></callManagerGroup>
  </devicePool>
  <sipProfile>
    <sipCallFeatures><dtmfAvtPayload>101</dtmfAvtPayload></sipCallFeatures>
    <sipStack><timerRegisterExpires>3600</timerRegisterExpires></sipStack>
    <sipLines>
      <line button="1">
        <featureID>9</featureID>
        <featureLabel>Desk 2001</featureLabel>
        <proxy>USECALLMANAGER</proxy>
        <port>5060</port>
        <name>2001</name>
        <displayName>Lab 2001</displayName>
        <authName>2001</authName>
        <authPassword>secret</authPassword>
        <messagesNumber>*97</messagesNumber>
      </line>
      <line button="2">
        <featureID>21</featureID>
        <featureLabel>Ana</featureLabel>
        <speedDialNumber>3001</speedDialNumber>
      </line>
    </sipLines>
  </sipProfile>
  <transportLayerProtocol>1</transportLayerProtocol>
</device>"#;

    const CISCO_TEXT: &str = "# SIP0011223344.cnf
image_version: P0S3-8-12-00
proxy1_address: 10.0.0.5
proxy1_port: 5060
line1_name: 2001
line1_authname: 2001
line1_password: secret
line1_displayname: \"Lab 2001\"
line2_name: UNPROVISIONED
messages_uri: *97
";

    #[test]
    fn cisco_xml_first_line() {
        assert_eq!(detect(CISCO), Format::Cisco);
        let v = parse(CISCO, "native").unwrap();
        let a = &v["profile"]["account"];
        assert_eq!(a["user"], "2001");
        assert_eq!(a["password"], "secret");
        assert_eq!(a["display_name"], "Lab 2001");
        assert_eq!(a["domain"], "10.0.0.5:5070");
        assert_eq!(a["expires"], 3600);
        assert_eq!(v["label"], "Desk 2001");
        assert_eq!(v["profile"]["behavior"]["transport"], "tcp");
        assert_eq!(v["blf"], serde_json::json!(["3001"]));
        assert_eq!(v["voicemail"], "*97");
    }

    #[test]
    fn cisco_text_form() {
        assert_eq!(detect(CISCO_TEXT), Format::Cisco);
        let v = parse(CISCO_TEXT, "native").unwrap();
        let a = &v["profile"]["account"];
        assert_eq!(a["user"], "2001");
        assert_eq!(a["auth_user"], "2001");
        assert_eq!(a["display_name"], "Lab 2001");
        assert_eq!(a["domain"], "10.0.0.5:5060");
        assert_eq!(v["voicemail"], "*97");
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect(YEALINK), Format::Yealink);
        assert_eq!(detect(POLYCOM), Format::Polycom);
        assert_eq!(
            detect("<sidetone-provision version=\"1\"/>"),
            Format::Sidetone
        );
    }

    #[test]
    fn yealink_line_two() {
        let v = parse(YEALINK, "native").unwrap();
        let a = &v["profile"]["account"];
        let b = &v["profile"]["behavior"];
        assert_eq!(a["user"], "2001");
        assert_eq!(a["display_name"], "Front desk");
        assert_eq!(a["domain"], "pbx.example.com:5061");
        assert_eq!(a["expires"], 600);
        assert_eq!(v["label"], "Reception");
        assert_eq!(b["transport"], "tls");
        assert_eq!(b["srtp"], "optional");
        assert_eq!(b["codecs"], serde_json::json!(["G722", "PCMU"]));
        assert_eq!(v["blf"], serde_json::json!(["3001"]));
        assert_eq!(v["mwi"], true);
        assert_eq!(v["voicemail"], "*97");
    }

    #[test]
    fn polycom_reg_one() {
        let v = parse(POLYCOM, "native").unwrap();
        let a = &v["profile"]["account"];
        let b = &v["profile"]["behavior"];
        assert_eq!(a["user"], "2001");
        assert_eq!(a["auth_user"], "2001");
        assert_eq!(a["display_name"], "Lab 2001");
        assert_eq!(a["domain"], "pbx.example.com:5060");
        assert_eq!(a["expires"], 3600);
        assert_eq!(b["transport"], "tcp");
        assert_eq!(b["codecs"], serde_json::json!(["G722", "PCMU", "PCMA"]));
        assert_eq!(v["blf"], serde_json::json!(["3001"]));
        assert_eq!(v["voicemail"], "*97");
    }

    #[test]
    fn vendor_files_need_the_desktop_app_in_the_browser() {
        assert!(parse(YEALINK, "browser").unwrap_err().contains("Yealink"));
    }

    #[test]
    fn polycom_doctype_rejected() {
        let x = r#"<!DOCTYPE x [<!ENTITY e "x">]><polycomConfig><reg reg.1.address="1"/></polycomConfig>"#;
        assert!(parse(x, "native").unwrap_err().contains("DOCTYPE"));
    }
}
