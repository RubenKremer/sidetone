//! SIP message builders shared by the blocking test UA and the phone engine.
//! Every behavior knob of the profile that changes the wire format is applied here.

use crate::media::Codec;
use crate::profile::{Behavior, Profile};
use sidetone_core::sip::{self, SipMessage, Uri};
use std::net::{IpAddr, SocketAddr};

pub fn host_str(local: SocketAddr) -> String {
    match local.ip() {
        IpAddr::V6(v6) => format!("[{v6}]:{}", local.port()),
        IpAddr::V4(v4) => format!("{v4}:{}", local.port()),
    }
}

/// Header name, compact form when the profile asks for it.
pub fn hn(b: &Behavior, full: &'static str) -> &'static str {
    if !b.compact_headers {
        return full;
    }
    match full {
        "Via" => "v",
        "From" => "f",
        "To" => "t",
        "Call-ID" => "i",
        "Contact" => "m",
        "Content-Length" => "l",
        "Content-Type" => "c",
        "Supported" => "k",
        "Subject" => "s",
        "Refer-To" => "r",
        "Referred-By" => "b",
        "Event" => "o",
        _ => full,
    }
}

/// Address of record. Without user or domain this is the RFC 3323
/// anonymous form, used by direct (unregistered) calls.
pub fn aor(p: &Profile) -> String {
    let user = if p.account.user.trim().is_empty() {
        "anonymous"
    } else {
        p.account.user.trim()
    };
    let host = sip::split_host_port(&p.account.domain).0;
    let host = if host.is_empty() {
        "anonymous.invalid".to_string()
    } else {
        host
    };
    format!("sip:{user}@{host}")
}

pub fn from_header(p: &Profile, tag: &str) -> String {
    let name = if p.account.user.trim().is_empty() {
        Some("Anonymous".to_string())
    } else {
        p.account.display_name.clone().filter(|n| !n.is_empty())
    };
    let name = name.map(|n| format!("\"{n}\" ")).unwrap_or_default();
    format!("{name}<{}>;tag={tag}", aor(p))
}

pub fn contact(p: &Profile, local: SocketAddr, instance: &str, register: bool) -> String {
    let b = &p.behavior;
    let user = if p.account.user.trim().is_empty() {
        "anonymous"
    } else {
        p.account.user.trim()
    };
    let tp = match crate::transport::Kind::parse(&b.transport) {
        crate::transport::Kind::Udp => "",
        crate::transport::Kind::Tcp => ";transport=tcp",
        crate::transport::Kind::Tls => ";transport=tls",
    };
    let mut c = format!("<sip:{user}@{}{tp}>", host_str(local));
    if register {
        if let Some(q) = &p.account.q_value {
            c.push_str(&format!(";q={q}"));
        }
    }
    if b.long_contact {
        c.push_str(&format!(";+sip.instance=\"<urn:uuid:{instance}>\";reg-id=1;audio;mobility=\"fixed\";duplex=\"full\";description=\"Sidetone\";methods=\"INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,UPDATE,PRACK,REFER,NOTIFY,MESSAGE\""));
    }
    c
}

/// Builds a request. `extra` headers are added after the standard ones.
#[allow(clippy::too_many_arguments)]
pub fn build_request(
    b: &Behavior,
    local: SocketAddr,
    method: &str,
    ruri: &str,
    branch: &str,
    from: &str,
    to: &str,
    call_id: &str,
    cseq: u32,
    cseq_method: &str,
    routes: &[String],
    extra: &[(String, String)],
    body: Option<(&str, &str)>,
) -> String {
    let mut s = format!("{method} {ruri} SIP/2.0\r\n");
    let rport = if b.rport { ";rport" } else { "" };
    s.push_str(&format!(
        "{}: SIP/2.0/{} {};branch={branch}{rport}\r\n",
        hn(b, "Via"),
        crate::transport::Kind::parse(&b.transport).via(),
        host_str(local)
    ));
    s.push_str(&format!("Max-Forwards: {}\r\n", b.max_forwards));
    for r in routes {
        s.push_str(&format!("Route: {r}\r\n"));
    }
    s.push_str(&format!(
        "{}: {from}\r\n{}: {to}\r\n{}: {call_id}\r\nCSeq: {cseq} {cseq_method}\r\n",
        hn(b, "From"),
        hn(b, "To"),
        hn(b, "Call-ID")
    ));
    if let Some(pr) = &b.proxy_require {
        if !pr.is_empty() && method != "ACK" && method != "CANCEL" {
            s.push_str(&format!("Proxy-Require: {pr}\r\n"));
        }
    }
    s.push_str(&format!("User-Agent: {}\r\n", b.user_agent));
    for (k, v) in extra {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    if method != "ACK" && method != "CANCEL" {
        for (k, v) in &b.extra_headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    match body {
        Some((ct, body)) => {
            s.push_str(&format!(
                "{}: {ct}\r\n{}: {}\r\n\r\n{body}",
                hn(b, "Content-Type"),
                hn(b, "Content-Length"),
                body.len()
            ));
        }
        None => s.push_str(&format!("{}: 0\r\n\r\n", hn(b, "Content-Length"))),
    }
    s
}

/// Builds a response that copies the dialog headers of `req`.
#[allow(clippy::too_many_arguments)]
pub fn build_response(
    p: &Profile,
    local: SocketAddr,
    instance: &str,
    req: &SipMessage,
    from: SocketAddr,
    code: u16,
    reason: &str,
    to_tag: Option<&str>,
    extra: &[(String, String)],
    body: Option<(&str, &str)>,
) -> String {
    let mut s = format!("SIP/2.0 {code} {reason}\r\n");
    let mut first_via = true;
    for (k, v) in &req.headers {
        match k.as_str() {
            "Via" => {
                // RFC 3581: fill received/rport on the top Via.
                let mut v2 = v.clone();
                if first_via {
                    if v2.contains(";rport") && !v2.contains(";rport=") {
                        v2 = v2.replacen(";rport", &format!(";rport={}", from.port()), 1);
                    }
                    v2.push_str(&format!(";received={}", from.ip()));
                    first_via = false;
                }
                s.push_str(&format!("Via: {v2}\r\n"));
            }
            "Record-Route" | "From" | "Call-ID" | "CSeq" => s.push_str(&format!("{k}: {v}\r\n")),
            "To" => {
                let has_tag = sip::param(v, "tag").is_some();
                match (has_tag, to_tag, code) {
                    (false, Some(t), c) if c > 100 => s.push_str(&format!("To: {v};tag={t}\r\n")),
                    _ => s.push_str(&format!("To: {v}\r\n")),
                }
            }
            _ => {}
        }
    }
    if (200..300).contains(&code) || (180..190).contains(&code) {
        s.push_str(&format!(
            "Contact: {}\r\n",
            contact(p, local, instance, false)
        ));
    }
    s.push_str(&format!("Server: {}\r\n", p.behavior.user_agent));
    for (k, v) in extra {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    match body {
        Some((ct, b)) => s.push_str(&format!(
            "Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        )),
        None => s.push_str("Content-Length: 0\r\n\r\n"),
    }
    s
}

/// Request URI for a dialed string: full URI, user@host or a bare user/number.
pub fn target_uri(p: &Profile, target: &str) -> String {
    let t = target.trim();
    if t.starts_with("sip:") || t.starts_with("sips:") || t.starts_with("tel:") {
        return t.to_string();
    }
    let (user, host) = match t.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (t.to_string(), p.account.domain.clone()),
    };
    // Visual separators people paste with numbers.
    let numeric_like = user
        .chars()
        .all(|c| c.is_ascii_digit() || " -().+".contains(c));
    let user = if numeric_like {
        user.chars().filter(|c| !" -()".contains(*c)).collect()
    } else {
        user
    };
    let numeric = user
        .trim_start_matches('+')
        .chars()
        .all(|c| c.is_ascii_digit());
    let up = if p.behavior.user_phone && numeric && !user.is_empty() {
        ";user=phone"
    } else {
        ""
    };
    format!("sip:{user}@{host}{up}")
}

/// Remote target URI (without display name or header params) from a Contact value.
pub fn uri_from_contact(v: &str) -> Option<String> {
    let inner = match (v.find('<'), v.find('>')) {
        (Some(a), Some(b)) if b > a => v[a + 1..b].to_string(),
        _ => v.split(';').next().unwrap_or(v).trim().to_string(),
    };
    Uri::parse(&inner)?;
    Some(inner)
}

/// Display name of a From/To header, if any.
pub fn display_name(v: &str) -> Option<String> {
    let lt = v.find('<')?;
    let name = v[..lt].trim().trim_matches('"').trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// SDP offer or answer for one audio stream.
#[allow(clippy::too_many_arguments)]
pub fn sdp_body(
    b: &Behavior,
    rtp: SocketAddr,
    codecs: &[Codec],
    dtmf_pt: Option<u8>,
    direction: &str,
    sess_id: u64,
    version: u64,
) -> String {
    let ip = b
        .sdp_ip_override
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rtp.ip().to_string());
    let fam = if ip.contains(':') { "IP6" } else { "IP4" };
    let mut pts: Vec<String> = codecs.iter().map(|c| c.pt().to_string()).collect();
    if let Some(p) = dtmf_pt {
        pts.push(p.to_string());
    }
    let mut s = format!(
        "v=0\r\no=sidetone {sess_id} {version} IN {fam} {ip}\r\ns=Sidetone\r\nc=IN {fam} {ip}\r\nt=0 0\r\nm=audio {} RTP/AVP {}\r\n",
        rtp.port(),
        pts.join(" ")
    );
    for c in codecs {
        s.push_str(&format!("a=rtpmap:{} {}/8000\r\n", c.pt(), c.name()));
    }
    if let Some(p) = dtmf_pt {
        s.push_str(&format!(
            "a=rtpmap:{p} telephone-event/8000\r\na=fmtp:{p} 0-16\r\n"
        ));
    }
    s.push_str(&format!("a=ptime:{}\r\na={direction}\r\n", b.ptime_ms));
    if !b.rtcp {
        s.push_str(&format!("a=rtcp:{}\r\n", rtp.port() + 1));
    }
    s
}

/// Codecs of the profile in preference order (G.711 only for now).
pub fn profile_codecs(b: &Behavior) -> Vec<Codec> {
    let v: Vec<Codec> = b
        .codecs
        .iter()
        .filter_map(|c| Codec::from_name(c))
        .collect();
    if v.is_empty() {
        vec![Codec::Pcmu, Codec::Pcma]
    } else {
        v
    }
}

/// Splits "target?Hdr=v&Hdr2=v2,123#" into (target, headers, post-answer DTMF).
/// This mirrors the "power dialing" syntax of common softphones.
pub fn parse_dial_string(s: &str) -> (String, Vec<(String, String)>, Option<String>) {
    let s = s.trim();
    let (main, dtmf) = match s.find(',') {
        Some(i) => {
            let d: String = s[i..].chars().filter(|c| *c != ' ').collect();
            (
                s[..i].to_string(),
                if d.is_empty() { None } else { Some(d) },
            )
        }
        None => (s.to_string(), None),
    };
    let mut headers = Vec::new();
    let target = match main.find('?') {
        Some(i) => {
            for kv in main[i + 1..].split('&') {
                if let Some((k, v)) = kv.split_once('=') {
                    if !k.is_empty() {
                        headers.push((pct_decode(k), pct_decode(v)));
                    }
                }
            }
            main[..i].to_string()
        }
        None => main,
    };
    (target.trim().to_string(), headers, dtmf)
}

fn pct_decode(s: &str) -> String {
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

pub fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_string() {
        let (t, h, d) = parse_dial_string("sip:600@pbx?X-Test=a%20b&Subject=hi,,123#");
        assert_eq!(t, "sip:600@pbx");
        assert_eq!(
            h,
            vec![
                ("X-Test".into(), "a b".into()),
                ("Subject".into(), "hi".into())
            ]
        );
        assert_eq!(d.as_deref(), Some(",,123#"));
        let (t, h, d) = parse_dial_string(" 600 ");
        assert_eq!(t, "600");
        assert!(h.is_empty() && d.is_none());
    }

    #[test]
    fn target_uri_cleans_numbers() {
        let mut p = Profile::default();
        p.account.domain = "pbx:5070".into();
        p.behavior.user_phone = true;
        assert_eq!(
            target_uri(&p, "+1 (555) 010-2000"),
            "sip:+15550102000@pbx:5070;user=phone"
        );
        assert_eq!(target_uri(&p, "alice@x"), "sip:alice@x");
        assert_eq!(
            uri_from_contact("\"A\" <sip:a@1.2.3.4:5060;transport=udp>;expires=60").as_deref(),
            Some("sip:a@1.2.3.4:5060;transport=udp")
        );
    }
}
