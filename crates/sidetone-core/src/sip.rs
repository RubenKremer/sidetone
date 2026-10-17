//! Tolerant SIP message parser (RFC 3261), built for troubleshooting:
//! it keeps the raw text, accepts sloppy line endings and never panics.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum StartLine {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct SipMessage {
    pub start: StartLine,
    /// Headers in wire order with canonical names (compact forms expanded).
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub raw: String,
    /// Problems noticed while parsing (bad Content-Length, folded lines...).
    pub parse_notes: Vec<String>,
}

const METHODS: &[&str] = &[
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
];

/// Headers whose values contain commas that are not list separators.
const NON_LIST_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "date",
    "user-agent",
    "server",
    "subject",
    "identity",
    "warning",
    "reason",
];

pub fn canonical_header(name: &str) -> String {
    let n = name.trim();
    let full = match n.to_ascii_lowercase().as_str() {
        "i" => "Call-ID",
        "m" => "Contact",
        "e" => "Content-Encoding",
        "l" => "Content-Length",
        "c" => "Content-Type",
        "f" => "From",
        "s" => "Subject",
        "k" => "Supported",
        "t" => "To",
        "v" => "Via",
        "o" => "Event",
        "u" => "Allow-Events",
        "r" => "Refer-To",
        "b" => "Referred-By",
        "x" => "Session-Expires",
        "a" => "Accept-Contact",
        "j" => "Reject-Contact",
        "d" => "Request-Disposition",
        "y" => "Identity",
        "n" => "Identity-Info",
        "call-id" => "Call-ID",
        "cseq" => "CSeq",
        "www-authenticate" => "WWW-Authenticate",
        "rack" => "RAck",
        "rseq" => "RSeq",
        "mime-version" => "MIME-Version",
        _ => {
            // Title-Case each dash-separated token.
            return n
                .split('-')
                .map(|t| {
                    let mut c = t.chars();
                    match c.next() {
                        Some(f) => {
                            f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase()
                        }
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join("-");
        }
    };
    full.to_string()
}

/// Quick check whether a payload starts like a SIP message.
pub fn looks_like_sip(b: &[u8]) -> bool {
    let b = trim_leading_crlf(b);
    if b.starts_with(b"SIP/2.0 ") {
        return true;
    }
    let first_line_end = b
        .iter()
        .position(|&c| c == b'\n')
        .unwrap_or(b.len())
        .min(512);
    let line = &b[..first_line_end];
    let line = std::str::from_utf8(line).unwrap_or("");
    let mut parts = line.split(' ');
    let m = parts.next().unwrap_or("");
    METHODS.contains(&m) && line.trim_end().ends_with("SIP/2.0")
}

fn trim_leading_crlf(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if c == b'\r' || c == b'\n' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn find_header_end(b: &[u8]) -> Option<(usize, usize)> {
    // Returns (end of headers, start of body).
    if let Some(p) = find(b, b"\r\n\r\n") {
        return Some((p, p + 4));
    }
    find(b, b"\n\n").map(|p| (p, p + 2))
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Parses one SIP message from a datagram (UDP): the body is the remainder
/// unless Content-Length says otherwise.
pub fn parse_datagram(b: &[u8]) -> Option<SipMessage> {
    parse_one(b, false).map(|(m, _)| m)
}

/// Parses as many complete SIP messages as possible from a stream buffer
/// (TCP/TLS/WebSocket). Returns messages and the number of bytes consumed.
pub fn parse_stream(b: &[u8]) -> (Vec<SipMessage>, usize) {
    let mut out = Vec::new();
    let mut consumed = 0;
    loop {
        let rest = &b[consumed..];
        let lead = rest.len() - trim_leading_crlf(rest).len();
        if lead == rest.len() {
            consumed += lead;
            break;
        }
        match parse_one(&rest[lead..], true) {
            Some((m, used)) => {
                out.push(m);
                consumed += lead + used;
            }
            None => break,
        }
    }
    (out, consumed)
}

fn parse_one(b: &[u8], stream: bool) -> Option<(SipMessage, usize)> {
    let b = trim_leading_crlf(b);
    if !looks_like_sip(b) {
        return None;
    }
    let (hend, bstart) = match find_header_end(b) {
        Some(x) => x,
        None if !stream => (b.len(), b.len()),
        None => return None,
    };
    let head = String::from_utf8_lossy(&b[..hend]).into_owned();
    let mut notes = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for l in head.split('\n') {
        let l = l.strip_suffix('\r').unwrap_or(l);
        if (l.starts_with(' ') || l.starts_with('\t')) && !lines.is_empty() {
            let last = lines.last_mut().unwrap();
            last.push(' ');
            last.push_str(l.trim());
            if !notes.iter().any(|n: &String| n.contains("folded")) {
                notes
                    .push("header line folding used (obsolete in RFC 3261 implementations)".into());
            }
        } else {
            lines.push(l.to_string());
        }
    }
    if lines.is_empty() {
        return None;
    }
    let first = lines.remove(0);
    let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
        let mut it = rest.splitn(2, ' ');
        let code = it.next()?.trim().parse::<u16>().ok()?;
        StartLine::Response {
            code,
            reason: it.next().unwrap_or("").trim().to_string(),
        }
    } else {
        let mut it = first.split(' ');
        let method = it.next()?.to_string();
        let uri = it.next().unwrap_or("").to_string();
        StartLine::Request { method, uri }
    };
    let mut headers = Vec::new();
    for l in lines {
        if l.trim().is_empty() {
            continue;
        }
        if let Some(idx) = l.find(':') {
            let name = canonical_header(&l[..idx]);
            headers.push((name, l[idx + 1..].trim().to_string()));
        } else {
            notes.push(format!("malformed header line: {l}"));
        }
    }
    let clen = headers
        .iter()
        .find(|(n, _)| n == "Content-Length")
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());
    let avail = b.len().saturating_sub(bstart);
    let body_len = match clen {
        Some(n) if n <= avail => {
            if !stream && n < avail && b[bstart + n..].iter().any(|c| !c.is_ascii_whitespace()) {
                notes.push(format!(
                    "Content-Length {n} is smaller than the body actually received ({avail} bytes)"
                ));
            }
            n
        }
        Some(n) => {
            if stream {
                return None; // wait for more data
            }
            notes.push(format!(
                "Content-Length {n} is larger than the body received ({avail} bytes)"
            ));
            avail
        }
        None => {
            if stream {
                notes.push(
                    "Content-Length missing on a stream transport (mandatory over TCP/TLS)".into(),
                );
                0
            } else {
                avail
            }
        }
    };
    let body = String::from_utf8_lossy(&b[bstart..bstart + body_len]).into_owned();
    let used = bstart + body_len;
    let raw = String::from_utf8_lossy(&b[..used]).into_owned();
    // Compute how many bytes we consumed relative to the untrimmed input in parse_stream.
    Some((
        SipMessage {
            start,
            headers,
            body,
            raw,
            parse_notes: notes,
        },
        used,
    ))
}

impl SipMessage {
    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match &self.start {
            StartLine::Response { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn request_uri(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { uri, .. } => Some(uri),
            _ => None,
        }
    }

    /// First value of a header (case-insensitive name match).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of a header, splitting comma-separated lists where valid.
    pub fn header_values(&self, name: &str) -> Vec<String> {
        let split = !NON_LIST_HEADERS.contains(&name.to_ascii_lowercase().as_str());
        let mut out = Vec::new();
        for (n, v) in &self.headers {
            if n.eq_ignore_ascii_case(name) {
                if split {
                    out.extend(split_list(v));
                } else {
                    out.push(v.clone());
                }
            }
        }
        out
    }

    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID")
    }

    /// CSeq number and method.
    pub fn cseq(&self) -> Option<(u32, String)> {
        let v = self.header("CSeq")?;
        let mut it = v.split_whitespace();
        let n = it.next()?.parse().ok()?;
        Some((n, it.next().unwrap_or("").to_string()))
    }

    pub fn top_via(&self) -> Option<Via> {
        self.header_values("Via")
            .first()
            .and_then(|v| Via::parse(v))
    }

    pub fn from_tag(&self) -> Option<String> {
        self.header("From").and_then(|v| param(v, "tag"))
    }

    pub fn to_tag(&self) -> Option<String> {
        self.header("To").and_then(|v| param(v, "tag"))
    }

    pub fn content_type(&self) -> Option<String> {
        self.header("Content-Type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
    }

    pub fn has_sdp(&self) -> bool {
        !self.body.trim().is_empty()
            && (self.content_type().as_deref() == Some("application/sdp")
                || (self.content_type().is_none() && self.body.trim_start().starts_with("v=0")))
    }

    /// Short human summary, e.g. "INVITE sip:100@pbx" or "200 OK (INVITE)".
    pub fn summary(&self) -> String {
        match &self.start {
            StartLine::Request { method, uri } => format!("{method} {uri}"),
            StartLine::Response { code, reason } => {
                let m = self.cseq().map(|c| c.1).unwrap_or_default();
                format!("{code} {reason} ({m})")
            }
        }
    }

    /// Label for ladder arrows: method, or code plus reason.
    pub fn label(&self) -> String {
        let sdp = if self.has_sdp() { " (SDP)" } else { "" };
        match &self.start {
            StartLine::Request { method, .. } => format!("{method}{sdp}"),
            StartLine::Response { code, reason } => format!("{code} {reason}{sdp}"),
        }
    }
}

/// Splits a header value on commas that are not inside quotes or angle brackets.
pub fn split_list(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    let mut angle = 0i32;
    for ch in v.chars() {
        match ch {
            '"' => {
                q = !q;
                cur.push(ch);
            }
            '<' if !q => {
                angle += 1;
                cur.push(ch);
            }
            '>' if !q => {
                angle -= 1;
                cur.push(ch);
            }
            ',' if !q && angle <= 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Reads a `;name=value` parameter from a header value (outside the URI brackets).
pub fn param(v: &str, name: &str) -> Option<String> {
    let after = match v.rfind('>') {
        Some(i) => &v[i + 1..],
        None => v,
    };
    for p in after.split(';').skip(1) {
        let mut kv = p.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim();
        if k.eq_ignore_ascii_case(name) {
            return Some(kv.next().unwrap_or("").trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Has a flag-style parameter like `;rport` or `;lr`.
pub fn has_param(v: &str, name: &str) -> bool {
    let after = match v.rfind('>') {
        Some(i) => &v[i + 1..],
        None => v,
    };
    after.split(';').skip(1).any(|p| {
        p.split('=')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case(name)
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Via {
    pub transport: String,
    pub host: String,
    pub port: Option<u16>,
    pub branch: Option<String>,
    pub received: Option<String>,
    pub rport: Option<String>,
}

impl Via {
    pub fn parse(v: &str) -> Option<Via> {
        // SIP/2.0/UDP host:port;branch=...;received=...;rport=...
        let mut it = v.splitn(2, char::is_whitespace);
        let proto = it.next()?;
        let rest = it.next().unwrap_or("").trim();
        let transport = proto.rsplit('/').next().unwrap_or("").to_ascii_uppercase();
        let sent_by = rest.split(';').next().unwrap_or("").trim();
        let (host, port) = split_host_port(sent_by);
        let get = |n: &str| -> Option<String> {
            rest.split(';').skip(1).find_map(|p| {
                let mut kv = p.splitn(2, '=');
                let k = kv.next()?.trim();
                if k.eq_ignore_ascii_case(n) {
                    Some(kv.next().unwrap_or("").trim().to_string())
                } else {
                    None
                }
            })
        };
        Some(Via {
            transport,
            host,
            port,
            branch: get("branch"),
            received: get("received"),
            rport: get("rport"),
        })
    }
}

/// Splits "host:port", "[v6]:port" or "host".
pub fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
            return (host, port);
        }
    }
    if s.matches(':').count() == 1 {
        let mut it = s.splitn(2, ':');
        let h = it.next().unwrap_or("").to_string();
        let p = it.next().and_then(|p| p.parse().ok());
        return (h, p);
    }
    (s.to_string(), None)
}

/// Parsed pieces of a SIP/SIPS/TEL URI.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Uri {
    pub scheme: String,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, String)>,
}

impl Uri {
    /// Parses a URI from a name-addr ("Alice" <sip:a@b>;tag=x) or addr-spec.
    pub fn from_header(v: &str) -> Option<Uri> {
        let inner = match (v.find('<'), v.find('>')) {
            (Some(a), Some(b)) if b > a => &v[a + 1..b],
            _ => v.split(';').next().unwrap_or(v).trim(),
        };
        Uri::parse(inner)
    }

    pub fn parse(s: &str) -> Option<Uri> {
        let s = s.trim();
        let colon = s.find(':')?;
        let scheme = s[..colon].to_ascii_lowercase();
        let rest = &s[colon + 1..];
        if scheme == "tel" {
            let mut parts = rest.split(';');
            let num = parts.next().unwrap_or("").to_string();
            return Some(Uri {
                scheme,
                user: Some(num.clone()),
                host: String::new(),
                port: None,
                params: vec![],
            });
        }
        let (hostpart, params_str) = match rest.find(';') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let hostpart = hostpart.split('?').next().unwrap_or("");
        let (user, hp) = match hostpart.rfind('@') {
            Some(i) => (
                Some(hostpart[..i].split(':').next().unwrap_or("").to_string()),
                &hostpart[i + 1..],
            ),
            None => (None, hostpart),
        };
        let (host, port) = split_host_port(hp);
        let params = params_str
            .split(';')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let mut kv = p.splitn(2, '=');
                (
                    kv.next().unwrap_or("").to_ascii_lowercase(),
                    kv.next().unwrap_or("").to_string(),
                )
            })
            .collect();
        Some(Uri {
            scheme,
            user,
            host,
            port,
            params,
        })
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn short(&self) -> String {
        match &self.user {
            Some(u) if !self.host.is_empty() => format!("{u}@{}", self.host),
            Some(u) => u.clone(),
            None => self.host.clone(),
        }
    }
}

/// Meaning of common SIP response codes, for explanations.
pub fn status_hint(code: u16) -> &'static str {
    match code {
        100 => "Trying: the next hop received the request and stops retransmissions",
        180 => "Ringing",
        181 => "Call is being forwarded",
        182 => "Queued",
        183 => "Session progress, usually early media",
        200 => "OK",
        202 => "Accepted",
        301 | 302 => "Moved: the target is reachable at the Contact in the response",
        400 => "Bad request: the receiver could not parse the request (syntax, missing header)",
        401 | 407 => "Authentication challenge: the request must be resent with credentials",
        403 => "Forbidden: credentials wrong, account barred, IP not allowed or destination not permitted",
        404 => "Not found: the user or number does not exist on the target",
        405 => "Method not allowed on this target",
        408 => "Request timeout: no final answer in time, often an unreachable next hop or nobody answered",
        410 => "Gone: the number or user no longer exists",
        415 => "Unsupported media type: body format (e.g. multipart, ISUP) not accepted",
        416 => "Unsupported URI scheme",
        420 | 421 => "Extension required or unsupported (check Require/Supported, e.g. 100rel, timer)",
        422 => "Session interval too small (Session-Expires below Min-SE)",
        423 => "Registration interval too brief (Expires below the server minimum)",
        480 => "Temporarily unavailable: user not registered, DND, or no route right now",
        481 => "Call/transaction does not exist: dialog identifiers do not match (tags, Call-ID) or the dialog already ended",
        482 => "Loop detected",
        483 => "Too many hops: Max-Forwards reached zero, routing loop likely",
        484 => "Address incomplete: number too short for the dial plan",
        486 => "Busy here",
        487 => "Request terminated, normally after CANCEL",
        488 => "Not acceptable here: SDP offer rejected (codec, crypto/SRTP, ptime or media attributes)",
        489 => "Bad event (SUBSCRIBE/NOTIFY package not supported)",
        491 => "Request pending: re-INVITE glare, retry after a random delay",
        500 => "Server internal error",
        501 => "Not implemented",
        502 => "Bad gateway: downstream element returned an invalid response",
        503 => "Service unavailable: overload, maintenance, no trunk capacity, or no available route",
        504 => "Server timeout: a downstream server did not answer in time",
        505 => "SIP version not supported",
        513 => "Message too large: switch to TCP or reduce the message size",
        580 => "Precondition failure",
        600 => "Busy everywhere",
        603 => "Declined",
        604 => "Does not exist anywhere",
        606 => "Not acceptable: session description not acceptable anywhere",
        607 => "Unwanted call",
        608 => "Rejected by an intermediary (call analytics/robocall filter)",
        _ => "",
    }
}

/// ITU-T Q.850 cause values commonly carried in Reason headers.
pub fn q850_hint(cause: u16) -> &'static str {
    match cause {
        1 => "Unallocated (unassigned) number",
        3 => "No route to destination",
        16 => "Normal call clearing",
        17 => "User busy",
        18 => "No user responding",
        19 => "No answer from user (user alerted)",
        20 => "Subscriber absent",
        21 => "Call rejected",
        22 => "Number changed",
        27 => "Destination out of order",
        28 => "Invalid number format (address incomplete)",
        29 => "Facility rejected",
        31 => "Normal, unspecified",
        34 => "No circuit/channel available",
        38 => "Network out of order",
        41 => "Temporary failure",
        42 => "Switching equipment congestion",
        44 => "Requested circuit/channel not available",
        47 => "Resource unavailable, unspecified",
        50 => "Requested facility not subscribed",
        57 => "Bearer capability not authorized",
        58 => "Bearer capability not presently available",
        65 => "Bearer capability not implemented",
        88 => "Incompatible destination",
        102 => "Recovery on timer expiry",
        111 => "Protocol error, unspecified",
        127 => "Interworking, unspecified",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = "INVITE sip:100@192.0.2.1 SIP/2.0\r\nv: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1;rport\r\nf: \"A\" <sip:200@pbx>;tag=abc\r\nt: <sip:100@pbx>\r\ni: call1@x\r\nCSeq: 1 INVITE\r\nl: 4\r\nc: application/sdp\r\n\r\nv=0\r\n";

    #[test]
    fn parses_compact_and_values() {
        let m = parse_datagram(INV.as_bytes()).unwrap();
        assert_eq!(m.method(), Some("INVITE"));
        assert_eq!(m.call_id(), Some("call1@x"));
        assert_eq!(m.from_tag().as_deref(), Some("abc"));
        assert_eq!(m.cseq(), Some((1, "INVITE".into())));
        let via = m.top_via().unwrap();
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK1"));
        assert_eq!(via.port, Some(5060));
        assert_eq!(m.body, "v=0\r");
        assert!(m.parse_notes.iter().any(|n| n.contains("smaller")) || m.body.len() == 4);
    }

    #[test]
    fn stream_parsing_multiple() {
        let a = "OPTIONS sip:x SIP/2.0\r\nCall-ID: 1\r\nContent-Length: 0\r\n\r\n";
        let b = "SIP/2.0 200 OK\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let buf = format!("{a}\r\n{b}SIP/2.0 1");
        let (msgs, used) = parse_stream(buf.as_bytes());
        assert_eq!(msgs.len(), 2);
        assert_eq!(&buf[used..], "SIP/2.0 1");
        assert_eq!(msgs[1].summary(), "200 OK (OPTIONS)");
    }

    #[test]
    fn uri_parsing() {
        let u = Uri::from_header("\"Bob\" <sip:+5511999@carrier.example:5061;transport=tls>;tag=1")
            .unwrap();
        assert_eq!(u.user.as_deref(), Some("+5511999"));
        assert_eq!(u.port, Some(5061));
        assert_eq!(u.param("transport"), Some("tls"));
    }
}
