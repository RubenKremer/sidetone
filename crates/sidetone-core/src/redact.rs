//! Masking of personal and sensitive data before sharing captures or
//! sending them to an external AI provider.

use crate::net::is_private;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactOptions {
    /// Mask digits in SIP/TEL URI user parts (keeps the last 2 digits).
    pub numbers: bool,
    /// Mask credentials and digest parameters.
    pub auth: bool,
    /// Replace public IPv4 addresses with consistent documentation addresses.
    pub ips: bool,
    /// Replace quoted display names.
    pub names: bool,
}

impl Default for RedactOptions {
    fn default() -> Self {
        RedactOptions {
            numbers: true,
            auth: true,
            ips: true,
            names: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct Redactor {
    pub opts: RedactOptions,
    ip_map: HashMap<Ipv4Addr, Ipv4Addr>,
}

const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
];
const AUTH_PARAMS: &[&str] = &["username", "response", "cnonce", "nonce", "opaque", "nc"];

impl Redactor {
    pub fn new(opts: RedactOptions) -> Self {
        Redactor {
            opts,
            ip_map: HashMap::new(),
        }
    }

    /// Maps an IP address consistently (public IPv4 only).
    pub fn map_ip(&mut self, ip: IpAddr) -> IpAddr {
        if !self.opts.ips {
            return ip;
        }
        match ip {
            IpAddr::V4(v4) if !is_private(&ip) && !v4.is_unspecified() && !v4.is_broadcast() => {
                let n = self.ip_map.len();
                // 240.0.0.0/4 is reserved and never appears in real traffic, so a
                // pseudonym cannot be confused with a genuine address in the capture.
                let mapped = *self.ip_map.entry(v4).or_insert_with(|| {
                    Ipv4Addr::new(
                        240,
                        ((n / 62_500) % 256) as u8,
                        ((n / 250) % 250) as u8,
                        (n % 250) as u8 + 1,
                    )
                });
                IpAddr::V4(mapped)
            }
            other => other,
        }
    }

    /// Redacts a full SIP message (headers and SDP body) and fixes Content-Length.
    pub fn sip_message(&mut self, raw: &str) -> String {
        let (head, body, sep) = match raw.find("\r\n\r\n") {
            Some(i) => (&raw[..i], &raw[i + 4..], "\r\n\r\n"),
            None => match raw.find("\n\n") {
                Some(i) => (&raw[..i], &raw[i + 2..], "\n\n"),
                None => (raw, "", ""),
            },
        };
        let body_r = self.text(body);
        let mut lines = Vec::new();
        let nl = if head.contains("\r\n") { "\r\n" } else { "\n" };
        for line in head.split(nl) {
            let lower = line.to_ascii_lowercase();
            let name = lower.split(':').next().unwrap_or("").trim().to_string();
            if self.opts.auth && AUTH_HEADERS.contains(&name.as_str()) {
                lines.push(self.auth_line(line));
            } else if name == "content-length" || name == "l" {
                let hdr = &line[..line.find(':').unwrap_or(line.len())];
                lines.push(format!("{hdr}: {}", body_r.len()));
            } else {
                lines.push(self.text(line));
            }
        }
        let mut out = lines.join(nl);
        out.push_str(sep);
        out.push_str(&body_r);
        out
    }

    fn auth_line(&self, line: &str) -> String {
        let Some(colon) = line.find(':') else {
            return line.to_string();
        };
        let (hdr, val) = (&line[..colon], line[colon + 1..].trim());
        let (scheme, params) = match val.find(char::is_whitespace) {
            Some(i) => (&val[..i], &val[i + 1..]),
            None => (val, ""),
        };
        let parts: Vec<String> = crate::sip::split_list(params)
            .into_iter()
            .map(|p| {
                let k = p
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if AUTH_PARAMS.contains(&k.as_str()) {
                    format!("{k}=\"[redacted]\"")
                } else {
                    p
                }
            })
            .collect();
        format!("{hdr}: {scheme} {}", parts.join(", "))
    }

    /// Redacts free text (headers, SDP, logs).
    pub fn text(&mut self, s: &str) -> String {
        let mut t = s.to_string();
        if self.opts.names {
            t = mask_display_names(&t);
        }
        if self.opts.numbers {
            t = mask_uri_users(&t);
        }
        if self.opts.ips {
            t = self.mask_ipv4(&t);
        }
        t
    }

    fn mask_ipv4(&mut self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_digit()
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.'))
            {
                let mut j = i;
                while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                    j += 1;
                }
                let tok = s[i..j].trim_end_matches('.');
                let tok_end = i + tok.len();
                let next_ok = tok_end >= b.len() || !b[tok_end].is_ascii_alphanumeric();
                if next_ok {
                    if let Ok(ip) = tok.parse::<Ipv4Addr>() {
                        out.push_str(&self.map_ip(IpAddr::V4(ip)).to_string());
                        i = tok_end;
                        continue;
                    }
                }
                out.push_str(&s[i..j]);
                i = j;
                continue;
            }
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }
}

fn mask_digits(user: &str) -> String {
    let digits = user.chars().filter(|c| c.is_ascii_digit()).count();
    if digits < 3 {
        return user.to_string();
    }
    let mut seen = 0;
    user.chars()
        .map(|c| {
            if c.is_ascii_digit() {
                seen += 1;
                if seen <= digits - 2 {
                    'x'
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect()
}

fn mask_uri_users(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let lower = rest.to_ascii_lowercase();
        let pos = ["sip:", "sips:", "tel:"]
            .iter()
            .filter_map(|p| lower.find(p).map(|i| (i, p.len())))
            .min();
        let Some((i, plen)) = pos else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..i + plen]);
        let after = &rest[i + plen..];
        let end = after
            .find(|c: char| {
                c == '@' || c == ';' || c == '>' || c == '"' || c.is_whitespace() || c == ','
            })
            .unwrap_or(after.len());
        let is_tel = lower[i..].starts_with("tel:");
        let has_at = after[end..].starts_with('@');
        if is_tel || has_at {
            out.push_str(&mask_digits(&after[..end]));
        } else {
            out.push_str(&after[..end]);
        }
        rest = &after[end..];
    }
    out
}

fn mask_display_names(s: &str) -> String {
    // Quoted display names directly before a <URI>.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    let b = s;
    let mut last = 0;
    while let Some((i, c)) = chars.next() {
        if c == '"' {
            if let Some(close_rel) = b[i + 1..].find('"') {
                let close = i + 1 + close_rel;
                let after = b[close + 1..].trim_start();
                if after.starts_with('<') {
                    out.push_str(&b[last..i]);
                    out.push_str("\"[name]\"");
                    last = close + 1;
                    while let Some(&(k, _)) = chars.peek() {
                        if k <= close {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }
    out.push_str(&b[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_message() {
        let raw = "INVITE sip:+5511987654321@203.0.113.250 SIP/2.0\r\nFrom: \"Joao Silva\" <sip:1001@8.8.8.8>;tag=1\r\nAuthorization: Digest username=\"1001\", realm=\"x\", response=\"abc\"\r\nContent-Length: 20\r\n\r\nc=IN IP4 8.8.4.4\r\n";
        let mut r = Redactor::new(RedactOptions::default());
        let out = r.sip_message(raw);
        assert!(out.contains("sip:+xxxxxxxxxxx21@"));
        assert!(out.contains("\"[name]\""));
        assert!(out.contains("response=\"[redacted]\""));
        assert!(!out.contains("8.8.8.8"));
        assert!(!out.contains("8.8.4.4"));
        assert!(out.contains("realm=\"x\""));
        let body = out.split("\r\n\r\n").nth(1).unwrap();
        assert!(out.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn ip_mapping_is_consistent_and_keeps_private() {
        let mut r = Redactor::new(RedactOptions::default());
        let a = r.text("x 1.2.3.4 y 1.2.3.4 z 192.168.0.1 v1.2.3");
        assert_eq!(a, "x 240.0.0.1 y 240.0.0.1 z 192.168.0.1 v1.2.3");
    }
}
