//! SDP (RFC 4566/8866) parsing focused on what matters for troubleshooting.

use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Sdp {
    pub origin: String,
    pub session_name: String,
    pub connection: Option<String>,
    pub direction: Option<String>,
    pub ice_lite: bool,
    pub media: Vec<Media>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Codec {
    pub pt: u8,
    pub name: String,
    pub rate: u32,
    pub fmtp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Media {
    pub kind: String,
    pub port: u16,
    pub proto: String,
    pub formats: Vec<u8>,
    pub codecs: Vec<Codec>,
    pub connection: Option<String>,
    /// Effective direction (media-level overrides session-level, default sendrecv).
    pub direction: String,
    pub ptime: Option<u32>,
    pub rtcp: Option<String>,
    pub rtcp_mux: bool,
    pub crypto: Vec<String>,
    pub fingerprint: Option<String>,
    pub setup: Option<String>,
    pub ice_ufrag: Option<String>,
    pub candidates: Vec<String>,
}

impl Media {
    /// The address RTP should be sent to for this stream.
    pub fn address(&self, sdp: &Sdp) -> Option<IpAddr> {
        self.connection
            .as_ref()
            .or(sdp.connection.as_ref())
            .and_then(|c| c.parse().ok())
    }

    pub fn is_secure(&self) -> bool {
        self.proto.to_ascii_uppercase().contains("SAVP")
    }

    pub fn codec_names(&self) -> Vec<String> {
        self.formats
            .iter()
            .map(|pt| {
                self.codecs
                    .iter()
                    .find(|c| c.pt == *pt)
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| {
                        static_codec(*pt)
                            .map(|(n, _)| n.to_string())
                            .unwrap_or_else(|| format!("PT{pt}"))
                    })
            })
            .collect()
    }

    /// Clock rate for a payload type in this media section.
    pub fn clock_rate(&self, pt: u8) -> u32 {
        self.codecs
            .iter()
            .find(|c| c.pt == pt)
            .map(|c| c.rate)
            .or_else(|| static_codec(pt).map(|(_, r)| r))
            .unwrap_or(8000)
    }

    pub fn codec_name(&self, pt: u8) -> String {
        self.codecs
            .iter()
            .find(|c| c.pt == pt)
            .map(|c| c.name.clone())
            .or_else(|| static_codec(pt).map(|(n, _)| n.to_string()))
            .unwrap_or_else(|| format!("PT{pt}"))
    }
}

/// RFC 3551 static payload types (name, RTP clock rate).
pub fn static_codec(pt: u8) -> Option<(&'static str, u32)> {
    Some(match pt {
        0 => ("PCMU", 8000),
        3 => ("GSM", 8000),
        4 => ("G723", 8000),
        8 => ("PCMA", 8000),
        9 => ("G722", 8000),
        13 => ("CN", 8000),
        18 => ("G729", 8000),
        _ => return None,
    })
}

pub fn parse(body: &str) -> Option<Sdp> {
    let mut sdp = Sdp::default();
    let mut session_dir: Option<String> = None;
    let mut session_fp: Option<String> = None;
    let mut cur: Option<Media> = None;
    let mut seen_v = false;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            continue;
        }
        let (t, v) = (line.as_bytes()[0], &line[2..]);
        match t {
            b'v' => seen_v = true,
            b'o' => sdp.origin = v.to_string(),
            b's' => sdp.session_name = v.to_string(),
            b'c' => {
                let addr = v
                    .split_whitespace()
                    .nth(2)
                    .map(|a| a.split('/').next().unwrap_or(a).to_string());
                match cur.as_mut() {
                    Some(m) => m.connection = addr,
                    None => sdp.connection = addr,
                }
            }
            b'm' => {
                if let Some(m) = cur.take() {
                    sdp.media.push(m);
                }
                let mut it = v.split_whitespace();
                let kind = it.next().unwrap_or("").to_string();
                let port = it
                    .next()
                    .unwrap_or("0")
                    .split('/')
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                let proto = it.next().unwrap_or("").to_string();
                let formats = it.filter_map(|f| f.parse().ok()).collect();
                cur = Some(Media {
                    kind,
                    port,
                    proto,
                    formats,
                    ..Default::default()
                });
            }
            b'a' => {
                let (name, val) = match v.find(':') {
                    Some(i) => (&v[..i], Some(&v[i + 1..])),
                    None => (v, None),
                };
                match (name, cur.as_mut()) {
                    ("sendrecv" | "sendonly" | "recvonly" | "inactive", Some(m)) => {
                        m.direction = name.to_string()
                    }
                    ("sendrecv" | "sendonly" | "recvonly" | "inactive", None) => {
                        session_dir = Some(name.to_string())
                    }
                    ("ice-lite", None) => sdp.ice_lite = true,
                    ("rtpmap", Some(m)) => {
                        if let Some(val) = val {
                            let mut it = val.splitn(2, ' ');
                            let pt = it.next().and_then(|p| p.parse().ok());
                            let enc = it.next().unwrap_or("");
                            let mut e = enc.split('/');
                            let cname = e.next().unwrap_or("").to_string();
                            let rate = e.next().and_then(|r| r.parse().ok()).unwrap_or(8000);
                            if let Some(pt) = pt {
                                m.codecs.push(Codec {
                                    pt,
                                    name: cname,
                                    rate,
                                    fmtp: None,
                                });
                            }
                        }
                    }
                    ("fmtp", Some(m)) => {
                        if let Some(val) = val {
                            let mut it = val.splitn(2, ' ');
                            if let Some(pt) = it.next().and_then(|p| p.parse::<u8>().ok()) {
                                let f = it.next().unwrap_or("").to_string();
                                if let Some(c) = m.codecs.iter_mut().find(|c| c.pt == pt) {
                                    c.fmtp = Some(f);
                                }
                            }
                        }
                    }
                    ("ptime", Some(m)) => m.ptime = val.and_then(|v| v.trim().parse().ok()),
                    ("rtcp", Some(m)) => m.rtcp = val.map(|v| v.to_string()),
                    ("rtcp-mux", Some(m)) => m.rtcp_mux = true,
                    ("crypto", Some(m)) => m.crypto.push(val.unwrap_or("").to_string()),
                    ("fingerprint", Some(m)) => m.fingerprint = val.map(|v| v.to_string()),
                    ("fingerprint", None) => session_fp = val.map(|v| v.to_string()),
                    ("setup", Some(m)) => m.setup = val.map(|v| v.to_string()),
                    ("ice-ufrag", Some(m)) => m.ice_ufrag = val.map(|v| v.to_string()),
                    ("candidate", Some(m)) => m.candidates.push(val.unwrap_or("").to_string()),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if let Some(m) = cur.take() {
        sdp.media.push(m);
    }
    if !seen_v {
        return None;
    }
    let sd = session_dir.clone().unwrap_or_else(|| "sendrecv".into());
    for m in sdp.media.iter_mut() {
        if m.direction.is_empty() {
            m.direction = sd.clone();
        }
        if m.fingerprint.is_none() {
            m.fingerprint = session_fp.clone();
        }
    }
    sdp.direction = session_dir;
    Some(sdp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_audio_offer() {
        let body = "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendonly\r\n";
        let s = parse(body).unwrap();
        let m = &s.media[0];
        assert_eq!(m.port, 40000);
        assert_eq!(m.codec_names(), vec!["PCMU", "PCMA", "telephone-event"]);
        assert_eq!(m.direction, "sendonly");
        assert_eq!(m.address(&s).unwrap().to_string(), "10.0.0.5");
        assert_eq!(m.ptime, Some(20));
    }
}
