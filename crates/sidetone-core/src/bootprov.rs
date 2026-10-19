//! Phone boot provisioning seen in a capture: DHCP handing out the TFTP or
//! provisioning server (options 66, 150, 160) and TFTP downloads of
//! configuration files (RFC 1350), with how each one ended.

use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize)]
pub struct ProvEvent {
    /// "dhcp" or "tftp".
    pub kind: String,
    pub frame: usize,
    pub rel_s: f64,
    /// The phone: its MAC for DHCP, its address for TFTP.
    pub client: String,
    pub server: String,
    /// TFTP: the file asked for.
    pub file: Option<String>,
    /// TFTP: "ok", "error", "no answer" or "incomplete". DHCP: the message type.
    pub outcome: String,
    pub bytes: u64,
    pub error: Option<String>,
    /// DHCP: provisioning options in the answer.
    pub option66: Option<String>,
    pub option150: Vec<String>,
    pub option160: Option<String>,
    /// DHCP: the phone asked for option 66 or 150 (parameter request list).
    pub asked_for_tftp: bool,
}

struct Transfer {
    idx: usize,
    client: SocketAddr,
    server_ip: IpAddr,
    blksize: usize,
    next_block: u16,
    last_ns: i64,
    done: bool,
}

#[derive(Default)]
pub struct Collector {
    events: Vec<ProvEvent>,
    transfers: Vec<Transfer>,
    /// DHCP requests by transaction id, for the options the phone asked for.
    asked: HashMap<u32, bool>,
}

fn ev(kind: &str, frame: usize, ts: i64, client: String, server: String) -> ProvEvent {
    ProvEvent {
        kind: kind.into(),
        frame,
        rel_s: ts as f64,
        client,
        server,
        file: None,
        outcome: String::new(),
        bytes: 0,
        error: None,
        option66: None,
        option150: Vec::new(),
        option160: None,
        asked_for_tftp: false,
    }
}

fn tftp_error(code: u16, msg: &str) -> String {
    let what = match code {
        1 => "File not found",
        2 => "Access violation",
        3 => "Disk full",
        4 => "Illegal TFTP operation",
        5 => "Unknown transfer ID",
        6 => "File already exists",
        7 => "No such user",
        8 => "Option negotiation refused",
        _ => "Not defined",
    };
    if msg.is_empty() || msg.eq_ignore_ascii_case(what) {
        format!("{what} (error {code})")
    } else {
        format!("{what} (error {code}: {msg})")
    }
}

impl Collector {
    /// Looks at one UDP datagram; true when it was DHCP or TFTP.
    pub fn observe(
        &mut self,
        frame: usize,
        ts: i64,
        src: SocketAddr,
        dst: SocketAddr,
        p: &[u8],
    ) -> bool {
        let ports = (src.port(), dst.port());
        if matches!(ports, (68, 67) | (67, 68) | (67, 67))
            && p.len() >= 240
            && p[236..240] == [99, 130, 83, 99]
        {
            self.dhcp(frame, ts, src, p);
            return true;
        }
        if p.len() < 4 || p[0] != 0 {
            return false;
        }
        let op = p[1];
        // A request to port 69 starts a transfer.
        if dst.port() == 69 && (op == 1 || op == 2) {
            let mut parts = p[2..].split(|b| *b == 0);
            let file = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            let _mode = parts.next();
            let mut blksize = 512;
            let rest: Vec<&[u8]> = parts.collect();
            for kv in rest.chunks(2) {
                if kv.len() == 2 && kv[0].eq_ignore_ascii_case(b"blksize") {
                    blksize = String::from_utf8_lossy(kv[1]).parse().unwrap_or(512);
                }
            }
            // A retransmitted request is the same transfer.
            if let Some(t) = self.transfers.iter().find(|t| {
                t.client == src && !t.done && self.events[t.idx].file.as_deref() == Some(&file)
            }) {
                let _ = t;
                return true;
            }
            let mut e = ev("tftp", frame, ts, src.to_string(), dst.ip().to_string());
            e.file = Some(file);
            e.outcome = "no answer".into();
            self.events.push(e);
            self.transfers.push(Transfer {
                idx: self.events.len() - 1,
                client: src,
                server_ip: dst.ip(),
                blksize,
                next_block: 1,
                last_ns: ts,
                done: false,
            });
            return true;
        }
        // Server to client (DATA, ERROR, OACK) or client to server (ACK).
        let t = self.transfers.iter_mut().rev().find(|t| {
            !t.done
                && ((dst == t.client && src.ip() == t.server_ip)
                    || (src == t.client && dst.ip() == t.server_ip && dst.port() != 69))
        });
        let Some(t) = t else {
            return false;
        };
        if !(3..=6).contains(&op) {
            return false;
        }
        t.last_ns = ts;
        let e = &mut self.events[t.idx];
        if dst == t.client {
            match op {
                3 => {
                    let block = u16::from_be_bytes([p[2], p[3]]);
                    if block == t.next_block {
                        let n = p.len() - 4;
                        e.bytes += n as u64;
                        e.outcome = "incomplete".into();
                        t.next_block = t.next_block.wrapping_add(1);
                        if n < t.blksize {
                            e.outcome = "ok".into();
                            t.done = true;
                        }
                    }
                }
                5 => {
                    let code = u16::from_be_bytes([p[2], p[3]]);
                    let msg = String::from_utf8_lossy(&p[4..])
                        .trim_end_matches('\0')
                        .to_string();
                    e.outcome = "error".into();
                    e.error = Some(tftp_error(code, &msg));
                    t.done = true;
                }
                6 => {
                    e.outcome = "incomplete".into();
                    let fields: Vec<String> = p[2..]
                        .split(|b| *b == 0)
                        .map(|x| String::from_utf8_lossy(x).to_ascii_lowercase())
                        .collect();
                    for kv in fields.chunks(2) {
                        if kv.len() == 2 && kv[0] == "blksize" {
                            t.blksize = kv[1].parse().unwrap_or(t.blksize);
                        }
                    }
                }
                _ => {}
            }
        }
        true
    }

    fn dhcp(&mut self, frame: usize, ts: i64, src: SocketAddr, p: &[u8]) {
        let xid = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let mac: String = p[28..34]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let mut kind = 0u8;
        let mut asked = false;
        let mut o66 = None;
        let mut o150 = Vec::new();
        let mut o160 = None;
        let mut server = None;
        let mut i = 240;
        while i + 1 < p.len() {
            let code = p[i];
            if code == 255 {
                break;
            }
            if code == 0 {
                i += 1;
                continue;
            }
            let len = p[i + 1] as usize;
            let Some(v) = p.get(i + 2..i + 2 + len) else {
                break;
            };
            let text = || {
                String::from_utf8_lossy(v)
                    .trim_end_matches('\0')
                    .trim()
                    .to_string()
            };
            match code {
                53 if len == 1 => kind = v[0],
                54 if len == 4 => server = Some(format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])),
                55 => asked = v.contains(&66) || v.contains(&150),
                66 => o66 = Some(text()).filter(|s| !s.is_empty()),
                150 => {
                    o150 = v
                        .chunks_exact(4)
                        .map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3]))
                        .collect()
                }
                160 => o160 = Some(text()).filter(|s| !s.is_empty()),
                _ => {}
            }
            i += 2 + len;
        }
        match kind {
            // DISCOVER, REQUEST, INFORM: remember what the phone asked for.
            1 | 3 | 8 => {
                self.asked.insert(xid, asked);
            }
            // OFFER, ACK: what the network told it.
            2 | 5 => {
                let asked = self.asked.get(&xid).copied().unwrap_or(false);
                let has = o66.is_some() || !o150.is_empty() || o160.is_some();
                if !has && !asked {
                    return;
                }
                // One event per transaction: the ACK replaces the OFFER.
                if let Some(e) = self.events.iter_mut().rev().find(|e| {
                    e.kind == "dhcp" && e.client == mac && e.outcome == "OFFER" && kind == 5
                }) {
                    e.outcome = "ACK".into();
                    e.frame = frame;
                    e.option66 = o66;
                    e.option150 = o150;
                    e.option160 = o160;
                    return;
                }
                let mut e = ev(
                    "dhcp",
                    frame,
                    ts,
                    mac,
                    server.unwrap_or_else(|| src.ip().to_string()),
                );
                e.outcome = if kind == 5 {
                    "ACK".into()
                } else {
                    "OFFER".into()
                };
                e.option66 = o66;
                e.option150 = o150;
                e.option160 = o160;
                e.asked_for_tftp = asked;
                self.events.push(e);
            }
            _ => {}
        }
    }

    /// The events, times made relative to `start_ns`.
    pub fn finish(mut self, start_ns: i64) -> Vec<ProvEvent> {
        for e in &mut self.events {
            e.rel_s = ((e.rel_s as i64 - start_ns) as f64 / 1e9 * 1000.0).round() / 1000.0;
        }
        self.events
    }
}

/// Cisco phones always ask for trust lists and a few fallbacks; their
/// absence is normal on a non-CUCM server.
pub fn optional_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    (n.starts_with("ctl") || n.starts_with("itl")) && n.ends_with(".tlv")
        || n.ends_with(".jar")
        || n.contains("dialplan")
        || n.contains("softkey")
        || n.contains("featurepolicy")
        || n.ends_with(".loads")
        || n.starts_with("g3-")
}
