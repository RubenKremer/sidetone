//! pcapng export: findings as packet comments, optional redaction, TLS key
//! log embedding, and per-call filtering.

use crate::analysis::Report;
use crate::net::{self, Transport};
use crate::pcap::{write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW};
use crate::redact::{RedactOptions, Redactor};
use crate::rtp;
use crate::sip;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Add findings as Wireshark packet comments.
    #[serde(default = "yes")]
    pub annotate: bool,
    /// Redact personal data; non-SIP/non-RTP packets are dropped when set.
    #[serde(default)]
    pub redact: Option<RedactOptions>,
    /// Only packets belonging to this call (SIP + its RTP).
    #[serde(default)]
    pub call: Option<usize>,
    /// Drop RTP and keep signaling only.
    #[serde(default)]
    pub sip_only: bool,
}

fn yes() -> bool {
    true
}

/// Exports the report's capture as pcapng bytes.
pub fn export_pcapng(r: &Report, opts: &ExportOptions) -> Vec<u8> {
    // Comments per frame (1-based) from findings.
    let mut comments: HashMap<usize, Vec<String>> = HashMap::new();
    if opts.annotate {
        for f in &r.findings {
            for &mi in &f.messages {
                if let Some(m) = r.messages.get(mi) {
                    comments
                        .entry(m.frame)
                        .or_default()
                        .push(format!("[{:?}] {}: {}", f.severity, f.title, f.detail));
                }
            }
            if let Some(si) = f.stream {
                if let Some(s) = r.streams.get(si) {
                    comments
                        .entry(s.first_frame)
                        .or_default()
                        .push(format!("[{:?}] {}: {}", f.severity, f.title, f.detail));
                }
            }
        }
    }

    // Frame filter for a single call.
    let (sip_frames, rtp_flows): (
        Option<HashSet<usize>>,
        Option<HashSet<(SocketAddr, SocketAddr)>>,
    ) = match opts.call.and_then(|c| r.calls.get(c)) {
        Some(c) => (
            Some(c.messages.iter().map(|&i| r.messages[i].frame).collect()),
            Some(
                c.streams
                    .iter()
                    .filter_map(|&s| Some((r.streams[s].src_addr?, r.streams[s].dst_addr?)))
                    .collect(),
            ),
        ),
        None => (None, None),
    };

    let mut redactor = opts.redact.clone().map(Redactor::new);
    let sip_frame_set: HashSet<usize> = r.messages.iter().map(|m| m.frame).collect();
    let mut owned: Vec<(i64, u32, Vec<u8>, u32, Option<String>)> = Vec::new();

    for (i, p) in r.capture.packets.iter().enumerate() {
        let frame = i + 1;
        let decoded = net::decode(p.linktype, &p.data);
        let is_sip_frame = sip_frame_set.contains(&frame);
        let rtp_key = decoded.as_ref().and_then(|d| {
            if d.transport == Transport::Udp
                && !sip::looks_like_sip(d.payload)
                && (rtp::parse_rtp(d.payload).is_some() || rtp::is_rtcp(d.payload))
            {
                Some((d.src, d.dst))
            } else {
                None
            }
        });
        if let Some(frames) = &sip_frames {
            let keep_sip = frames.contains(&frame);
            let keep_rtp = rtp_key
                .map(|(s, d)| {
                    rtp_flows
                        .as_ref()
                        .map(|f| {
                            f.contains(&(s, d))
                                || f.iter().any(|(a, b)| {
                                    (s, d) == (rtp_port_plus1(*a), rtp_port_plus1(*b))
                                })
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !keep_sip && !keep_rtp {
                continue;
            }
        }
        if opts.sip_only && !is_sip_frame {
            continue;
        }
        let mut comment = p.comment.clone();
        if let Some(c) = comments.get(&frame) {
            let joined = c.join("\n");
            comment = Some(match comment {
                Some(old) => format!("{old}\n{joined}"),
                None => joined,
            });
        }
        match (&mut redactor, decoded) {
            (None, _) => owned.push((p.ts_ns, p.linktype, p.data.clone(), p.orig_len, comment)),
            (Some(red), Some(d)) => {
                let src = SocketAddr::new(red.map_ip(d.src.ip()), d.src.port());
                let dst = SocketAddr::new(red.map_ip(d.dst.ip()), d.dst.port());
                if is_sip_frame {
                    // Rebuild every SIP message carried by this frame as UDP datagrams.
                    for m in r.messages.iter().filter(|m| m.frame == frame) {
                        let text = red.sip_message(&m.raw);
                        let pkt = net::build_udp_packet(src, dst, text.as_bytes());
                        let len = pkt.len() as u32;
                        let note = if m.transport == Transport::Tcp {
                            Some(
                                "Sidetone: SIP over TCP rebuilt as UDP after redaction".to_string(),
                            )
                        } else {
                            None
                        };
                        let c = match (&comment, note) {
                            (Some(a), Some(b)) => Some(format!("{a}\n{b}")),
                            (Some(a), None) => Some(a.clone()),
                            (None, b) => b,
                        };
                        owned.push((p.ts_ns, LINKTYPE_RAW, pkt, len, c.map(|x| red.text(&x))));
                    }
                } else if rtp_key.is_some() && !opts.sip_only {
                    let pkt = net::build_udp_packet(src, dst, d.payload);
                    let len = pkt.len() as u32;
                    owned.push((
                        p.ts_ns,
                        LINKTYPE_RAW,
                        pkt,
                        len,
                        comment.map(|x| red.text(&x)),
                    ));
                }
                // Everything else is dropped: it cannot be sanitized reliably.
            }
            (Some(_), None) => {}
        }
    }

    let out: Vec<OutPacket<'_>> = owned
        .iter()
        .map(|(ts, lt, data, ol, c)| OutPacket {
            ts_ns: *ts,
            linktype: *lt,
            data,
            orig_len: *ol,
            comment: c.clone(),
        })
        .collect();
    let section_comment = format!(
        "Exported by Sidetone {}: {} calls, {} findings ({} errors, {} warnings){}",
        r.version,
        r.summary.calls,
        r.findings.len(),
        r.summary.errors,
        r.summary.warnings,
        if opts.redact.is_some() {
            ", redacted"
        } else {
            ""
        }
    );
    let popts = PcapngOptions {
        user_appl: Some(format!("Sidetone {}", r.version)),
        section_comment: Some(section_comment),
        // Keys reveal session content; never ship them in a redacted export.
        tls_keylog: if opts.redact.is_some() {
            vec![]
        } else {
            r.capture.tls_keylog.clone()
        },
    };
    write_pcapng(&out, &popts)
}

fn rtp_port_plus1(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip(), a.port().wrapping_add(1))
}
