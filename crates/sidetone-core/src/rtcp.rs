//! RTCP (RFC 3550) sender and receiver reports, RTCP XR VoIP metrics
//! (RFC 3611, block type 7), and the SIP PUBLISH voice-quality reports of
//! RFC 6035 (application/vq-rtcpxr).

use serde::Serialize;

/// One reception report block: how a receiver sees a stream (by its SSRC).
#[derive(Debug, Clone, Serialize, Default)]
pub struct ReportBlock {
    pub ssrc: u32,
    /// Fraction lost since the previous report, 0..=255 (/256).
    pub fraction_lost: u8,
    pub cumulative_lost: i32,
    pub highest_seq: u32,
    /// Interarrival jitter in RTP timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP time of the last SR received.
    pub lsr: u32,
    /// Delay since that SR, in units of 1/65536 s.
    pub dlsr: u32,
}

/// RFC 3611 VoIP metrics report block (type 7).
#[derive(Debug, Clone, Serialize, Default)]
pub struct VoipMetrics {
    pub ssrc: u32,
    /// Packets lost, in 1/256.
    pub loss_rate: u8,
    pub discard_rate: u8,
    pub burst_density: u8,
    pub gap_density: u8,
    pub burst_duration_ms: u16,
    pub gap_duration_ms: u16,
    pub round_trip_ms: u16,
    pub end_system_delay_ms: u16,
    pub signal_level_dbm: i8,
    pub noise_level_dbm: i8,
    pub rerl_db: u8,
    pub gmin: u8,
    /// 127 means unavailable.
    pub r_factor: u8,
    pub ext_r_factor: u8,
    /// MOS × 10; 127 means unavailable.
    pub mos_lq: u8,
    pub mos_cq: u8,
    pub jb_nominal_ms: u16,
    pub jb_max_ms: u16,
    pub jb_abs_max_ms: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RtcpPacket {
    Sr {
        ssrc: u32,
        ntp_sec: u32,
        ntp_frac: u32,
        rtp_ts: u32,
        packets: u32,
        octets: u32,
        blocks: Vec<ReportBlock>,
    },
    Rr {
        ssrc: u32,
        blocks: Vec<ReportBlock>,
    },
    Sdes {
        ssrc: u32,
        cname: String,
    },
    Bye {
        ssrcs: Vec<u32>,
    },
    Xr {
        ssrc: u32,
        voip: Vec<VoipMetrics>,
    },
    Other {
        pt: u8,
    },
}

fn u16be(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn u32be(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn blocks(b: &[u8], at: usize, count: usize) -> Vec<ReportBlock> {
    let mut v = Vec::new();
    for k in 0..count {
        let o = at + k * 24;
        if o + 24 > b.len() {
            break;
        }
        let cum = ((b[o + 5] as i32) << 16) | ((b[o + 6] as i32) << 8) | b[o + 7] as i32;
        // 24-bit signed.
        let cum = if cum & 0x80_0000 != 0 {
            cum - 0x100_0000
        } else {
            cum
        };
        v.push(ReportBlock {
            ssrc: u32be(b, o),
            fraction_lost: b[o + 4],
            cumulative_lost: cum,
            highest_seq: u32be(b, o + 8),
            jitter: u32be(b, o + 12),
            lsr: u32be(b, o + 16),
            dlsr: u32be(b, o + 20),
        });
    }
    v
}

/// Parses a compound RTCP packet; empty when it is not RTCP.
pub fn parse_compound(b: &[u8]) -> Vec<RtcpPacket> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= b.len() {
        if b[i] >> 6 != 2 {
            break;
        }
        let count = (b[i] & 0x1f) as usize;
        let pt = b[i + 1];
        let len = (u16be(b, i + 2) as usize + 1) * 4;
        if i + len > b.len() || len < 4 {
            break;
        }
        let p = &b[i..i + len];
        let pkt = match pt {
            200 if p.len() >= 28 => RtcpPacket::Sr {
                ssrc: u32be(p, 4),
                ntp_sec: u32be(p, 8),
                ntp_frac: u32be(p, 12),
                rtp_ts: u32be(p, 16),
                packets: u32be(p, 20),
                octets: u32be(p, 24),
                blocks: blocks(p, 28, count),
            },
            201 if p.len() >= 8 => RtcpPacket::Rr {
                ssrc: u32be(p, 4),
                blocks: blocks(p, 8, count),
            },
            202 if p.len() >= 8 => {
                // First chunk, CNAME item (type 1).
                let ssrc = u32be(p, 4);
                let mut cname = String::new();
                let mut k = 8;
                while k + 2 <= p.len() && p[k] != 0 {
                    let (t, l) = (p[k], p[k + 1] as usize);
                    if k + 2 + l > p.len() {
                        break;
                    }
                    if t == 1 {
                        cname = String::from_utf8_lossy(&p[k + 2..k + 2 + l]).into_owned();
                        break;
                    }
                    k += 2 + l;
                }
                RtcpPacket::Sdes { ssrc, cname }
            }
            203 => RtcpPacket::Bye {
                ssrcs: (0..count)
                    .filter(|k| 4 + k * 4 + 4 <= p.len())
                    .map(|k| u32be(p, 4 + k * 4))
                    .collect(),
            },
            207 if p.len() >= 8 => {
                let ssrc = u32be(p, 4);
                let mut voip = Vec::new();
                let mut k = 8;
                while k + 4 <= p.len() {
                    let bt = p[k];
                    let blen = (u16be(p, k + 2) as usize + 1) * 4;
                    if k + blen > p.len() {
                        break;
                    }
                    if bt == 7 && blen >= 36 {
                        let q = &p[k..k + blen];
                        voip.push(VoipMetrics {
                            ssrc: u32be(q, 4),
                            loss_rate: q[8],
                            discard_rate: q[9],
                            burst_density: q[10],
                            gap_density: q[11],
                            burst_duration_ms: u16be(q, 12),
                            gap_duration_ms: u16be(q, 14),
                            round_trip_ms: u16be(q, 16),
                            end_system_delay_ms: u16be(q, 18),
                            signal_level_dbm: q[20] as i8,
                            noise_level_dbm: q[21] as i8,
                            rerl_db: q[22],
                            gmin: q[23],
                            r_factor: q[24],
                            ext_r_factor: q[25],
                            mos_lq: q[26],
                            mos_cq: q[27],
                            jb_nominal_ms: u16be(q, 30),
                            jb_max_ms: u16be(q, 32),
                            jb_abs_max_ms: u16be(q, 34),
                        });
                    }
                    k += blen;
                }
                RtcpPacket::Xr { ssrc, voip }
            }
            _ => RtcpPacket::Other { pt },
        };
        out.push(pkt);
        i += len;
    }
    out
}

/// One RTCP observation about a stream, as the Report shows it.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RtcpView {
    /// Seconds from the start of the capture.
    pub t: f64,
    pub frame: usize,
    /// Who sent the report (the receiver of the stream for RR/XR).
    pub from: String,
    /// "SR", "RR" or "XR".
    pub kind: String,
    pub fraction_lost_pct: Option<f64>,
    pub cumulative_lost: Option<i64>,
    pub jitter_ms: Option<f64>,
    /// Round trip seen by the stream's sender, from LSR/DLSR (RFC 3550 6.4.1).
    pub rtt_ms: Option<f64>,
    pub mos_lq: Option<f64>,
    pub mos_cq: Option<f64>,
    pub r_factor: Option<f64>,
    pub discard_pct: Option<f64>,
    pub jb_nominal_ms: Option<u16>,
    /// SR only: what the sender says it sent.
    pub sender_packets: Option<u32>,
}

/// RFC 6035 voice-quality report carried in SIP PUBLISH (application/vq-rtcpxr).
#[derive(Debug, Clone, Serialize, Default)]
pub struct VqReport {
    pub message: usize,
    pub call_id: Option<String>,
    /// "local" or "remote" metrics section.
    pub side: String,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub codec: Option<String>,
    pub loss_pct: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub mos_lq: Option<f64>,
    pub mos_cq: Option<f64>,
    pub r_lq: Option<f64>,
}

/// Parses the body of an application/vq-rtcpxr PUBLISH: one report per
/// LocalMetrics or RemoteMetrics section.
pub fn parse_vq(body: &str, message: usize) -> Vec<VqReport> {
    let mut out: Vec<VqReport> = Vec::new();
    let mut call_id = None;
    let mut cur: Option<VqReport> = None;
    let num = |s: &str, key: &str| -> Option<f64> {
        s.split_whitespace()
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
            .and_then(|v| v.parse::<f64>().ok())
    };
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let (k, v) = match l.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (l, ""),
        };
        match k {
            "CallID" => call_id = Some(v.to_string()),
            "LocalMetrics" | "RemoteMetrics" => {
                if let Some(r) = cur.take() {
                    out.push(r);
                }
                cur = Some(VqReport {
                    message,
                    side: if k == "LocalMetrics" {
                        "local"
                    } else {
                        "remote"
                    }
                    .into(),
                    ..Default::default()
                });
            }
            _ => {
                let Some(r) = cur.as_mut() else { continue };
                match k {
                    "LocalAddr" => {
                        r.local_addr = Some(format!(
                            "{}:{}",
                            v.split_whitespace()
                                .find_map(|x| x.strip_prefix("IP="))
                                .unwrap_or(""),
                            v.split_whitespace()
                                .find_map(|x| x.strip_prefix("PORT="))
                                .unwrap_or("")
                        ))
                    }
                    "RemoteAddr" => {
                        r.remote_addr = Some(format!(
                            "{}:{}",
                            v.split_whitespace()
                                .find_map(|x| x.strip_prefix("IP="))
                                .unwrap_or(""),
                            v.split_whitespace()
                                .find_map(|x| x.strip_prefix("PORT="))
                                .unwrap_or("")
                        ))
                    }
                    "PayloadDesc" => {
                        r.codec = v
                            .split_whitespace()
                            .find_map(|x| x.strip_prefix("PD="))
                            .map(|s| s.to_string())
                            .or_else(|| Some(v.to_string()))
                    }
                    "PacketLoss" => r.loss_pct = num(v, "NLR").map(|x| x * 100.0 / 256.0),
                    "JitterBuffer" => r.jitter_ms = num(v, "JBN"),
                    "Delay" => r.rtt_ms = num(v, "RTD"),
                    "QualityEst" => {
                        r.mos_lq = num(v, "MOSLQ");
                        r.mos_cq = num(v, "MOSCQ");
                        r.r_lq = num(v, "RLQ").or_else(|| num(v, "RCQ"));
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(r) = cur.take() {
        out.push(r);
    }
    for r in &mut out {
        r.call_id = call_id.clone();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sr_with_block_and_sdes() {
        let mut p = vec![0x81, 200, 0, 12];
        p.extend_from_slice(&0x1111_1111u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1, 0x80, 0, 0, 0]); // NTP
        p.extend_from_slice(&160u32.to_be_bytes());
        p.extend_from_slice(&50u32.to_be_bytes());
        p.extend_from_slice(&8000u32.to_be_bytes());
        // report block about 0x22222222: 25% lost, 3 cumulative, jitter 80
        p.extend_from_slice(&0x2222_2222u32.to_be_bytes());
        p.extend_from_slice(&[64, 0, 0, 3]);
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&80u32.to_be_bytes());
        p.extend_from_slice(&0x0001_8000u32.to_be_bytes());
        p.extend_from_slice(&0x0000_8000u32.to_be_bytes());
        let mut sdes = vec![0x81, 202, 0, 3];
        sdes.extend_from_slice(&0x1111_1111u32.to_be_bytes());
        sdes.extend_from_slice(&[1, 2, b'a', b'b', 0, 0, 0, 0]);
        p.extend(sdes);
        let v = parse_compound(&p);
        assert_eq!(v.len(), 2);
        match &v[0] {
            RtcpPacket::Sr {
                packets, blocks, ..
            } => {
                assert_eq!(*packets, 50);
                assert_eq!(blocks[0].fraction_lost, 64);
                assert_eq!(blocks[0].cumulative_lost, 3);
                assert_eq!(blocks[0].jitter, 80);
            }
            x => panic!("{x:?}"),
        }
        match &v[1] {
            RtcpPacket::Sdes { cname, .. } => assert_eq!(cname, "ab"),
            x => panic!("{x:?}"),
        }
    }

    #[test]
    fn parses_vq_rtcpxr() {
        let body = "VQSessionReport: CallTerm\r\nCallID: abc@host\r\nLocalMetrics:\r\nTimestamps: START=2026-01-01T10:00:00Z STOP=2026-01-01T10:01:00Z\r\nLocalAddr: IP=10.0.0.5 PORT=4000 SSRC=0x1234\r\nRemoteAddr: IP=10.0.0.9 PORT=5000 SSRC=0x5678\r\nPayloadDesc: PT=0 PD=PCMU SR=8000\r\nPacketLoss: NLR=5.0 JDR=0.0\r\nJitterBuffer: JBA=3 JBR=2 JBN=40 JBM=80 JBX=240\r\nDelay: RTD=120 ESD=60\r\nQualityEst: RLQ=88 MOSLQ=4.1 MOSCQ=4.0\r\n";
        let v = parse_vq(body, 3);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].call_id.as_deref(), Some("abc@host"));
        assert_eq!(v[0].mos_lq, Some(4.1));
        assert_eq!(v[0].rtt_ms, Some(120.0));
        assert_eq!(v[0].codec.as_deref(), Some("PCMU"));
    }
}
