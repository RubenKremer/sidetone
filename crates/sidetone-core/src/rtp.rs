//! RTP/RTCP detection and per-stream quality statistics (RFC 3550),
//! plus an ITU-T G.107 E-model estimate of listening quality.

use serde::Serialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    pub marker: bool,
    pub pt: u8,
    pub seq: u16,
    pub ts: u32,
    pub ssrc: u32,
    pub payload_offset: usize,
}

/// Parses an RTP header if the payload looks like RTP (not RTCP).
pub fn parse_rtp(b: &[u8]) -> Option<RtpHeader> {
    if b.len() < 12 || b[0] >> 6 != 2 {
        return None;
    }
    let pt = b[1] & 0x7f;
    if (72..=78).contains(&pt) {
        return None; // RTCP range when the marker bit is folded in
    }
    let cc = (b[0] & 0x0f) as usize;
    let mut off = 12 + cc * 4;
    if off > b.len() {
        return None;
    }
    if b[0] & 0x10 != 0 {
        // Header extension.
        if off + 4 > b.len() {
            return None;
        }
        let words = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        off += 4 + words * 4;
        if off > b.len() {
            return None;
        }
    }
    Some(RtpHeader {
        marker: b[1] & 0x80 != 0,
        pt,
        seq: u16::from_be_bytes([b[2], b[3]]),
        ts: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        payload_offset: off,
    })
}

/// True if the payload looks like an RTCP compound packet.
pub fn is_rtcp(b: &[u8]) -> bool {
    b.len() >= 8 && b[0] >> 6 == 2 && (200..=206).contains(&b[1])
}

/// A single observed RTP packet, retained until stream statistics are computed.
#[derive(Debug, Clone)]
pub struct RtpObs {
    pub frame: usize,
    pub arrival_ns: i64,
    pub hdr: RtpHeader,
    pub payload_len: usize,
    /// First payload bytes, used for RFC 4733 telephone-event decoding.
    pub head: [u8; 4],
}

#[derive(Debug, Clone, Serialize)]
pub struct RtpStream {
    pub id: usize,
    pub src: String,
    pub dst: String,
    pub ssrc: String,
    pub payload_types: Vec<u8>,
    pub codec: String,
    pub clock_rate: u32,
    pub packets: u64,
    pub bytes: u64,
    pub start_ns: i64,
    pub end_ns: i64,
    pub duration_s: f64,
    pub expected: u64,
    pub lost: i64,
    pub loss_pct: f64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub seq_jumps: u64,
    pub jitter_ms: f64,
    pub max_jitter_ms: f64,
    pub max_gap_ms: f64,
    pub mean_ptime_ms: f64,
    pub dtmf_events: Vec<String>,
    pub mos: Option<f64>,
    pub r_factor: Option<f64>,
    pub call: Option<usize>,
    /// Frame numbers of the first and last packet.
    pub first_frame: usize,
    pub last_frame: usize,
    #[serde(skip)]
    pub src_addr: Option<SocketAddr>,
    #[serde(skip)]
    pub dst_addr: Option<SocketAddr>,
}

/// Computes stream statistics from packets of one (src, dst, ssrc) flow.
/// `clock_of` maps a payload type to its clock rate, `name_of` to a codec name,
/// `dtmf_pt` is the negotiated telephone-event payload type, if any.
pub fn compute_stream(
    id: usize,
    src: SocketAddr,
    dst: SocketAddr,
    obs: &[RtpObs],
    clock_of: &dyn Fn(u8) -> u32,
    name_of: &dyn Fn(u8) -> String,
    dtmf_pt: Option<u8>,
) -> RtpStream {
    let mut pts: Vec<u8> = Vec::new();
    for o in obs {
        if !pts.contains(&o.hdr.pt) {
            pts.push(o.hdr.pt);
        }
    }
    // The main codec is the most frequent non-DTMF, non-CN payload type.
    let main_pt = {
        let mut counts: Vec<(u8, usize)> = Vec::new();
        for o in obs {
            if Some(o.hdr.pt) == dtmf_pt || o.hdr.pt == 13 {
                continue;
            }
            match counts.iter_mut().find(|c| c.0 == o.hdr.pt) {
                Some(c) => c.1 += 1,
                None => counts.push((o.hdr.pt, 1)),
            }
        }
        counts
            .iter()
            .max_by_key(|c| c.1)
            .map(|c| c.0)
            .unwrap_or_else(|| pts.first().copied().unwrap_or(0))
    };
    let clock = clock_of(main_pt).max(1);

    // Sequence accounting with 16-bit wrap handling.
    let mut seen = std::collections::HashSet::new();
    let mut max_ext: i64 = -1;
    let mut base_ext: i64 = -1;
    let mut dups = 0u64;
    let mut ooo = 0u64;
    let mut jumps = 0u64;
    let mut received = 0u64;
    let mut bytes = 0u64;

    let mut jitter = 0f64; // in timestamp units
    let mut max_jitter = 0f64;
    let mut prev_transit: Option<f64> = None;
    let mut max_gap_ns: i64 = 0;
    let mut prev_arrival: Option<i64> = None;
    let mut ptime_sum = 0f64;
    let mut ptime_n = 0u64;
    let mut prev_ts: Option<(u32, u16)> = None;
    let mut dtmf_events: Vec<String> = Vec::new();
    let mut last_dtmf_ts: Option<u32> = None;

    for o in obs {
        received += 1;
        bytes += o.payload_len as u64;
        let seq = o.hdr.seq as i64;
        // Extend the 16-bit sequence to the value closest to the highest seen so far.
        let ext = if max_ext < 0 {
            seq
        } else {
            let mut e = (max_ext & !0xffff) | seq;
            if e - max_ext > 32768 {
                e -= 65536;
            } else if max_ext - e > 32768 {
                e += 65536;
            }
            e
        };
        if !seen.insert(ext) {
            dups += 1;
            continue;
        }
        if base_ext < 0 {
            base_ext = ext;
        }
        if max_ext >= 0 && ext < max_ext {
            ooo += 1;
        } else if max_ext >= 0 && ext - max_ext > 1000 {
            jumps += 1;
        }
        if ext > max_ext {
            max_ext = ext;
        }
        if ext < base_ext {
            base_ext = ext;
        }

        if let Some(pa) = prev_arrival {
            max_gap_ns = max_gap_ns.max(o.arrival_ns - pa);
        }
        prev_arrival = Some(o.arrival_ns);

        if Some(o.hdr.pt) == dtmf_pt {
            // RFC 4733: event, E|R|volume, duration. Count one event per timestamp at its end packet.
            if o.head[1] & 0x80 != 0 && last_dtmf_ts != Some(o.hdr.ts) {
                last_dtmf_ts = Some(o.hdr.ts);
                let ev = o.head[0];
                let digit = match ev {
                    0..=9 => (b'0' + ev) as char,
                    10 => '*',
                    11 => '#',
                    12..=15 => (b'A' + ev - 12) as char,
                    _ => '?',
                };
                dtmf_events.push(digit.to_string());
            }
            continue; // DTMF timestamps do not advance like audio; skip jitter
        }
        if o.hdr.pt != main_pt {
            continue;
        }
        let arrival_units = o.arrival_ns as f64 * clock as f64 / 1e9;
        let transit = arrival_units - o.hdr.ts as f64;
        if let Some(pt) = prev_transit {
            let mut d = (transit - pt).abs();
            // Guard against timestamp discontinuities (e.g. after hold/resume).
            if d > clock as f64 * 2.0 {
                d = 0.0;
            }
            jitter += (d - jitter) / 16.0;
            max_jitter = f64::max(max_jitter, jitter);
        }
        prev_transit = Some(transit);
        if let Some((pts, pseq)) = prev_ts {
            let dt = o.hdr.ts.wrapping_sub(pts);
            if o.hdr.seq.wrapping_sub(pseq) == 1 && dt > 0 && dt < clock * 2 {
                ptime_sum += dt as f64 * 1000.0 / clock as f64;
                ptime_n += 1;
            }
        }
        prev_ts = Some((o.hdr.ts, o.hdr.seq));
    }

    let expected = if max_ext >= base_ext && base_ext >= 0 {
        (max_ext - base_ext + 1) as u64
    } else {
        0
    };
    let unique = received - dups;
    let lost = expected as i64 - unique as i64;
    let loss_pct = if expected > 0 {
        (lost.max(0) as f64) * 100.0 / expected as f64
    } else {
        0.0
    };
    let start_ns = obs.first().map(|o| o.arrival_ns).unwrap_or(0);
    let end_ns = obs.last().map(|o| o.arrival_ns).unwrap_or(0);
    let jitter_ms = jitter * 1000.0 / clock as f64;
    let max_jitter_ms = max_jitter * 1000.0 / clock as f64;
    let codec = name_of(main_pt);
    let (r, mos) = if unique >= 10 {
        emodel(&codec, loss_pct, jitter_ms)
    } else {
        (None, None)
    };

    RtpStream {
        id,
        src: src.to_string(),
        dst: dst.to_string(),
        ssrc: obs
            .first()
            .map(|o| format!("0x{:08X}", o.hdr.ssrc))
            .unwrap_or_default(),
        payload_types: pts,
        codec,
        clock_rate: clock,
        packets: received,
        bytes,
        start_ns,
        end_ns,
        duration_s: (end_ns - start_ns) as f64 / 1e9,
        expected,
        lost,
        loss_pct: round2(loss_pct),
        duplicates: dups,
        out_of_order: ooo,
        seq_jumps: jumps,
        jitter_ms: round2(jitter_ms),
        max_jitter_ms: round2(max_jitter_ms),
        max_gap_ms: round2(max_gap_ns as f64 / 1e6),
        mean_ptime_ms: if ptime_n > 0 {
            round2(ptime_sum / ptime_n as f64)
        } else {
            0.0
        },
        dtmf_events,
        mos,
        r_factor: r,
        call: None,
        first_frame: obs.first().map(|o| o.frame).unwrap_or(0),
        last_frame: obs.last().map(|o| o.frame).unwrap_or(0),
        src_addr: Some(src),
        dst_addr: Some(dst),
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Simplified ITU-T G.107 E-model. Network delay is unknown from a single
/// capture point, so mouth-to-ear delay is approximated from packetization,
/// a jitter buffer sized at twice the jitter, and a nominal 20 ms transit.
pub fn emodel(codec: &str, loss_pct: f64, jitter_ms: f64) -> (Option<f64>, Option<f64>) {
    let c = codec.to_ascii_uppercase();
    let (ie, bpl) = if c.starts_with("PCM") || c == "G711" {
        (0.0, 25.1)
    } else if c.starts_with("G729") {
        (11.0, 19.0)
    } else if c.starts_with("G722") {
        (0.0, 20.0)
    } else if c.starts_with("OPUS") {
        (0.0, 20.0)
    } else if c.starts_with("GSM") {
        (20.0, 10.0)
    } else if c.starts_with("ILBC") {
        (10.0, 32.0)
    } else {
        (0.0, 20.0)
    };
    let ta = 20.0 + 20.0 + 2.0 * jitter_ms + 20.0;
    let id = 0.024 * ta + if ta > 177.3 { 0.11 * (ta - 177.3) } else { 0.0 };
    let ppl = loss_pct.max(0.0);
    let ie_eff = ie + (95.0 - ie) * ppl / (ppl + bpl);
    let r = (93.2 - id - ie_eff).clamp(0.0, 100.0);
    let mos = if r <= 0.0 {
        1.0
    } else if r >= 100.0 {
        4.5
    } else {
        1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6
    };
    (Some(round2(r)), Some(round2(mos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(seq: u16, ts: u32, t_ms: i64) -> RtpObs {
        RtpObs {
            frame: seq as usize,
            arrival_ns: t_ms * 1_000_000,
            hdr: RtpHeader {
                marker: false,
                pt: 0,
                seq,
                ts,
                ssrc: 7,
                payload_offset: 12,
            },
            payload_len: 160,
            head: [0; 4],
        }
    }

    #[test]
    fn loss_and_wrap() {
        let mut v = Vec::new();
        let mut seq: u16 = 65530;
        for i in 0..20u32 {
            if i != 10 {
                v.push(pkt(seq, i * 160, i as i64 * 20));
            }
            seq = seq.wrapping_add(1);
        }
        let s = compute_stream(
            0,
            "1.1.1.1:1".parse().unwrap(),
            "2.2.2.2:2".parse().unwrap(),
            &v,
            &|_| 8000,
            &|_| "PCMU".into(),
            None,
        );
        assert_eq!(s.expected, 20);
        assert_eq!(s.lost, 1);
        assert_eq!(s.mean_ptime_ms, 20.0);
        assert!(s.jitter_ms < 0.01);
        assert!(s.mos.unwrap() > 3.5);
    }

    #[test]
    fn emodel_clean_g711() {
        let (r, mos) = emodel("PCMU", 0.0, 0.0);
        assert!(r.unwrap() > 90.0);
        assert!(mos.unwrap() > 4.3);
    }
}
