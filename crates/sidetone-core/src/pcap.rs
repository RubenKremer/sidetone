//! Reading of classic pcap / pcapng captures and writing of annotated pcapng.
//!
//! The writer supports per-packet comments (shown by Wireshark as packet
//! comments) and a Decryption Secrets Block carrying a TLS key log, so a
//! receiver can open the file and see SIP over TLS already decrypted.

use std::fmt;

/// Link-layer types we understand.
pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

/// pcapng secrets type for a TLS key log (SSLKEYLOGFILE format).
pub const SECRETS_TYPE_TLS: u32 = 0x544c_534b;

#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub ts_ns: i64,
    pub linktype: u32,
    pub data: Vec<u8>,
    /// Original length on the wire (may be larger than `data` when truncated).
    pub orig_len: u32,
    pub comment: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct Capture {
    pub packets: Vec<RawPacket>,
    /// TLS key log lines found in pcapng Decryption Secrets Blocks.
    pub tls_keylog: Vec<String>,
    pub format: CaptureFormat,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureFormat {
    #[default]
    Pcap,
    Pcapng,
}

#[derive(Debug)]
pub enum PcapError {
    TooShort,
    BadMagic(u32),
    Truncated(&'static str),
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::TooShort => write!(f, "file too short to be a capture"),
            PcapError::BadMagic(m) => write!(f, "not a pcap/pcapng file (magic 0x{m:08x})"),
            PcapError::Truncated(w) => write!(f, "capture truncated while reading {w}"),
        }
    }
}

impl std::error::Error for PcapError {}

#[derive(Clone, Copy)]
struct Endian(bool); // true = little endian

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.0 {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    }
}

/// Parses a classic pcap or a pcapng file from memory.
pub fn read_capture(bytes: &[u8]) -> Result<Capture, PcapError> {
    if bytes.len() < 12 {
        return Err(PcapError::TooShort);
    }
    let magic_be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match magic_be {
        0x0A0D_0D0A => read_pcapng(bytes),
        0xa1b2_c3d4 | 0xa1b2_3c4d | 0xd4c3_b2a1 | 0x4d3c_b2a1 => read_pcap(bytes),
        other => Err(PcapError::BadMagic(other)),
    }
}

fn read_pcap(bytes: &[u8]) -> Result<Capture, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::TooShort);
    }
    let magic_be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (e, nanos) = match magic_be {
        0xa1b2_c3d4 => (Endian(false), false),
        0xa1b2_3c4d => (Endian(false), true),
        0xd4c3_b2a1 => (Endian(true), false),
        0x4d3c_b2a1 => (Endian(true), true),
        m => return Err(PcapError::BadMagic(m)),
    };
    // The link type occupies the low 16 bits; upper bits may carry FCS info.
    let linktype = e.u32(&bytes[20..24]) & 0xffff;
    let mut cap = Capture {
        format: CaptureFormat::Pcap,
        ..Default::default()
    };
    let mut off = 24;
    while off + 16 <= bytes.len() {
        let sec = e.u32(&bytes[off..]) as i64;
        let frac = e.u32(&bytes[off + 4..]) as i64;
        let incl = e.u32(&bytes[off + 8..]) as usize;
        let orig = e.u32(&bytes[off + 12..]);
        off += 16;
        if off + incl > bytes.len() {
            break; // tolerate a truncated last record
        }
        let ts_ns = sec * 1_000_000_000 + if nanos { frac } else { frac * 1000 };
        cap.packets.push(RawPacket {
            ts_ns,
            linktype,
            data: bytes[off..off + incl].to_vec(),
            orig_len: orig,
            comment: None,
        });
        off += incl;
    }
    Ok(cap)
}

struct Interface {
    linktype: u32,
    /// Timestamp units per second.
    ts_units: u64,
}

fn read_pcapng(bytes: &[u8]) -> Result<Capture, PcapError> {
    let mut cap = Capture {
        format: CaptureFormat::Pcapng,
        ..Default::default()
    };
    let mut ifaces: Vec<Interface> = Vec::new();
    let mut e = Endian(true);
    let mut off = 0usize;
    while off + 12 <= bytes.len() {
        let btype_raw = &bytes[off..off + 4];
        // A Section Header Block resets byte order and interfaces.
        if btype_raw == [0x0A, 0x0D, 0x0D, 0x0A] {
            if off + 12 > bytes.len() {
                return Err(PcapError::Truncated("section header"));
            }
            let bom = &bytes[off + 8..off + 12];
            e = if bom == [0x4D, 0x3C, 0x2B, 0x1A] {
                Endian(true)
            } else {
                Endian(false)
            };
            ifaces.clear();
        }
        let btype = e.u32(btype_raw);
        let blen = e.u32(&bytes[off + 4..]) as usize;
        if blen < 12 || off + blen > bytes.len() {
            break;
        }
        let body = &bytes[off + 8..off + blen - 4];
        match btype {
            0x0A0D_0D0A => {}
            1 => {
                // Interface Description Block.
                if body.len() >= 8 {
                    let linktype = e.u16(&body[0..]) as u32;
                    let mut ts_units = 1_000_000u64;
                    for (code, val) in iter_options(&body[8..], e) {
                        if code == 9 && !val.is_empty() {
                            let v = val[0];
                            ts_units = if v & 0x80 != 0 {
                                1u64 << (v & 0x7f).min(63)
                            } else {
                                10u64.saturating_pow((v as u32).min(19))
                            };
                        }
                    }
                    ifaces.push(Interface { linktype, ts_units });
                }
            }
            6 => {
                // Enhanced Packet Block.
                if body.len() >= 20 {
                    let if_id = e.u32(&body[0..]) as usize;
                    let ts = ((e.u32(&body[4..]) as u64) << 32) | e.u32(&body[8..]) as u64;
                    let caplen = e.u32(&body[12..]) as usize;
                    let orig = e.u32(&body[16..]);
                    if 20 + caplen <= body.len() {
                        let data = body[20..20 + caplen].to_vec();
                        let padded = (caplen + 3) & !3;
                        let mut comment = None;
                        if 20 + padded <= body.len() {
                            for (code, val) in iter_options(&body[20 + padded..], e) {
                                if code == 1 {
                                    comment = Some(String::from_utf8_lossy(val).into_owned());
                                }
                            }
                        }
                        let (linktype, units) = ifaces
                            .get(if_id)
                            .map(|i| (i.linktype, i.ts_units))
                            .unwrap_or((LINKTYPE_ETHERNET, 1_000_000));
                        let ts_ns = ticks_to_ns(ts, units);
                        cap.packets.push(RawPacket {
                            ts_ns,
                            linktype,
                            data,
                            orig_len: orig,
                            comment,
                        });
                    }
                }
            }
            3 => {
                // Simple Packet Block: no timestamp, interface 0.
                if body.len() >= 4 {
                    let orig = e.u32(&body[0..]);
                    let caplen = (orig as usize).min(body.len() - 4);
                    let linktype = ifaces
                        .first()
                        .map(|i| i.linktype)
                        .unwrap_or(LINKTYPE_ETHERNET);
                    let ts_ns = cap.packets.last().map(|p| p.ts_ns).unwrap_or(0);
                    cap.packets.push(RawPacket {
                        ts_ns,
                        linktype,
                        data: body[4..4 + caplen].to_vec(),
                        orig_len: orig,
                        comment: None,
                    });
                }
            }
            0x0000_000A => {
                // Decryption Secrets Block.
                if body.len() >= 8 {
                    let stype = e.u32(&body[0..]);
                    let slen = e.u32(&body[4..]) as usize;
                    if stype == SECRETS_TYPE_TLS && 8 + slen <= body.len() {
                        let text = String::from_utf8_lossy(&body[8..8 + slen]);
                        cap.tls_keylog.extend(
                            text.lines()
                                .filter(|l| !l.trim().is_empty())
                                .map(|l| l.to_string()),
                        );
                    }
                }
            }
            _ => {}
        }
        off += blen;
    }
    Ok(cap)
}

fn ticks_to_ns(ticks: u64, units: u64) -> i64 {
    if units == 1_000_000_000 {
        ticks as i64
    } else {
        ((ticks as u128 * 1_000_000_000u128) / units.max(1) as u128) as i64
    }
}

fn iter_options(mut b: &[u8], e: Endian) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let code = e.u16(b);
        let len = e.u16(&b[2..]) as usize;
        if code == 0 {
            break;
        }
        if 4 + len > b.len() {
            break;
        }
        out.push((code, &b[4..4 + len]));
        let adv = 4 + ((len + 3) & !3);
        if adv > b.len() {
            break;
        }
        b = &b[adv..];
    }
    out
}

/// A packet to be written into a pcapng file.
#[derive(Debug, Clone)]
pub struct OutPacket<'a> {
    pub ts_ns: i64,
    pub linktype: u32,
    pub data: &'a [u8],
    pub orig_len: u32,
    pub comment: Option<String>,
}

/// Options for the pcapng writer.
#[derive(Debug, Default, Clone)]
pub struct PcapngOptions {
    /// Application name recorded in the section header.
    pub user_appl: Option<String>,
    /// Section-level comment.
    pub section_comment: Option<String>,
    /// TLS key log lines (SSLKEYLOGFILE format) embedded in a Decryption Secrets Block.
    pub tls_keylog: Vec<String>,
}

/// Writes packets as little-endian pcapng with nanosecond timestamps.
/// One interface is created per distinct link type.
pub fn write_pcapng(packets: &[OutPacket<'_>], opts: &PcapngOptions) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(packets.iter().map(|p| p.data.len() + 48).sum::<usize>() + 256);

    // Section Header Block.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    let mut shb_opts = Vec::new();
    if let Some(c) = &opts.section_comment {
        push_option(&mut shb_opts, 1, c.as_bytes());
    }
    if let Some(a) = &opts.user_appl {
        push_option(&mut shb_opts, 4, a.as_bytes());
    }
    if !shb_opts.is_empty() {
        push_option(&mut shb_opts, 0, &[]);
        shb.extend_from_slice(&shb_opts);
    }
    push_block(&mut out, 0x0A0D_0D0A, &shb);

    // Interface Description Blocks.
    let mut linktypes: Vec<u32> = Vec::new();
    for p in packets {
        if !linktypes.contains(&p.linktype) {
            linktypes.push(p.linktype);
        }
    }
    if linktypes.is_empty() {
        linktypes.push(LINKTYPE_RAW);
    }
    for lt in &linktypes {
        let mut idb = Vec::new();
        idb.extend_from_slice(&(*lt as u16).to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&0u32.to_le_bytes()); // snaplen: unlimited
        let mut o = Vec::new();
        push_option(&mut o, 9, &[9u8]); // if_tsresol = 10^-9
        push_option(&mut o, 0, &[]);
        idb.extend_from_slice(&o);
        push_block(&mut out, 1, &idb);
    }

    // Decryption Secrets Block must precede the packets it decrypts.
    if !opts.tls_keylog.is_empty() {
        let mut text = opts.tls_keylog.join("\n");
        text.push('\n');
        let mut dsb = Vec::new();
        dsb.extend_from_slice(&SECRETS_TYPE_TLS.to_le_bytes());
        dsb.extend_from_slice(&(text.len() as u32).to_le_bytes());
        dsb.extend_from_slice(text.as_bytes());
        pad4(&mut dsb);
        push_block(&mut out, 0x0000_000A, &dsb);
    }

    for p in packets {
        let if_id = linktypes.iter().position(|l| *l == p.linktype).unwrap_or(0) as u32;
        let ts = p.ts_ns.max(0) as u64;
        let mut epb = Vec::with_capacity(p.data.len() + 64);
        epb.extend_from_slice(&if_id.to_le_bytes());
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts as u32).to_le_bytes());
        epb.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&p.orig_len.max(p.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(p.data);
        pad4(&mut epb);
        if let Some(c) = &p.comment {
            let mut o = Vec::new();
            push_option(&mut o, 1, c.as_bytes());
            push_option(&mut o, 0, &[]);
            epb.extend_from_slice(&o);
        }
        push_block(&mut out, 6, &epb);
    }
    out
}

fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

fn push_option(v: &mut Vec<u8>, code: u16, val: &[u8]) {
    v.extend_from_slice(&code.to_le_bytes());
    v.extend_from_slice(&(val.len() as u16).to_le_bytes());
    v.extend_from_slice(val);
    pad4(v);
}

fn push_block(out: &mut Vec<u8>, btype: u32, body: &[u8]) {
    let total = (body.len() + 12) as u32;
    out.extend_from_slice(&btype.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

/// Writes packets as classic little-endian pcap (microsecond timestamps).
/// All packets must share one link type; the first packet's type is used.
pub fn write_pcap(packets: &[OutPacket<'_>]) -> Vec<u8> {
    let linktype = packets.first().map(|p| p.linktype).unwrap_or(LINKTYPE_RAW);
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());
    for p in packets.iter().filter(|p| p.linktype == linktype) {
        let us = p.ts_ns.max(0) / 1000;
        out.extend_from_slice(&((us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&p.orig_len.max(p.data.len() as u32).to_le_bytes());
        out.extend_from_slice(p.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcapng_roundtrip_with_comment_and_secrets() {
        let data = vec![0x45u8; 40];
        let pk = OutPacket {
            ts_ns: 1_700_000_000_123_456_789,
            linktype: LINKTYPE_RAW,
            data: &data,
            orig_len: 40,
            comment: Some("hello".into()),
        };
        let opts = PcapngOptions {
            tls_keylog: vec!["CLIENT_RANDOM aa bb".into()],
            ..Default::default()
        };
        let bytes = write_pcapng(&[pk], &opts);
        let cap = read_capture(&bytes).unwrap();
        assert_eq!(cap.packets.len(), 1);
        assert_eq!(cap.packets[0].ts_ns, 1_700_000_000_123_456_789);
        assert_eq!(cap.packets[0].comment.as_deref(), Some("hello"));
        assert_eq!(cap.tls_keylog, vec!["CLIENT_RANDOM aa bb".to_string()]);
    }

    #[test]
    fn pcap_roundtrip() {
        let data = vec![1u8, 2, 3];
        let pk = OutPacket {
            ts_ns: 2_000_000_000,
            linktype: LINKTYPE_ETHERNET,
            data: &data,
            orig_len: 3,
            comment: None,
        };
        let cap = read_capture(&write_pcap(&[pk])).unwrap();
        assert_eq!(cap.packets[0].ts_ns, 2_000_000_000);
        assert_eq!(cap.packets[0].linktype, LINKTYPE_ETHERNET);
    }
}
