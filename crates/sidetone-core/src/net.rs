//! Minimal link/IP/transport decoding and synthetic packet construction.

use crate::pcap::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Transport {
    Udp,
    Tcp,
    /// SIP over TLS, captured already decrypted (Wireshark exported PDUs).
    Tls,
}

#[derive(Debug, Clone)]
pub struct Decoded<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub transport: Transport,
    pub payload: &'a [u8],
    /// TCP sequence number (for ordering stream reassembly), 0 for UDP.
    pub tcp_seq: u32,
}

/// Decodes a captured frame down to its UDP/TCP payload.
pub fn decode(linktype: u32, data: &[u8]) -> Option<Decoded<'_>> {
    let (ethertype, ip) = match linktype {
        LINKTYPE_ETHERNET => {
            if data.len() < 14 {
                return None;
            }
            let mut et = u16::from_be_bytes([data[12], data[13]]);
            let mut off = 14;
            // 802.1Q / 802.1ad VLAN tags, possibly stacked.
            while (et == 0x8100 || et == 0x88a8 || et == 0x9100) && data.len() >= off + 4 {
                et = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                off += 4;
            }
            (et, &data[off..])
        }
        LINKTYPE_RAW | 12 | 14 | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            let v = data.first()? >> 4;
            (if v == 6 { 0x86dd } else { 0x0800 }, data)
        }
        LINKTYPE_LINUX_SLL => {
            if data.len() < 16 {
                return None;
            }
            (u16::from_be_bytes([data[14], data[15]]), &data[16..])
        }
        LINKTYPE_LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            (u16::from_be_bytes([data[0], data[1]]), &data[20..])
        }
        LINKTYPE_WIRESHARK_UPPER_PDU => return decode_exported_pdu(data),
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            if data.len() < 4 {
                return None;
            }
            let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let fam = if le < 256 { le } else { be };
            (if fam == 2 { 0x0800 } else { 0x86dd }, &data[4..])
        }
        _ => return None,
    };
    match ethertype {
        0x0800 => decode_ipv4(ip),
        0x86dd => decode_ipv6(ip),
        _ => None,
    }
}

// Wireshark exported PDU tags (epan/exported_pdu.h).
const EXP_PDU_TAG_END: u16 = 0;
const EXP_PDU_TAG_DISSECTOR_NAME: u16 = 12;
const EXP_PDU_TAG_IPV4_SRC: u16 = 20;
const EXP_PDU_TAG_IPV4_DST: u16 = 21;
const EXP_PDU_TAG_IPV6_SRC: u16 = 22;
const EXP_PDU_TAG_IPV6_DST: u16 = 23;
const EXP_PDU_TAG_PORT_TYPE: u16 = 24;
const EXP_PDU_TAG_SRC_PORT: u16 = 25;
const EXP_PDU_TAG_DST_PORT: u16 = 26;
const EXP_PDU_PT_TCP: u32 = 2;

/// Decodes a Wireshark exported PDU carrying SIP (how Wireshark and Sidetone
/// store SIP that travelled over TLS, already decrypted).
fn decode_exported_pdu(data: &[u8]) -> Option<Decoded<'_>> {
    let mut off = 0;
    let mut name: Option<&[u8]> = None;
    let mut src_ip: Option<IpAddr> = None;
    let mut dst_ip: Option<IpAddr> = None;
    let (mut sp, mut dp) = (0u16, 0u16);
    loop {
        if off + 4 > data.len() {
            return None;
        }
        let tag = u16::from_be_bytes([data[off], data[off + 1]]);
        let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        off += 4;
        if tag == EXP_PDU_TAG_END {
            break;
        }
        let v = data.get(off..off + len)?;
        let u32v = || {
            v.get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        };
        match tag {
            EXP_PDU_TAG_DISSECTOR_NAME => {
                let end = v.iter().position(|b| *b == 0).unwrap_or(v.len());
                name = Some(&v[..end]);
            }
            EXP_PDU_TAG_IPV4_SRC if len >= 4 => {
                src_ip = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])))
            }
            EXP_PDU_TAG_IPV4_DST if len >= 4 => {
                dst_ip = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])))
            }
            EXP_PDU_TAG_IPV6_SRC if len >= 16 => {
                src_ip = Some(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&v[..16]).ok()?,
                )))
            }
            EXP_PDU_TAG_IPV6_DST if len >= 16 => {
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&v[..16]).ok()?,
                )))
            }
            EXP_PDU_TAG_SRC_PORT => sp = u32v()? as u16,
            EXP_PDU_TAG_DST_PORT => dp = u32v()? as u16,
            _ => {}
        }
        off += len;
    }
    if !name.is_some_and(|n| n.eq_ignore_ascii_case(b"sip")) {
        return None;
    }
    Some(Decoded {
        src: SocketAddr::new(src_ip?, sp),
        dst: SocketAddr::new(dst_ip?, dp),
        transport: Transport::Tls,
        payload: &data[off..],
        tcp_seq: 0,
    })
}

/// Builds a Wireshark exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU) for one
/// decrypted SIP message received or sent over TLS.
pub fn build_sip_pdu(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    fn tag(out: &mut Vec<u8>, t: u16, v: &[u8]) {
        let padded = (v.len() + 3) & !3;
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(padded as u16).to_be_bytes());
        out.extend_from_slice(v);
        out.extend(std::iter::repeat_n(0u8, padded - v.len()));
    }
    let mut out = Vec::with_capacity(64 + payload.len());
    tag(&mut out, EXP_PDU_TAG_DISSECTOR_NAME, b"sip");
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            tag(&mut out, EXP_PDU_TAG_IPV4_SRC, &s.octets());
            tag(&mut out, EXP_PDU_TAG_IPV4_DST, &d.octets());
        }
        (s, d) => {
            tag(&mut out, EXP_PDU_TAG_IPV6_SRC, &to_v6(s).octets());
            tag(&mut out, EXP_PDU_TAG_IPV6_DST, &to_v6(d).octets());
        }
    }
    tag(
        &mut out,
        EXP_PDU_TAG_PORT_TYPE,
        &EXP_PDU_PT_TCP.to_be_bytes(),
    );
    tag(
        &mut out,
        EXP_PDU_TAG_SRC_PORT,
        &(src.port() as u32).to_be_bytes(),
    );
    tag(
        &mut out,
        EXP_PDU_TAG_DST_PORT,
        &(dst.port() as u32).to_be_bytes(),
    );
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(payload);
    out
}

fn decode_ipv4(ip: &[u8]) -> Option<Decoded<'_>> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x1fff != 0 {
        return None; // non-first fragment
    }
    let end = if total >= ihl && total <= ip.len() {
        total
    } else {
        ip.len()
    };
    if ihl < 20 || ihl > end {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    decode_l4(ip[9], src, dst, &ip[ihl..end])
}

fn decode_ipv6(ip: &[u8]) -> Option<Decoded<'_>> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let mut next = ip[6];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?));
    let end = (40 + plen).min(ip.len());
    let mut off = 40;
    // Walk common extension headers.
    loop {
        match next {
            0 | 43 | 60 => {
                if off + 2 > end {
                    return None;
                }
                let n = ip[off];
                let len = (ip[off + 1] as usize + 1) * 8;
                next = n;
                off += len;
            }
            44 => {
                if off + 8 > end {
                    return None;
                }
                let fo = u16::from_be_bytes([ip[off + 2], ip[off + 3]]) >> 3;
                if fo != 0 {
                    return None;
                }
                next = ip[off];
                off += 8;
            }
            _ => break,
        }
        if off > end {
            return None;
        }
    }
    decode_l4(next, src, dst, &ip[off..end])
}

fn decode_l4(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8]) -> Option<Decoded<'_>> {
    match proto {
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            let ulen = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let end = if ulen >= 8 && ulen <= l4.len() {
                ulen
            } else {
                l4.len()
            };
            Some(Decoded {
                src: SocketAddr::new(src, sp),
                dst: SocketAddr::new(dst, dp),
                transport: Transport::Udp,
                payload: &l4[8..end],
                tcp_seq: 0,
            })
        }
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || doff > l4.len() {
                return None;
            }
            Some(Decoded {
                src: SocketAddr::new(src, sp),
                dst: SocketAddr::new(dst, dp),
                transport: Transport::Tcp,
                payload: &l4[doff..],
                tcp_seq: seq,
            })
        }
        _ => None,
    }
}

fn checksum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn checksum_fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a raw IP (LINKTYPE_RAW) TCP segment with PSH and ACK set.
pub fn build_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    wrap_ip(6, src, dst, tcp, 16)
}

/// Puts a transport segment into an IPv4 or IPv6 header, filling in the
/// transport checksum at `csum_at`.
fn wrap_ip(
    proto: u8,
    src: SocketAddr,
    dst: SocketAddr,
    mut l4: Vec<u8>,
    csum_at: usize,
) -> Vec<u8> {
    let l4_len = l4.len();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + l4_len;
            let mut ip = Vec::with_capacity(total);
            ip.extend_from_slice(&[0x45, 0x00]);
            ip.extend_from_slice(&(total.min(0xffff) as u16).to_be_bytes());
            ip.extend_from_slice(&[0, 0, 0x40, 0x00, 64, proto, 0, 0]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let c = checksum_fold(checksum_add(0, &ip[..20]));
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            let mut sum = checksum_add(0, &s.octets());
            sum = checksum_add(sum, &d.octets());
            sum += proto as u32 + l4_len as u32;
            let c = checksum_fold(checksum_add(sum, &l4));
            l4[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&l4);
            ip
        }
        (s, d) => {
            let s6 = to_v6(s);
            let d6 = to_v6(d);
            let mut ip = Vec::with_capacity(40 + l4_len);
            ip.extend_from_slice(&[0x60, 0, 0, 0]);
            ip.extend_from_slice(&(l4_len.min(0xffff) as u16).to_be_bytes());
            ip.extend_from_slice(&[proto, 64]);
            ip.extend_from_slice(&s6.octets());
            ip.extend_from_slice(&d6.octets());
            let mut sum = checksum_add(0, &s6.octets());
            sum = checksum_add(sum, &d6.octets());
            sum += l4_len as u32 + proto as u32;
            let c = checksum_fold(checksum_add(sum, &l4));
            l4[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&l4);
            ip
        }
    }
}

/// Builds a raw IP (LINKTYPE_RAW) UDP packet. IPv4 and IPv6 are supported;
/// mixed families fall back to mapping the IPv4 side into IPv6.
pub fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&(udp_len.min(0xffff) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + udp_len;
            let mut ip = Vec::with_capacity(total);
            ip.extend_from_slice(&[0x45, 0x00]);
            ip.extend_from_slice(&(total.min(0xffff) as u16).to_be_bytes());
            ip.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 17, 0, 0]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let c = checksum_fold(checksum_add(0, &ip[..20]));
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            // UDP checksum over IPv4 pseudo-header.
            let mut sum = checksum_add(0, &s.octets());
            sum = checksum_add(sum, &d.octets());
            sum += 17 + udp_len as u32;
            let mut uc = checksum_fold(checksum_add(sum, &udp));
            if uc == 0 {
                uc = 0xffff;
            }
            udp[6..8].copy_from_slice(&uc.to_be_bytes());
            ip.extend_from_slice(&udp);
            ip
        }
        (s, d) => {
            let s6 = to_v6(s);
            let d6 = to_v6(d);
            let mut ip = Vec::with_capacity(40 + udp_len);
            ip.extend_from_slice(&[0x60, 0, 0, 0]);
            ip.extend_from_slice(&(udp_len.min(0xffff) as u16).to_be_bytes());
            ip.extend_from_slice(&[17, 64]);
            ip.extend_from_slice(&s6.octets());
            ip.extend_from_slice(&d6.octets());
            let mut sum = checksum_add(0, &s6.octets());
            sum = checksum_add(sum, &d6.octets());
            sum += udp_len as u32 + 17;
            let mut uc = checksum_fold(checksum_add(sum, &udp));
            if uc == 0 {
                uc = 0xffff;
            }
            udp[6..8].copy_from_slice(&uc.to_be_bytes());
            ip.extend_from_slice(&udp);
            ip
        }
    }
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// True for RFC 1918, CGNAT, loopback, link-local and ULA addresses.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exported_pdu_and_tcp_roundtrip() {
        let a: std::net::SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let b: std::net::SocketAddr = "10.0.0.2:5061".parse().unwrap();
        let msg = b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let pdu = super::build_sip_pdu(a, b, msg);
        let d = super::decode(crate::pcap::LINKTYPE_WIRESHARK_UPPER_PDU, &pdu).unwrap();
        assert_eq!(
            (d.src, d.dst, d.transport, d.payload),
            (a, b, super::Transport::Tls, &msg[..])
        );
        let six: std::net::SocketAddr = "[2001:db8::1]:5061".parse().unwrap();
        let d6 = super::build_sip_pdu(six, six, msg);
        assert_eq!(
            super::decode(crate::pcap::LINKTYPE_WIRESHARK_UPPER_PDU, &d6)
                .unwrap()
                .src,
            six
        );
        let t = super::build_tcp_packet(a, b, 1000, 2000, msg);
        let d = super::decode(crate::pcap::LINKTYPE_RAW, &t).unwrap();
        assert_eq!(
            (d.transport, d.tcp_seq, d.payload),
            (super::Transport::Tcp, 1000, &msg[..])
        );
    }

    use super::*;

    #[test]
    fn build_then_decode_udp_v4_and_v6() {
        let a: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let b: SocketAddr = "192.0.2.10:5080".parse().unwrap();
        let pkt = build_udp_packet(a, b, b"hello");
        let d = decode(LINKTYPE_RAW, &pkt).unwrap();
        assert_eq!(d.src, a);
        assert_eq!(d.dst, b);
        assert_eq!(d.payload, b"hello");

        let a6: SocketAddr = "[2001:db8::1]:5060".parse().unwrap();
        let b6: SocketAddr = "[2001:db8::2]:5060".parse().unwrap();
        let pkt = build_udp_packet(a6, b6, b"x");
        let d = decode(LINKTYPE_RAW, &pkt).unwrap();
        assert_eq!(d.dst, b6);
    }

    #[test]
    fn private_ranges() {
        assert!(is_private(&"192.168.1.1".parse().unwrap()));
        assert!(is_private(&"100.64.0.1".parse().unwrap()));
        assert!(!is_private(&"8.8.8.8".parse().unwrap()));
        assert!(is_private(&"fd00::1".parse().unwrap()));
    }
}
