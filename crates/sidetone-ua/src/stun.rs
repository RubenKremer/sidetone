//! STUN binding test (RFC 5389) to learn the public address and whether the
//! NAT keeps the same mapping towards different servers.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const MAGIC: u32 = 0x2112_A442;

#[derive(Debug, Clone, Serialize, Default)]
pub struct StunProbe {
    pub server: String,
    pub resolved: Option<String>,
    pub mapped: Option<String>,
    pub rtt_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StunReport {
    pub local: Option<String>,
    pub probes: Vec<StunProbe>,
    /// Plain-language conclusion.
    pub nat: String,
    pub public: Option<String>,
}

fn request(tid: &[u8; 12]) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&0x0001u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&MAGIC.to_be_bytes());
    v.extend_from_slice(tid);
    v
}

/// Parses a Binding Success Response and returns the mapped address.
pub fn parse_response(b: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    if b.len() < 20 || u16::from_be_bytes([b[0], b[1]]) != 0x0101 || &b[8..20] != tid {
        return None;
    }
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let body = b.get(20..20 + len)?;
    let mut i = 0;
    let mut plain = None;
    while i + 4 <= body.len() {
        let t = u16::from_be_bytes([body[i], body[i + 1]]);
        let l = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let v = body.get(i + 4..i + 4 + l)?;
        if (t == 0x0020 || t == 0x8020 || t == 0x0001) && l >= 8 {
            let xor = t != 0x0001;
            let fam = v[1];
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            if xor {
                port ^= (MAGIC >> 16) as u16;
            }
            let ip = match fam {
                1 => {
                    let mut o = [v[4], v[5], v[6], v[7]];
                    if xor {
                        for (k, x) in o.iter_mut().zip(MAGIC.to_be_bytes()) {
                            *k ^= x;
                        }
                    }
                    IpAddr::V4(Ipv4Addr::from(o))
                }
                2 if l >= 20 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&v[4..20]);
                    if xor {
                        let mut key = MAGIC.to_be_bytes().to_vec();
                        key.extend_from_slice(tid);
                        for (k, x) in o.iter_mut().zip(key) {
                            *k ^= x;
                        }
                    }
                    IpAddr::V6(Ipv6Addr::from(o))
                }
                _ => return None,
            };
            let a = SocketAddr::new(ip, port);
            if xor {
                return Some(a);
            }
            plain = Some(a);
        }
        i += 4 + ((l + 3) & !3);
    }
    plain
}

fn tid() -> [u8; 12] {
    let h = crate::ua::rand_hex(24);
    let mut t = [0u8; 12];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(i as u8);
    }
    t
}

fn probe(sock: &UdpSocket, server: &str) -> StunProbe {
    let mut p = StunProbe {
        server: server.to_string(),
        ..Default::default()
    };
    let hp = server
        .trim()
        .trim_start_matches("stun:")
        .trim_start_matches("stuns:");
    let hp = if hp.contains(':') && !hp.starts_with('[') {
        hp.to_string()
    } else {
        format!("{hp}:3478")
    };
    let addr = match hp
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()))
    {
        Some(a) => a,
        None => {
            p.error = Some(format!("cannot resolve {hp}"));
            return p;
        }
    };
    p.resolved = Some(addr.to_string());
    let id = tid();
    let req = request(&id);
    let start = Instant::now();
    let mut buf = [0u8; 1500];
    // RFC 5389 retransmission: 500 ms doubling, three tries here.
    let mut wait = Duration::from_millis(500);
    for _ in 0..3 {
        if let Err(e) = sock.send_to(&req, addr) {
            p.error = Some(e.to_string());
            return p;
        }
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            let _ =
                sock.set_read_timeout(Some(deadline - Instant::now() + Duration::from_millis(1)));
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from == addr => {
                    if let Some(m) = parse_response(&buf[..n], &id) {
                        p.mapped = Some(m.to_string());
                        p.rtt_ms = Some(start.elapsed().as_millis() as u64);
                        return p;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        wait *= 2;
    }
    p.error = Some("no response (UDP blocked or wrong server)".into());
    p
}

/// Sends binding requests from one local socket to each server.
pub fn test(servers: &[String], local_ip: Option<IpAddr>) -> StunReport {
    let mut r = StunReport::default();
    let bind = SocketAddr::new(local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            r.nat = format!("cannot open a UDP socket: {e}");
            return r;
        }
    };
    let local = sock.local_addr().ok();
    for s in servers.iter().filter(|s| !s.trim().is_empty()) {
        r.probes.push(probe(&sock, s));
    }
    let mapped: Vec<SocketAddr> = r
        .probes
        .iter()
        .filter_map(|p| p.mapped.as_ref()?.parse().ok())
        .collect();
    // Which local IP the OS used towards the first server.
    let local_ip_used = r
        .probes
        .iter()
        .find_map(|p| p.resolved.as_ref()?.parse::<SocketAddr>().ok())
        .and_then(|a| crate::ua::local_ip_for(a).ok());
    r.local = match (local, local_ip_used) {
        (Some(l), Some(ip)) if l.ip().is_unspecified() => {
            Some(SocketAddr::new(ip, l.port()).to_string())
        }
        (Some(l), _) => Some(l.to_string()),
        _ => None,
    };
    r.public = mapped.first().map(|m| m.to_string());
    r.nat = match mapped.as_slice() {
        [] => "no STUN server answered; UDP to the internet may be blocked".into(),
        [m, rest @ ..] => {
            let local_sa: Option<SocketAddr> = r.local.as_ref().and_then(|l| l.parse().ok());
            if Some(*m) == local_sa {
                "no NAT: the public address is this machine's address".into()
            } else if rest.iter().any(|x| x != m) {
                "symmetric NAT (endpoint-dependent mapping): the public port changes per destination; expect one-way or no audio without a media relay, ICE/TURN or SBC latching".into()
            } else if rest.is_empty() {
                format!("behind NAT, public address {m}; add a second STUN server to check whether the mapping is stable")
            } else {
                format!("behind NAT with a stable mapping (endpoint-independent), public address {m}; rport/received and symmetric RTP should work")
            }
        }
    };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_address() {
        let t = [1u8; 12];
        let mut b = vec![0x01, 0x01, 0, 12];
        b.extend_from_slice(&MAGIC.to_be_bytes());
        b.extend_from_slice(&t);
        // XOR-MAPPED-ADDRESS 192.0.2.1:32853
        let port = 32853u16 ^ 0x2112;
        let ip = [192u8 ^ 0x21, 0 ^ 0x12, 2 ^ 0xA4, 1 ^ 0x42];
        b.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&ip);
        assert_eq!(
            parse_response(&b, &t),
            Some("192.0.2.1:32853".parse().unwrap())
        );
    }
}
