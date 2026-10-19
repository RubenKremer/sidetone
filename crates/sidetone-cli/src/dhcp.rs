//! Finds the provisioning server the network hands to phones: a DHCPINFORM
//! asking for options 66 (TFTP server name), 150 (Cisco TFTP servers) and
//! 160 (Polycom provisioning URL). DHCP replies go to UDP port 68, which
//! needs administrator rights on most systems; the error says so.

use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct DhcpProvisioning {
    pub dhcp_server: Option<String>,
    /// Option 66, TFTP server name (a host, an IP or sometimes a URL).
    pub option66: Option<String>,
    /// Option 150, Cisco TFTP server addresses.
    pub option150: Vec<String>,
    /// Option 160, Polycom provisioning server URL.
    pub option160: Option<String>,
    /// Ready-to-use base URLs built from the options, best first.
    pub servers: Vec<String>,
}

/// The local IPv4 address used towards the network (no packet is sent).
fn local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    for probe in ["192.0.2.1:9", "10.255.255.255:9"] {
        if s.connect(probe).is_ok() {
            if let Ok(SocketAddr::V4(a)) = s.local_addr() {
                if !a.ip().is_unspecified() {
                    return Some(*a.ip());
                }
            }
        }
    }
    None
}

pub fn build_inform(xid: u32, ciaddr: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10] = 0x80; // broadcast flag
    p[12..16].copy_from_slice(&ciaddr.octets());
    p[28..34].copy_from_slice(&mac);
    p.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    p.extend_from_slice(&[53, 1, 8]); // DHCPINFORM
    p.extend_from_slice(&[61, 7, 1]);
    p.extend_from_slice(&mac);
    p.extend_from_slice(&[55, 6, 66, 150, 160, 1, 3, 6]);
    p.push(255);
    while p.len() < 300 {
        p.push(0);
    }
    p
}

/// Reads the provisioning options of a DHCP reply (ACK) for `xid`.
pub fn parse_reply(b: &[u8], xid: u32) -> Option<DhcpProvisioning> {
    if b.len() < 240
        || b[0] != 2
        || b[4..8] != xid.to_be_bytes()
        || b[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let mut r = DhcpProvisioning::default();
    let mut kind = 0u8;
    let mut i = 240;
    while i < b.len() {
        let code = b[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *b.get(i + 1)? as usize;
        let v = b.get(i + 2..i + 2 + len)?;
        let text = || {
            String::from_utf8_lossy(v)
                .trim_end_matches('\0')
                .trim()
                .to_string()
        };
        match code {
            53 if len == 1 => kind = v[0],
            54 if len == 4 => {
                r.dhcp_server = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string())
            }
            66 => r.option66 = Some(text()).filter(|s| !s.is_empty()),
            150 => {
                r.option150 = v
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                    .collect()
            }
            160 => r.option160 = Some(text()).filter(|s| !s.is_empty()),
            _ => {}
        }
        i += 2 + len;
    }
    if kind != 5 {
        return None;
    }
    let mut servers = Vec::new();
    if let Some(u) = &r.option160 {
        servers.push(u.clone());
    }
    for ip in &r.option150 {
        servers.push(format!("tftp://{ip}"));
    }
    if let Some(s) = &r.option66 {
        servers.push(if s.contains("://") {
            s.clone()
        } else {
            format!("tftp://{s}")
        });
    }
    servers.dedup();
    r.servers = servers;
    Some(r)
}

/// Sends a DHCPINFORM and waits up to `wait` for the answer.
pub fn discover(mac: [u8; 6], wait: Duration) -> Result<DhcpProvisioning, String> {
    let ip = local_ipv4().ok_or("no IPv4 address on this computer")?;
    let sock = UdpSocket::bind("0.0.0.0:68").map_err(|e| {
        format!(
            "cannot listen on UDP port 68 for the DHCP answer ({e}). Run Sidetone as administrator (root on Linux and macOS), or type the TFTP server by hand"
        )
    })?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let xid = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7))
        ^ 0x5349_4454;
    let pkt = build_inform(xid, ip, mac);
    sock.send_to(&pkt, "255.255.255.255:67")
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let mut buf = [0u8; 1500];
    let mut resent = false;
    while start.elapsed() < wait {
        sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(r) = parse_reply(&buf[..n], xid) {
                    return Ok(r);
                }
            }
            Err(_) => {
                if !resent && start.elapsed() > wait / 2 {
                    resent = true;
                    let _ = sock.send_to(&pkt, "255.255.255.255:67");
                }
            }
        }
    }
    Err(format!(
        "no DHCP server answered the DHCPINFORM from {ip} within {} s",
        wait.as_secs()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inform_and_ack_options() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let p = build_inform(42, Ipv4Addr::new(10, 0, 0, 9), mac);
        assert_eq!(p[240..243], [53, 1, 8]);
        // An ACK with 66, 150 (two servers) and 160.
        let mut a = p.clone();
        a.truncate(240);
        a[0] = 2;
        a.extend_from_slice(&[53, 1, 5, 54, 4, 10, 0, 0, 1]);
        a.extend_from_slice(&[66, 8]);
        a.extend_from_slice(b"pbx.lab\0");
        a.extend_from_slice(&[150, 8, 10, 0, 0, 5, 10, 0, 0, 6]);
        a.extend_from_slice(&[160, 21]);
        a.extend_from_slice(b"http://prov.lab/poly/");
        a.push(255);
        let r = parse_reply(&a, 42).unwrap();
        assert_eq!(r.dhcp_server.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.option66.as_deref(), Some("pbx.lab"));
        assert_eq!(r.option150, vec!["10.0.0.5", "10.0.0.6"]);
        assert_eq!(
            r.servers,
            vec![
                "http://prov.lab/poly/",
                "tftp://10.0.0.5",
                "tftp://10.0.0.6",
                "tftp://pbx.lab"
            ]
        );
        assert!(parse_reply(&a, 43).is_none());
    }
}
