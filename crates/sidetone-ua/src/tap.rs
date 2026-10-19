//! In-process capture: every datagram the UA sends or receives is recorded
//! with its real addresses, so the export needs no driver or privileges.

use crate::transport::Kind;
use sidetone_core::net::{
    build_hep, build_sip_pdu, build_tcp_packet, build_udp_packet, HEP_TYPE_SIP,
};
use sidetone_core::pcap::{
    write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW, LINKTYPE_WIRESHARK_UPPER_PDU,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

type Entry = (i64, u32, Vec<u8>, Option<Vec<u8>>);

#[derive(Clone)]
pub struct Tap {
    /// (time, link type, packet as on the wire, the same packet with its
    /// SRTP payload decrypted when there was one).
    inner: Arc<Mutex<Vec<Entry>>>,
    on: Arc<AtomicBool>,
    /// Next TCP sequence number per direction, for SIP over TCP.
    seq: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), u32>>>,
    /// Homer collector that gets a HEPv3 copy of every SIP message.
    hep: Arc<Mutex<Option<HepOut>>>,
    srtp: Arc<AtomicBool>,
}

struct HepOut {
    sock: std::net::UdpSocket,
    to: SocketAddr,
    agent: u32,
}

impl Default for Tap {
    fn default() -> Self {
        Tap {
            inner: Default::default(),
            on: Arc::new(AtomicBool::new(true)),
            seq: Default::default(),
            hep: Default::default(),
            srtp: Default::default(),
        }
    }
}

/// Packets kept by one tap before the oldest are dropped.
const TAP_CAP: usize = 2_000_000;

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl Tap {
    pub fn new() -> Self {
        Tap::default()
    }

    /// Records one datagram as an IP/UDP packet.
    pub fn record(&self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if !self.on.load(Ordering::Relaxed) {
            return;
        }
        self.push(LINKTYPE_RAW, build_udp_packet(src, dst, payload));
    }

    /// Records an SRTP datagram together with its decrypted form, so a
    /// capture can be exported either way.
    pub fn record_srtp(&self, src: SocketAddr, dst: SocketAddr, wire: &[u8], plain: &[u8]) {
        if !self.on.load(Ordering::Relaxed) {
            return;
        }
        self.srtp.store(true, Ordering::Relaxed);
        self.push_both(
            LINKTYPE_RAW,
            build_udp_packet(src, dst, wire),
            Some(build_udp_packet(src, dst, plain)),
        );
    }

    /// Records SIP as it travelled: UDP datagrams, TCP segments with running
    /// sequence numbers, or for TLS the decrypted message as a Wireshark
    /// exported PDU (what Wireshark writes for "Export PDUs", TLS layer).
    pub fn record_sip(&self, kind: Kind, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if let Ok(h) = self.hep.lock() {
            if let Some(h) = h.as_ref() {
                let cid = sidetone_core::sip::parse_datagram(payload)
                    .and_then(|m| m.header("call-id").map(str::to_string));
                let pkt = build_hep(
                    src,
                    dst,
                    kind != Kind::Udp,
                    now_ns(),
                    HEP_TYPE_SIP,
                    h.agent,
                    cid.as_deref(),
                    payload,
                );
                let _ = h.sock.send_to(&pkt, h.to);
            }
        }
        if !self.on.load(Ordering::Relaxed) {
            return;
        }
        match kind {
            Kind::Udp => self.push(LINKTYPE_RAW, build_udp_packet(src, dst, payload)),
            Kind::Tls => self.push(
                LINKTYPE_WIRESHARK_UPPER_PDU,
                build_sip_pdu(src, dst, payload),
            ),
            Kind::Tcp => {
                let (seq, ack) = {
                    let mut m = self.seq.lock().unwrap();
                    let start =
                        |a: &SocketAddr| 0x1000_0000u32.wrapping_add(a.port() as u32 * 7919);
                    let seq = *m.entry((src, dst)).or_insert_with(|| start(&src));
                    m.insert((src, dst), seq.wrapping_add(payload.len() as u32));
                    let ack = *m.entry((dst, src)).or_insert_with(|| start(&dst));
                    (seq, ack)
                };
                self.push(LINKTYPE_RAW, build_tcp_packet(src, dst, seq, ack, payload));
            }
        }
    }

    fn push(&self, linktype: u32, pkt: Vec<u8>) {
        self.push_both(linktype, pkt, None)
    }

    fn push_both(&self, linktype: u32, pkt: Vec<u8>, plain: Option<Vec<u8>>) {
        if let Ok(mut v) = self.inner.lock() {
            if v.len() >= TAP_CAP {
                v.drain(..TAP_CAP / 10);
            }
            v.push((now_ns(), linktype, pkt, plain));
        }
    }

    /// True when some recorded packet has a decrypted SRTP form.
    pub fn has_srtp(&self) -> bool {
        self.srtp.load(Ordering::Relaxed)
    }

    /// Sends a HEPv3 copy of every SIP message to `collector` ("host:port",
    /// default port 9060); empty turns it off. Returns the resolved address.
    pub fn set_hep(&self, collector: &str, agent: u32) -> Result<Option<SocketAddr>, String> {
        let collector = collector.trim();
        let mut slot = self.hep.lock().map_err(|e| e.to_string())?;
        if collector.is_empty() {
            *slot = None;
            return Ok(None);
        }
        let with_port = if collector
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.ends_with(':') && p.parse::<u16>().is_ok())
            || collector.starts_with('[') && collector.contains("]:")
        {
            collector.to_string()
        } else {
            format!("{collector}:9060")
        };
        use std::net::ToSocketAddrs;
        let to = with_port
            .to_socket_addrs()
            .map_err(|e| format!("{collector}: {e}"))?
            .next()
            .ok_or_else(|| format!("{collector}: no address"))?;
        let bind = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = std::net::UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        *slot = Some(HepOut { sock, to, agent });
        Ok(Some(to))
    }

    pub fn set_enabled(&self, on: bool) {
        self.on.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    pub fn clear(&self) {
        if let Ok(mut v) = self.inner.lock() {
            v.clear();
        }
        if let Ok(mut m) = self.seq.lock() {
            m.clear();
        }
        self.srtp.store(false, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|v| v.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serializes everything recorded so far as pcapng.
    pub fn to_pcapng(&self) -> Vec<u8> {
        self.export(false)
    }

    /// The same capture with SRTP replaced by the decrypted RTP (and RTCP),
    /// each such packet commented, so audio can be played and analyzed.
    pub fn to_pcapng_decrypted(&self) -> Vec<u8> {
        self.export(true)
    }

    fn export(&self, decrypted: bool) -> Vec<u8> {
        let mut v = self.inner.lock().map(|v| v.clone()).unwrap_or_default();
        v.sort_by_key(|p| p.0);
        let out: Vec<OutPacket<'_>> = v
            .iter()
            .map(|(t, lt, d, plain)| {
                let (data, comment) = match plain {
                    Some(p) if decrypted => (p, Some("SRTP decrypted by Sidetone".to_string())),
                    _ => (d, None),
                };
                OutPacket {
                    ts_ns: *t,
                    linktype: *lt,
                    data,
                    orig_len: data.len() as u32,
                    comment,
                }
            })
            .collect();
        write_pcapng(
            &out,
            &PcapngOptions {
                user_appl: Some(format!("Sidetone UA {}", env!("CARGO_PKG_VERSION"))),
                section_comment: decrypted
                    .then(|| "SRTP payloads decrypted by Sidetone".to_string()),
                ..Default::default()
            },
        )
    }
}

#[cfg(test)]
mod hep_tests {
    use super::*;

    #[test]
    fn sip_copies_reach_the_collector() {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let tap = Tap::new();
        let to = tap
            .set_hep(&rx.local_addr().unwrap().to_string(), 42)
            .unwrap();
        assert_eq!(to, Some(rx.local_addr().unwrap()));
        let a: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:5060".parse().unwrap();
        let msg = b"OPTIONS sip:b SIP/2.0\r\nCall-ID: abc\r\nContent-Length: 0\r\n\r\n";
        tap.record_sip(Kind::Udp, a, b, msg);
        let mut buf = [0u8; 2048];
        let n = rx.recv(&mut buf).unwrap();
        let d = sidetone_core::net::decode_hep(&buf[..n]).unwrap();
        assert_eq!((d.src, d.dst), (a, b));
        assert_eq!(d.payload, msg);
        assert!(tap.set_hep("", 0).unwrap().is_none());
    }
}
