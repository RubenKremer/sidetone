//! In-process capture: every datagram the UA sends or receives is recorded
//! with its real addresses, so the export needs no driver or privileges.

use crate::transport::Kind;
use sidetone_core::net::{build_sip_pdu, build_tcp_packet, build_udp_packet};
use sidetone_core::pcap::{
    write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW, LINKTYPE_WIRESHARK_UPPER_PDU,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Tap {
    inner: Arc<Mutex<Vec<(i64, u32, Vec<u8>)>>>,
    on: Arc<AtomicBool>,
    /// Next TCP sequence number per direction, for SIP over TCP.
    seq: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), u32>>>,
}

impl Default for Tap {
    fn default() -> Self {
        Tap {
            inner: Default::default(),
            on: Arc::new(AtomicBool::new(true)),
            seq: Default::default(),
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

    /// Records SIP as it travelled: UDP datagrams, TCP segments with running
    /// sequence numbers, or for TLS the decrypted message as a Wireshark
    /// exported PDU (what Wireshark writes for "Export PDUs", TLS layer).
    pub fn record_sip(&self, kind: Kind, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
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
        if let Ok(mut v) = self.inner.lock() {
            if v.len() >= TAP_CAP {
                v.drain(..TAP_CAP / 10);
            }
            v.push((now_ns(), linktype, pkt));
        }
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
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|v| v.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serializes everything recorded so far as pcapng.
    pub fn to_pcapng(&self) -> Vec<u8> {
        let mut v = self.inner.lock().map(|v| v.clone()).unwrap_or_default();
        v.sort_by_key(|p| p.0);
        let out: Vec<OutPacket<'_>> = v
            .iter()
            .map(|(t, lt, d)| OutPacket {
                ts_ns: *t,
                linktype: *lt,
                data: d,
                orig_len: d.len() as u32,
                comment: None,
            })
            .collect();
        write_pcapng(
            &out,
            &PcapngOptions {
                user_appl: Some(format!("Sidetone UA {}", env!("CARGO_PKG_VERSION"))),
                ..Default::default()
            },
        )
    }
}
