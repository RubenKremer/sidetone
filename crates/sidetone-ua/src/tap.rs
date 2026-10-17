//! In-process capture: every datagram the UA sends or receives is recorded
//! with its real addresses, so the export needs no driver or privileges.

use sidetone_core::net::build_udp_packet;
use sidetone_core::pcap::{write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default)]
pub struct Tap {
    inner: Arc<Mutex<Vec<(i64, Vec<u8>)>>>,
}

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
        let pkt = build_udp_packet(src, dst, payload);
        if let Ok(mut v) = self.inner.lock() {
            v.push((now_ns(), pkt));
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
            .map(|(t, d)| OutPacket {
                ts_ns: *t,
                linktype: LINKTYPE_RAW,
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
