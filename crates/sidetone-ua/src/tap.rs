//! In-process capture: every datagram the UA sends or receives is recorded
//! with its real addresses, so the export needs no driver or privileges.

use sidetone_core::net::build_udp_packet;
use sidetone_core::pcap::{write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Tap {
    inner: Arc<Mutex<Vec<(i64, Vec<u8>)>>>,
    on: Arc<AtomicBool>,
}

impl Default for Tap {
    fn default() -> Self {
        Tap {
            inner: Default::default(),
            on: Arc::new(AtomicBool::new(true)),
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
        let pkt = build_udp_packet(src, dst, payload);
        if let Ok(mut v) = self.inner.lock() {
            if v.len() >= TAP_CAP {
                v.drain(..TAP_CAP / 10);
            }
            v.push((now_ns(), pkt));
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
