//! G.711 codecs, tone generation, WAV output and the RTP session.

use crate::tap::Tap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub fn ulaw_encode(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;
    let mut s = sample as i32;
    let sign = if s < 0 { 0x80 } else { 0 };
    if s < 0 {
        s = -s;
    }
    s = s.min(CLIP) + BIAS;
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && s & mask == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = (s >> (exp + 3)) & 0x0f;
    !((sign | (exp << 4) | mant) as u8)
}

pub fn ulaw_decode(b: u8) -> i16 {
    let b = !b;
    let sign = b & 0x80;
    let exp = ((b >> 4) & 0x07) as i32;
    let mant = (b & 0x0f) as i32;
    let s = (((mant << 3) + 0x84) << exp) - 0x84;
    (if sign != 0 { -s } else { s }) as i16
}

pub fn alaw_encode(sample: i16) -> u8 {
    let mut s = sample as i32;
    let sign = if s >= 0 { 0x80 } else { 0 };
    if s < 0 {
        s = -s - 1;
    }
    s = s.min(32767);
    let out = if s < 256 {
        (s >> 4) as u8
    } else {
        let mut exp = 1;
        let mut v = s >> 8;
        while v > 1 && exp < 7 {
            v >>= 1;
            exp += 1;
        }
        ((exp << 4) | ((s >> (exp + 3)) & 0x0f)) as u8
    };
    (out | sign) ^ 0x55
}

pub fn alaw_decode(b: u8) -> i16 {
    let b = b ^ 0x55;
    let sign = b & 0x80;
    let exp = ((b >> 4) & 0x07) as i32;
    let mant = (b & 0x0f) as i32;
    let s = if exp == 0 {
        (mant << 4) + 8
    } else {
        ((mant << 4) + 0x108) << (exp - 1)
    };
    (if sign != 0 { s } else { -s }) as i16
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Pcmu,
    Pcma,
}

impl Codec {
    pub fn pt(self) -> u8 {
        match self {
            Codec::Pcmu => 0,
            Codec::Pcma => 8,
        }
    }
    pub fn from_name(n: &str) -> Option<Codec> {
        match n.to_ascii_uppercase().as_str() {
            "PCMU" => Some(Codec::Pcmu),
            "PCMA" => Some(Codec::Pcma),
            _ => None,
        }
    }
    pub fn from_pt(pt: u8) -> Option<Codec> {
        match pt {
            0 => Some(Codec::Pcmu),
            8 => Some(Codec::Pcma),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
        }
    }
    fn encode(self, s: i16) -> u8 {
        match self {
            Codec::Pcmu => ulaw_encode(s),
            Codec::Pcma => alaw_encode(s),
        }
    }
    fn decode(self, b: u8) -> i16 {
        match self {
            Codec::Pcmu => ulaw_decode(b),
            Codec::Pcma => alaw_decode(b),
        }
    }
}

/// What the UA sends as audio.
#[derive(Debug, Clone)]
pub enum AudioSource {
    Silence,
    /// Sine tone in Hz.
    Tone(f32),
    /// Mono 16-bit samples at 8 kHz, looped.
    Samples(Arc<Vec<i16>>),
    /// Send back whatever is received (echo test).
    Echo,
}

/// Writes 8 kHz 16-bit stereo WAV: left = sent, right = received.
pub fn write_wav_stereo(left: &[i16], right: &[i16]) -> Vec<u8> {
    let n = left.len().max(right.len());
    let data_len = (n * 4) as u32;
    let mut v = Vec::with_capacity(44 + data_len as usize);
    v.extend_from_slice(b"RIFF");
    v.extend_from_slice(&(36 + data_len).to_le_bytes());
    v.extend_from_slice(b"WAVEfmt ");
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&8000u32.to_le_bytes());
    v.extend_from_slice(&(8000u32 * 4).to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(b"data");
    v.extend_from_slice(&data_len.to_le_bytes());
    for i in 0..n {
        v.extend_from_slice(&left.get(i).copied().unwrap_or(0).to_le_bytes());
        v.extend_from_slice(&right.get(i).copied().unwrap_or(0).to_le_bytes());
    }
    v
}

/// Reads a mono or stereo 16-bit PCM WAV at 8 kHz (first channel used).
pub fn read_wav_8k(bytes: &[u8]) -> Result<Vec<i16>, String> {
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err("not a RIFF/WAVE file".into());
    }
    let mut off = 12;
    let mut channels = 1u16;
    let mut rate = 0u32;
    let mut bits = 0u16;
    while off + 8 <= bytes.len() {
        let id = &bytes[off..off + 4];
        let len = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]) as usize;
        let body = &bytes[off + 8..(off + 8 + len).min(bytes.len())];
        if id == b"fmt " && body.len() >= 16 {
            channels = u16::from_le_bytes([body[2], body[3]]);
            rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            bits = u16::from_le_bytes([body[14], body[15]]);
        } else if id == b"data" {
            if bits != 16 || rate != 8000 {
                return Err(format!(
                    "need 8 kHz 16-bit PCM WAV, got {rate} Hz {bits}-bit"
                ));
            }
            let step = 2 * channels.max(1) as usize;
            return Ok(body
                .chunks_exact(step)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect());
        }
        off += 8 + len + (len & 1);
    }
    Err("no data chunk".into())
}

#[derive(Debug, Clone, Default)]
pub struct MediaStats {
    pub sent_packets: u64,
    pub received_packets: u64,
    pub latched_remote: Option<SocketAddr>,
}

pub struct RtpSession {
    pub socket: UdpSocket,
    pub local: SocketAddr,
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
    pub sent: Arc<Mutex<Vec<i16>>>,
    pub received: Arc<Mutex<Vec<i16>>>,
    pub stats: Arc<Mutex<MediaStats>>,
    dtmf_queue: Arc<Mutex<Vec<char>>>,
}

impl RtpSession {
    /// Binds an even RTP port inside the range on the given local IP.
    pub fn bind(
        ip: std::net::IpAddr,
        start: u16,
        end: u16,
        dscp: u8,
    ) -> std::io::Result<RtpSession> {
        let span = (end.saturating_sub(start) / 2).max(1) as u32;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(7);
        for k in 0..span.min(200) {
            let port = start + (((seed.wrapping_add(k * 2654435761)) % span) * 2) as u16;
            let addr = SocketAddr::new(ip, port);
            if let Ok(s) = bind_udp(addr, dscp) {
                let local = s.local_addr()?;
                return Ok(RtpSession {
                    socket: s,
                    local,
                    stop: Arc::new(AtomicBool::new(false)),
                    handles: Vec::new(),
                    sent: Arc::new(Mutex::new(Vec::new())),
                    received: Arc::new(Mutex::new(Vec::new())),
                    stats: Arc::new(Mutex::new(MediaStats::default())),
                    dtmf_queue: Arc::new(Mutex::new(Vec::new())),
                });
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no free RTP port in range",
        ))
    }

    pub fn queue_dtmf(&self, digits: &str) {
        self.dtmf_queue.lock().unwrap().extend(digits.chars());
    }

    /// Starts sender and receiver threads.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        remote: SocketAddr,
        codec: Codec,
        ptime_ms: u32,
        source: AudioSource,
        dtmf_pt: Option<u8>,
        symmetric: bool,
        tap: Tap,
    ) {
        let recv_sock = self.socket.try_clone().expect("clone rtp socket");
        let send_sock = self.socket.try_clone().expect("clone rtp socket");
        let stop = self.stop.clone();
        let received = self.received.clone();
        let stats = self.stats.clone();
        let latched: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let echo_buf: Arc<Mutex<std::collections::VecDeque<i16>>> =
            Arc::new(Mutex::new(Default::default()));
        let local = self.local;

        {
            let stop = stop.clone();
            let latched = latched.clone();
            let echo_buf = echo_buf.clone();
            let tap = tap.clone();
            let stats = stats.clone();
            self.handles.push(thread::spawn(move || {
                recv_sock
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .ok();
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = recv_sock.recv_from(&mut buf) else {
                        continue;
                    };
                    tap.record(from, local, &buf[..n]);
                    let Some(h) = sidetone_core::rtp::parse_rtp(&buf[..n]) else {
                        continue;
                    };
                    {
                        let mut st = stats.lock().unwrap();
                        st.received_packets += 1;
                        if symmetric && st.latched_remote.is_none() {
                            st.latched_remote = Some(from);
                            *latched.lock().unwrap() = Some(from);
                        }
                    }
                    if let Some(c) = Codec::from_pt(h.pt) {
                        let pcm: Vec<i16> = buf[h.payload_offset..n]
                            .iter()
                            .map(|&b| c.decode(b))
                            .collect();
                        echo_buf.lock().unwrap().extend(pcm.iter().copied());
                        received.lock().unwrap().extend(pcm);
                    }
                }
            }));
        }

        let sent = self.sent.clone();
        let dtmf_queue = self.dtmf_queue.clone();
        self.handles.push(thread::spawn(move || {
            let spp = (8 * ptime_ms) as usize; // samples per packet at 8 kHz
            let ssrc: u32 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() ^ 0x5157_0000)
                .unwrap_or(1);
            let mut seq: u16 = (ssrc >> 16) as u16;
            let mut ts: u32 = ssrc.rotate_left(7);
            let mut phase = 0f32;
            let mut sample_idx = 0usize;
            let start = Instant::now();
            let mut n: u64 = 0;
            let mut first = true;
            // Active RFC 4733 event: (digit code, packets sent, event timestamp).
            let mut dtmf: Option<(u8, u32, u32)> = None;
            let mut dtmf_gap = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let dest = latched.lock().unwrap().unwrap_or(remote);
                let mut pkt = Vec::with_capacity(12 + spp);
                if dtmf.is_none() && dtmf_gap == 0 {
                    if let Some(pt) = dtmf_pt {
                        let mut q = dtmf_queue.lock().unwrap();
                        if !q.is_empty() {
                            let d = q.remove(0);
                            if let (Some(code), true) = (dtmf_code(d), pt > 0) {
                                dtmf = Some((code, 0, ts));
                            }
                        }
                    }
                }
                if let (Some((code, k, ets)), Some(pt)) = (dtmf, dtmf_pt) {
                    // 8 update packets (160 ms), then 3 end packets.
                    let end = k >= 8;
                    let dur = (spp as u32) * (k.min(8) + 1);
                    pkt.extend_from_slice(&[0x80, if k == 0 { 0x80 | pt } else { pt }]);
                    pkt.extend_from_slice(&seq.to_be_bytes());
                    pkt.extend_from_slice(&ets.to_be_bytes());
                    pkt.extend_from_slice(&ssrc.to_be_bytes());
                    pkt.extend_from_slice(&[code, if end { 0x8a } else { 0x0a }]);
                    pkt.extend_from_slice(&(dur.min(0xffff) as u16).to_be_bytes());
                    dtmf = if k >= 10 {
                        dtmf_gap = 5;
                        None
                    } else {
                        Some((code, k + 1, ets))
                    };
                    sent.lock().unwrap().extend(std::iter::repeat(0).take(spp));
                } else {
                    if dtmf_gap > 0 {
                        dtmf_gap -= 1;
                    }
                    let mut pcm = Vec::with_capacity(spp);
                    for _ in 0..spp {
                        let s = match &source {
                            AudioSource::Silence => 0,
                            AudioSource::Tone(f) => {
                                phase += 2.0 * std::f32::consts::PI * f / 8000.0;
                                if phase > 2.0 * std::f32::consts::PI {
                                    phase -= 2.0 * std::f32::consts::PI;
                                }
                                (phase.sin() * 8000.0) as i16
                            }
                            AudioSource::Samples(v) => {
                                let s = if v.is_empty() {
                                    0
                                } else {
                                    v[sample_idx % v.len()]
                                };
                                sample_idx += 1;
                                s
                            }
                            AudioSource::Echo => echo_buf.lock().unwrap().pop_front().unwrap_or(0),
                        };
                        pcm.push(s);
                    }
                    pkt.extend_from_slice(&[
                        0x80,
                        if first { 0x80 | codec.pt() } else { codec.pt() },
                    ]);
                    pkt.extend_from_slice(&seq.to_be_bytes());
                    pkt.extend_from_slice(&ts.to_be_bytes());
                    pkt.extend_from_slice(&ssrc.to_be_bytes());
                    pkt.extend(pcm.iter().map(|&s| codec.encode(s)));
                    sent.lock().unwrap().extend(pcm);
                    first = false;
                }
                if send_sock.send_to(&pkt, dest).is_ok() {
                    tap.record(local, dest, &pkt);
                    stats.lock().unwrap().sent_packets += 1;
                }
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(spp as u32);
                n += 1;
                let next = start + Duration::from_millis(n * ptime_ms as u64);
                let now = Instant::now();
                if next > now {
                    thread::sleep(next - now);
                }
            }
        }));
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }

    pub fn wav(&self) -> Vec<u8> {
        write_wav_stereo(&self.sent.lock().unwrap(), &self.received.lock().unwrap())
    }
}

impl Drop for RtpSession {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn dtmf_code(d: char) -> Option<u8> {
    Some(match d {
        '0'..='9' => d as u8 - b'0',
        '*' => 10,
        '#' => 11,
        'A'..='D' => d as u8 - b'A' + 12,
        'a'..='d' => d as u8 - b'a' + 12,
        _ => return None,
    })
}

/// Binds a UDP socket and applies a DSCP marking when requested.
pub fn bind_udp(addr: SocketAddr, dscp: u8) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if dscp > 0 && addr.is_ipv4() {
        // TOS byte = DSCP << 2. Some platforms ignore it without privileges.
        let _ = s.set_tos((dscp as u32) << 2);
    }
    s.bind(&addr.into())?;
    Ok(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711_roundtrip_is_close() {
        for &x in &[0i16, 100, -100, 1000, -1000, 12000, -12000, 32000, -32000] {
            let u = ulaw_decode(ulaw_encode(x));
            let a = alaw_decode(alaw_encode(x));
            let tol = (x.unsigned_abs() as i32 / 16).max(16);
            assert!((u as i32 - x as i32).abs() <= tol, "ulaw {x} -> {u}");
            assert!((a as i32 - x as i32).abs() <= tol, "alaw {x} -> {a}");
        }
        assert_eq!(ulaw_encode(0), 0xff);
        assert_eq!(alaw_encode(0), 0xd5);
    }
}
