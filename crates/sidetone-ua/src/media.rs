//! G.711 codecs, tone generation, WAV output and the RTP session.

use crate::tap::Tap;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

/// Audio codec of a call. Opus carries the payload type negotiated in SDP;
/// two Opus values compare equal whatever their payload type, so a codec
/// from the profile matches the same codec in an offer.
#[derive(Debug, Clone, Copy, Eq)]
pub enum Codec {
    Pcmu,
    Pcma,
    Opus(u8),
}

impl PartialEq for Codec {
    fn eq(&self, o: &Codec) -> bool {
        matches!(
            (self, o),
            (Codec::Pcmu, Codec::Pcmu)
                | (Codec::Pcma, Codec::Pcma)
                | (Codec::Opus(_), Codec::Opus(_))
        )
    }
}

/// Payload type Sidetone offers for Opus.
pub const OPUS_PT: u8 = 111;

/// Sample rate of the phone's audio path: microphone, speaker, mixing, tones
/// and recordings. Wideband, so Opus calls carry 7 kHz audio; G.711 calls are
/// converted to and from 8 kHz at the codec.
pub const AUDIO_RATE: u32 = 16000;
/// Samples per millisecond at AUDIO_RATE.
pub const SPMS: usize = (AUDIO_RATE / 1000) as usize;

impl Codec {
    pub fn pt(self) -> u8 {
        match self {
            Codec::Pcmu => 0,
            Codec::Pcma => 8,
            Codec::Opus(pt) => pt,
        }
    }
    pub fn from_name(n: &str) -> Option<Codec> {
        match n.to_ascii_uppercase().as_str() {
            "PCMU" => Some(Codec::Pcmu),
            "PCMA" => Some(Codec::Pcma),
            "OPUS" => Some(Codec::Opus(OPUS_PT)),
            _ => None,
        }
    }
    /// Static payload types only.
    pub fn from_pt(pt: u8) -> Option<Codec> {
        match pt {
            0 => Some(Codec::Pcmu),
            8 => Some(Codec::Pcma),
            _ => None,
        }
    }
    /// A payload type of an SDP media line, using its rtpmap for dynamic types.
    pub fn from_media(m: &sidetone_core::sdp::Media, pt: u8) -> Option<Codec> {
        match m.codecs.iter().find(|c| c.pt == pt) {
            Some(c) if c.name.eq_ignore_ascii_case("opus") => Some(Codec::Opus(pt)),
            Some(c) => Codec::from_pt(pt).filter(|x| x.name().eq_ignore_ascii_case(&c.name)),
            None => Codec::from_pt(pt),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
            Codec::Opus(_) => "opus",
        }
    }
    /// RTP clock rate.
    pub fn clock(self) -> u32 {
        match self {
            Codec::Opus(_) => 48000,
            _ => 8000,
        }
    }
    /// SDP rtpmap encoding, e.g. "PCMU/8000" or "opus/48000/2".
    pub fn rtpmap(self) -> String {
        match self {
            Codec::Opus(_) => "opus/48000/2".into(),
            c => format!("{}/8000", c.name()),
        }
    }
}

/// Encoder state for one outgoing stream (PCM at AUDIO_RATE in).
pub enum Encoder {
    G711(Codec, Box<Halfband>),
    Opus(Box<opus::Encoder>),
}

const HB_TAPS: usize = 47;

/// Windowed-sinc low-pass at 3.6 kHz for a 16 kHz signal, used to go between
/// AUDIO_RATE and 8 kHz without aliasing (down) or images (up).
pub struct Halfband {
    taps: [f32; HB_TAPS],
    hist: [f32; HB_TAPS],
    pos: usize,
}

impl Halfband {
    pub fn new() -> Halfband {
        let mut taps = [0f32; HB_TAPS];
        let fc = 3600.0 / AUDIO_RATE as f32;
        let m = (HB_TAPS - 1) as f32;
        let mut sum = 0.0;
        for (i, t) in taps.iter_mut().enumerate() {
            let n = i as f32 - m / 2.0;
            let sinc = if n == 0.0 {
                2.0 * fc
            } else {
                (2.0 * std::f32::consts::PI * fc * n).sin() / (std::f32::consts::PI * n)
            };
            // Blackman window: about 74 dB stop band.
            let w = 0.42 - 0.5 * (2.0 * std::f32::consts::PI * i as f32 / m).cos()
                + 0.08 * (4.0 * std::f32::consts::PI * i as f32 / m).cos();
            *t = sinc * w;
            sum += *t;
        }
        for t in taps.iter_mut() {
            *t /= sum;
        }
        Halfband {
            taps,
            hist: [0.0; HB_TAPS],
            pos: 0,
        }
    }

    fn push(&mut self, x: f32) {
        self.hist[self.pos] = x;
        self.pos = (self.pos + 1) % HB_TAPS;
    }

    fn output(&self) -> f32 {
        let mut acc = 0.0;
        for (k, t) in self.taps.iter().enumerate() {
            acc += t * self.hist[(self.pos + k) % HB_TAPS];
        }
        acc
    }

    /// AUDIO_RATE in, 8 kHz out.
    pub fn down(&mut self, pcm: &[i16], out: &mut Vec<i16>) {
        for (i, &x) in pcm.iter().enumerate() {
            self.push(x as f32);
            if i % 2 == 1 {
                out.push(self.output().round().clamp(-32768.0, 32767.0) as i16);
            }
        }
    }

    /// 8 kHz in, AUDIO_RATE out.
    pub fn up(&mut self, pcm: &[i16], out: &mut Vec<i16>) {
        for &x in pcm {
            for v in [x as f32 * 2.0, 0.0] {
                self.push(v);
                out.push(self.output().round().clamp(-32768.0, 32767.0) as i16);
            }
        }
    }
}

impl Default for Halfband {
    fn default() -> Self {
        Halfband::new()
    }
}

impl Encoder {
    pub fn new(c: Codec) -> Encoder {
        match c {
            Codec::Opus(_) => {
                match opus::Encoder::new(AUDIO_RATE, opus::Channels::Mono, opus::Application::Voip)
                {
                    Ok(mut e) => {
                        e.set_inband_fec(true).ok();
                        e.set_packet_loss_perc(5).ok();
                        Encoder::Opus(Box::new(e))
                    }
                    Err(_) => Encoder::G711(Codec::Pcmu, Box::default()),
                }
            }
            c => Encoder::G711(c, Box::default()),
        }
    }
    pub fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) {
        match self {
            Encoder::G711(c, hb) => {
                let mut n = Vec::with_capacity(pcm.len() / 2);
                hb.down(pcm, &mut n);
                if *c == Codec::Pcma {
                    out.extend(n.iter().map(|&s| alaw_encode(s)));
                } else {
                    out.extend(n.iter().map(|&s| ulaw_encode(s)));
                }
            }
            Encoder::Opus(e) => {
                let mut buf = [0u8; 1500];
                if let Ok(n) = e.encode(pcm, &mut buf) {
                    out.extend_from_slice(&buf[..n]);
                }
            }
        }
    }
}

/// Decoder state for one incoming stream (PCM at AUDIO_RATE out).
pub struct Decoder {
    codec: Codec,
    opus: Option<opus::Decoder>,
    /// Interpolates G.711 up to AUDIO_RATE.
    up: Box<Halfband>,
}

impl Decoder {
    pub fn new(c: Codec) -> Decoder {
        let opus = match c {
            Codec::Opus(_) => opus::Decoder::new(AUDIO_RATE, opus::Channels::Mono).ok(),
            _ => None,
        };
        Decoder {
            codec: c,
            opus,
            up: Box::default(),
        }
    }
    /// Decodes one payload of payload type `pt`; None when the type is not audio we know.
    pub fn decode(&mut self, pt: u8, payload: &[u8]) -> Option<Vec<i16>> {
        let narrow: Option<Vec<i16>> = match Codec::from_pt(pt) {
            Some(Codec::Pcmu) => Some(payload.iter().map(|&b| ulaw_decode(b)).collect()),
            Some(Codec::Pcma) => Some(payload.iter().map(|&b| alaw_decode(b)).collect()),
            _ => None,
        };
        if let Some(n) = narrow {
            let mut out = Vec::with_capacity(n.len() * 2);
            self.up.up(&n, &mut out);
            return Some(out);
        }
        if let (Codec::Opus(p), Some(d)) = (self.codec, self.opus.as_mut()) {
            if p == pt {
                let mut out = vec![0i16; SPMS * 120];
                let n = d.decode(payload, &mut out, false).ok()?;
                out.truncate(n);
                return Some(out);
            }
        }
        None
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
    /// Live microphone samples pushed into `MediaCtl::mic` (silence when empty).
    Device,
}

/// Bounded PCM queue at 8 kHz shared with audio devices.
#[derive(Default)]
pub struct Ring {
    q: Mutex<VecDeque<i16>>,
    cap: usize,
}

impl Ring {
    pub fn new(cap: usize) -> Arc<Ring> {
        Arc::new(Ring {
            q: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        })
    }
    pub fn push(&self, s: &[i16]) {
        let mut q = self.q.lock().unwrap();
        q.extend(s.iter().copied());
        while q.len() > self.cap {
            q.pop_front();
        }
    }
    pub fn pop(&self) -> Option<i16> {
        self.q.lock().unwrap().pop_front()
    }
    pub fn pop_into(&self, out: &mut [i16]) -> usize {
        let mut q = self.q.lock().unwrap();
        let n = out.len().min(q.len());
        for o in out.iter_mut().take(n) {
            *o = q.pop_front().unwrap_or(0);
        }
        n
    }
    pub fn len(&self) -> usize {
        self.q.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn clear(&self) {
        self.q.lock().unwrap().clear();
    }
}

/// Live controls of a running RTP session, changed from the signaling side.
pub struct MediaCtl {
    /// Do not send media (local hold).
    pub hold: AtomicBool,
    /// Send silence instead of the source (mute).
    pub mute: AtomicBool,
    /// Keep sent/received PCM for the WAV recording.
    pub record: AtomicBool,
    /// New remote address after a re-INVITE/UPDATE.
    pub remote: Mutex<Option<SocketAddr>>,
    /// Digits to play as inband dual tones.
    pub inband: Mutex<VecDeque<char>>,
    /// Peak levels of the last packet, 0..=32767.
    pub tx_level: AtomicU32,
    pub rx_level: AtomicU32,
    /// Microphone input for `AudioSource::Device`.
    pub mic: Mutex<Option<Arc<Ring>>>,
    /// Decoded received audio goes here when set (speaker).
    pub speaker: Mutex<Option<Arc<Ring>>>,
    /// Received RFC 4733 digits (for display).
    pub dtmf_rx: Mutex<Vec<char>>,
    /// Conference mixing: own outgoing source samples are copied here.
    pub mic_copy: Mutex<Option<Arc<Ring>>>,
    /// Conference mixing: audio added to what this line sends.
    pub tx_adds: Mutex<Vec<Arc<Ring>>>,
    /// Conference mixing: received audio is copied into these.
    pub rx_copies: Mutex<Vec<Arc<Ring>>>,
    /// Conference mixing: audio added to what this line plays on the speaker.
    pub spk_adds: Mutex<Vec<Arc<Ring>>>,
}

impl MediaCtl {
    /// Removes every conference mixing link.
    pub fn clear_mix(&self) {
        *self.mic_copy.lock().unwrap() = None;
        self.tx_adds.lock().unwrap().clear();
        self.rx_copies.lock().unwrap().clear();
        self.spk_adds.lock().unwrap().clear();
    }
}

fn mix_in(pcm: &mut [i16], adds: &[Arc<Ring>]) {
    if adds.is_empty() {
        return;
    }
    for s in pcm.iter_mut() {
        let mut v = *s as i32;
        for r in adds {
            v += r.pop().unwrap_or(0) as i32;
        }
        *s = v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    }
}

impl Default for MediaCtl {
    fn default() -> Self {
        MediaCtl {
            hold: AtomicBool::new(false),
            mute: AtomicBool::new(false),
            record: AtomicBool::new(true),
            remote: Mutex::new(None),
            inband: Mutex::new(VecDeque::new()),
            tx_level: AtomicU32::new(0),
            rx_level: AtomicU32::new(0),
            mic: Mutex::new(None),
            speaker: Mutex::new(None),
            dtmf_rx: Mutex::new(Vec::new()),
            mic_copy: Mutex::new(None),
            tx_adds: Mutex::new(Vec::new()),
            rx_copies: Mutex::new(Vec::new()),
            spk_adds: Mutex::new(Vec::new()),
        }
    }
}

/// Frequencies (low, high) of a DTMF digit.
pub fn dtmf_freqs(d: char) -> Option<(f32, f32)> {
    let rows = [697.0, 770.0, 852.0, 941.0];
    let cols = [1209.0, 1336.0, 1477.0, 1633.0];
    let (r, c) = match d.to_ascii_uppercase() {
        '1' => (0, 0),
        '2' => (0, 1),
        '3' => (0, 2),
        'A' => (0, 3),
        '4' => (1, 0),
        '5' => (1, 1),
        '6' => (1, 2),
        'B' => (1, 3),
        '7' => (2, 0),
        '8' => (2, 1),
        '9' => (2, 2),
        'C' => (2, 3),
        '*' => (3, 0),
        '0' => (3, 1),
        '#' => (3, 2),
        'D' => (3, 3),
        _ => return None,
    };
    Some((rows[r], cols[c]))
}

fn peak(pcm: &[i16]) -> u32 {
    pcm.iter()
        .map(|s| s.unsigned_abs() as u32)
        .max()
        .unwrap_or(0)
}

/// Writes 8 kHz 16-bit stereo WAV: left = sent, right = received.
/// Stereo 16-bit WAV at AUDIO_RATE: left is what was sent, right what was received.
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
    v.extend_from_slice(&AUDIO_RATE.to_le_bytes());
    v.extend_from_slice(&(AUDIO_RATE * 4).to_le_bytes());
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
    /// SRTP packets that failed authentication (wrong key or not SRTP).
    pub srtp_failed: u64,
    /// DTLS-SRTP progress or outcome, when the call uses it.
    pub dtls: Option<String>,
    /// True once DTLS-SRTP keys are in place.
    pub dtls_ready: bool,
    /// The DTLS handshake failed.
    pub dtls_failed: bool,
}

pub struct RtpSession {
    pub socket: UdpSocket,
    pub local: SocketAddr,
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
    pub sent: Arc<Mutex<Vec<i16>>>,
    pub received: Arc<Mutex<Vec<i16>>>,
    pub stats: Arc<Mutex<MediaStats>>,
    pub ctl: Arc<MediaCtl>,
    dtmf_queue: Arc<Mutex<Vec<char>>>,
    /// SRTP keys (send, receive); set before `start` to encrypt the media.
    pub srtp: Option<(crate::srtp::KeyMaterial, crate::srtp::KeyMaterial)>,
    /// DTLS-SRTP: run a handshake on this socket and take the keys from it.
    pub dtls: Option<crate::dtls::DtlsParams>,
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
                    ctl: Arc::new(MediaCtl::default()),
                    srtp: None,
                    dtls: None,
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
        // Opus frames are 10, 20, 40 or 60 ms.
        let ptime_ms = match codec {
            Codec::Opus(_) if ![10, 20, 40, 60].contains(&ptime_ms) => 20,
            _ => ptime_ms,
        };
        let recv_sock = self.socket.try_clone().expect("clone rtp socket");
        let send_sock = self.socket.try_clone().expect("clone rtp socket");
        let stop = self.stop.clone();
        let received = self.received.clone();
        let stats = self.stats.clone();
        let latched: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let last_dtmf_ts: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let echo_buf: Arc<Mutex<std::collections::VecDeque<i16>>> =
            Arc::new(Mutex::new(Default::default()));
        let local = self.local;
        let ctl = self.ctl.clone();
        // Recording is capped at one hour per direction.
        const REC_CAP: usize = AUDIO_RATE as usize * 3600;

        // SRTP contexts: from SDES keys now, or from DTLS once it completes.
        let srtp_rx: Arc<Mutex<Option<crate::srtp::Context>>> = Arc::new(Mutex::new(
            self.srtp
                .as_ref()
                .map(|(_, rx)| crate::srtp::Context::new(rx)),
        ));
        let srtp_tx: Arc<Mutex<Option<crate::srtp::Context>>> = Arc::new(Mutex::new(
            self.srtp
                .as_ref()
                .map(|(tx, _)| crate::srtp::Context::new(tx)),
        ));
        let dtls: Option<Arc<Mutex<crate::dtls::DtlsSrtp>>> = self
            .dtls
            .clone()
            .map(|p| Arc::new(Mutex::new(crate::dtls::DtlsSrtp::new(p))));
        let outbox: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        if dtls.is_some() {
            stats.lock().unwrap().dtls = Some("DTLS handshake".into());
        }
        let on_dtls_event = {
            let (srtp_rx, srtp_tx, stats) = (srtp_rx.clone(), srtp_tx.clone(), stats.clone());
            move |ev: Option<crate::dtls::Event>| match ev {
                Some(crate::dtls::Event::Keys(tx, rx, state)) => {
                    *srtp_tx.lock().unwrap() = Some(crate::srtp::Context::new(&tx));
                    *srtp_rx.lock().unwrap() = Some(crate::srtp::Context::new(&rx));
                    let mut st = stats.lock().unwrap();
                    st.dtls = Some(state);
                    st.dtls_ready = true;
                }
                Some(crate::dtls::Event::Failed(why)) => {
                    let mut st = stats.lock().unwrap();
                    st.dtls = Some(why);
                    st.dtls_failed = true;
                }
                None => {}
            }
        };
        {
            let srtp_rx = srtp_rx.clone();
            let dtls = dtls.clone();
            let outbox = outbox.clone();
            let on_dtls_event = on_dtls_event.clone();
            let mut decoder = Decoder::new(codec);
            let ctl = ctl.clone();
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
                    if let Some(d) = &dtls {
                        if crate::dtls::DtlsSrtp::is_dtls(&buf[..n]) {
                            let mut out = Vec::new();
                            let ev = d.lock().unwrap().handle(&buf[..n], &mut out);
                            outbox.lock().unwrap().extend(out);
                            on_dtls_event(ev);
                            continue;
                        }
                    }
                    let n = match srtp_rx.lock().unwrap().as_mut() {
                        Some(c) => match c.unprotect(&mut buf[..n]) {
                            Some(m) => m,
                            None => {
                                stats.lock().unwrap().srtp_failed += 1;
                                continue;
                            }
                        },
                        // DTLS-SRTP without keys yet: nothing can be read.
                        None if dtls.is_some() => continue,
                        None => n,
                    };
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
                    if Some(h.pt) == dtmf_pt && n >= h.payload_offset + 4 {
                        // RFC 4733: record the digit once, on the first end packet.
                        let p = &buf[h.payload_offset..n];
                        if p[1] & 0x80 != 0 {
                            let ts = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                            let mut last = last_dtmf_ts.lock().unwrap();
                            if *last != Some(ts) {
                                *last = Some(ts);
                                let d = b"0123456789*#ABCD".get(p[0] as usize).copied();
                                if let Some(d) = d {
                                    ctl.dtmf_rx.lock().unwrap().push(d as char);
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(pcm) = decoder.decode(h.pt, &buf[h.payload_offset..n]) {
                        ctl.rx_level.store(peak(&pcm), Ordering::Relaxed);
                        for r in ctl.rx_copies.lock().unwrap().iter() {
                            r.push(&pcm);
                        }
                        if let Some(spk) = ctl.speaker.lock().unwrap().as_ref() {
                            let mut out = pcm.clone();
                            mix_in(&mut out, &ctl.spk_adds.lock().unwrap());
                            spk.push(&out);
                        }
                        {
                            let mut eb = echo_buf.lock().unwrap();
                            eb.extend(pcm.iter().copied());
                            while eb.len() > AUDIO_RATE as usize {
                                eb.pop_front();
                            }
                        }
                        if ctl.record.load(Ordering::Relaxed) {
                            let mut r = received.lock().unwrap();
                            if r.len() < REC_CAP {
                                r.extend(pcm);
                            }
                        }
                    }
                }
            }));
        }

        let sent = self.sent.clone();
        let dtmf_queue = self.dtmf_queue.clone();
        self.handles.push(thread::spawn(move || {
            let spp = SPMS * ptime_ms as usize; // samples per packet at AUDIO_RATE
            let ts_step = codec.clock() / 1000 * ptime_ms; // RTP timestamp units per packet
            let mut encoder = Encoder::new(codec);
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
            // Inband tone state: (low Hz, high Hz, samples left in tone, samples left in gap).
            let mut tone: Option<(f32, f32, usize, usize)> = None;
            let mut tone_t = 0usize;
            let mut remote = remote;
            while !stop.load(Ordering::Relaxed) {
                if let Some(r) = ctl.remote.lock().unwrap().take() {
                    remote = r;
                    *latched.lock().unwrap() = None;
                    stats.lock().unwrap().latched_remote = None;
                }
                let dest = latched.lock().unwrap().unwrap_or(remote);
                // DTLS: retransmission timers, then whatever the handshake wants sent.
                if let Some(d) = &dtls {
                    let mut out = Vec::new();
                    let ev = d.lock().unwrap().tick(&mut out);
                    outbox.lock().unwrap().extend(out);
                    on_dtls_event(ev);
                }
                for p in std::mem::take(&mut *outbox.lock().unwrap()) {
                    if send_sock.send_to(&p, dest).is_ok() {
                        tap.record(local, dest, &p);
                    }
                }
                let waiting_keys = dtls.is_some() && srtp_tx.lock().unwrap().is_none();
                if ctl.hold.load(Ordering::Relaxed) || waiting_keys {
                    ctl.tx_level.store(0, Ordering::Relaxed);
                    ts = ts.wrapping_add(ts_step);
                    n += 1;
                    let next = start + Duration::from_millis(n * ptime_ms as u64);
                    let now = Instant::now();
                    if next > now {
                        thread::sleep(next - now);
                    }
                    continue;
                }
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
                    let dur = ts_step * (k.min(8) + 1);
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
                    if ctl.record.load(Ordering::Relaxed) {
                        sent.lock().unwrap().extend(std::iter::repeat(0).take(spp));
                    }
                } else {
                    if dtmf_gap > 0 {
                        dtmf_gap -= 1;
                    }
                    let mut pcm = Vec::with_capacity(spp);
                    if tone.is_none() {
                        if let Some(d) = ctl.inband.lock().unwrap().pop_front() {
                            if let Some((lo, hi)) = dtmf_freqs(d) {
                                tone = Some((lo, hi, SPMS * 120, SPMS * 80));
                                tone_t = 0;
                            }
                        }
                    }
                    let muted = ctl.mute.load(Ordering::Relaxed);
                    for _ in 0..spp {
                        let s = match &source {
                            AudioSource::Silence => 0,
                            AudioSource::Tone(f) => {
                                phase += 2.0 * std::f32::consts::PI * f / AUDIO_RATE as f32;
                                if phase > 2.0 * std::f32::consts::PI {
                                    phase -= 2.0 * std::f32::consts::PI;
                                }
                                (phase.sin() * 8000.0) as i16
                            }
                            AudioSource::Samples(v) => {
                                let s = if v.is_empty() {
                                    0
                                } else {
                                    // Samples are 8 kHz: each one lasts two output samples.
                                    v[(sample_idx / 2) % v.len()]
                                };
                                sample_idx += 1;
                                s
                            }
                            AudioSource::Echo => echo_buf.lock().unwrap().pop_front().unwrap_or(0),
                            AudioSource::Device => ctl
                                .mic
                                .lock()
                                .unwrap()
                                .as_ref()
                                .and_then(|m| m.pop())
                                .unwrap_or(0),
                        };
                        let s = if muted { 0 } else { s };
                        let s = match &mut tone {
                            Some((lo, hi, on, gap)) => {
                                let v = if *on > 0 {
                                    *on -= 1;
                                    let t = tone_t as f32 / AUDIO_RATE as f32;
                                    tone_t += 1;
                                    let w = 2.0 * std::f32::consts::PI;
                                    (((w * *lo * t).sin() + (w * *hi * t).sin()) * 6000.0) as i16
                                } else {
                                    *gap = gap.saturating_sub(1);
                                    0
                                };
                                if *on == 0 && *gap == 0 {
                                    tone = None;
                                }
                                v
                            }
                            None => s,
                        };
                        pcm.push(s);
                    }
                    if let Some(c) = ctl.mic_copy.lock().unwrap().as_ref() {
                        c.push(&pcm);
                    }
                    mix_in(&mut pcm, &ctl.tx_adds.lock().unwrap());
                    ctl.tx_level.store(peak(&pcm), Ordering::Relaxed);
                    pkt.extend_from_slice(&[
                        0x80,
                        if first { 0x80 | codec.pt() } else { codec.pt() },
                    ]);
                    pkt.extend_from_slice(&seq.to_be_bytes());
                    pkt.extend_from_slice(&ts.to_be_bytes());
                    pkt.extend_from_slice(&ssrc.to_be_bytes());
                    encoder.encode(&pcm, &mut pkt);
                    if ctl.record.load(Ordering::Relaxed) {
                        let mut v = sent.lock().unwrap();
                        if v.len() < REC_CAP {
                            v.extend(pcm);
                        }
                    }
                    first = false;
                }
                if let Some(c) = srtp_tx.lock().unwrap().as_mut() {
                    c.protect(&mut pkt);
                }
                if send_sock.send_to(&pkt, dest).is_ok() {
                    tap.record(local, dest, &pkt);
                    stats.lock().unwrap().sent_packets += 1;
                }
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(ts_step);
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

    fn tone(hz: f32, n: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                ((i as f32 * 2.0 * std::f32::consts::PI * hz / AUDIO_RATE as f32).sin() * 10000.0)
                    as i16
            })
            .collect()
    }

    #[test]
    fn halfband_passes_voice_and_blocks_aliases() {
        let peak = |v: &[i16]| {
            v.iter()
                .skip(200)
                .map(|s| s.unsigned_abs())
                .max()
                .unwrap_or(0)
        };
        let mut hb = Halfband::new();
        let mut out = Vec::new();
        hb.down(&tone(1000.0, 3200), &mut out);
        assert!(peak(&out) > 9000, "1 kHz passes: {}", peak(&out));
        let mut hb = Halfband::new();
        let mut out = Vec::new();
        hb.down(&tone(6000.0, 3200), &mut out);
        assert!(
            peak(&out) < 200,
            "6 kHz is removed, not folded to 2 kHz: {}",
            peak(&out)
        );
        // Up: 1 kHz at 8 kHz becomes 1 kHz at 16 kHz with no image at 7 kHz.
        let n: Vec<i16> = (0..1600)
            .map(|i| {
                ((i as f32 * 2.0 * std::f32::consts::PI * 1000.0 / 8000.0).sin() * 10000.0) as i16
            })
            .collect();
        let mut hb = Halfband::new();
        let mut up = Vec::new();
        hb.up(&n, &mut up);
        assert_eq!(up.len(), 3200);
        assert!(
            (peak(&up) as i32 - 10000).abs() < 600,
            "unity gain: {}",
            peak(&up)
        );
    }

    #[test]
    fn opus_roundtrip_keeps_a_tone() {
        let c = Codec::Opus(107);
        let mut enc = Encoder::new(c);
        let mut dec = Decoder::new(c);
        let mut peak_out = 0i16;
        for f in 0..20 {
            let pcm: Vec<i16> = (0..160)
                .map(|i| {
                    ((((f * 160 + i) as f32) * 2.0 * std::f32::consts::PI * 440.0 / 8000.0).sin()
                        * 8000.0) as i16
                })
                .collect();
            let mut pkt = Vec::new();
            enc.encode(&pcm, &mut pkt);
            assert!(!pkt.is_empty() && pkt.len() < 160);
            let out = dec.decode(107, &pkt).expect("decodes");
            assert_eq!(out.len(), 160);
            if f > 5 {
                peak_out = peak_out.max(out.iter().map(|s| s.saturating_abs()).max().unwrap());
            }
        }
        assert!(peak_out > 5000, "tone survives: {peak_out}");
        assert!(dec.decode(0, &[0xff; 160]).is_some(), "G.711 still decodes");
        assert!(dec.decode(96, &[0; 10]).is_none(), "unknown payload type");
        assert_eq!(Codec::Opus(111), Codec::Opus(107));
        assert_eq!(c.clock(), 48000);
    }

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
