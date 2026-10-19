//! Audio codecs beyond G.711 and Opus.
//!
//! - G.722: libg722 by Steve Underwood (public domain) and CMU, as translated
//!   to Rust in the ezk-g722 crate (MIT).
//! - G.726: from the soundkit-g726 crate (MIT).
//! - GSM 06.10: libgsm by Jutta Degener and Carsten Bormann, TU Berlin,
//!   through the gsm-sys crate.
//! - Speex: libspeex (Xiph.Org, BSD), bundled in native/speex.
//! - iLBC: the WebRTC iLBC (RFC 3951, BSD), bundled in native/ilbc.
//! - G.729 Annex A/B: the g729-sys crate, a Rust port of bcg729.

pub mod g722;
pub mod g726;

/// GSM 06.10 full-rate codec: 160 samples at 8 kHz <-> 33-byte frames.
pub struct Gsm(gsm_sys::Gsm);

// The libgsm state is plain memory owned by this value.
unsafe impl Send for Gsm {}

impl Gsm {
    pub fn new() -> Option<Gsm> {
        let h = unsafe { gsm_sys::gsm_create() };
        (!h.is_null()).then_some(Gsm(h))
    }
    /// One 20 ms frame (exactly 160 samples) to 33 bytes.
    pub fn encode(&mut self, pcm: &[i16]) -> [u8; 33] {
        let mut sig = [0i16; 160];
        let n = pcm.len().min(160);
        sig[..n].copy_from_slice(&pcm[..n]);
        let mut out = [0u8; 33];
        unsafe { gsm_sys::gsm_encode(self.0, sig.as_mut_ptr(), out.as_mut_ptr()) };
        out
    }
    /// One 33-byte frame to 160 samples (silence when the frame is invalid).
    pub fn decode(&mut self, frame: &[u8]) -> Vec<i16> {
        let mut inp = [0u8; 33];
        inp.copy_from_slice(&frame[..33]);
        let mut out = vec![0i16; 160];
        let r = unsafe { gsm_sys::gsm_decode(self.0, inp.as_mut_ptr(), out.as_mut_ptr()) };
        if r != 0 {
            out.iter_mut().for_each(|s| *s = 0);
        }
        out
    }
}

impl Drop for Gsm {
    fn drop(&mut self) {
        unsafe { gsm_sys::gsm_destroy(self.0) };
    }
}

// ---------------------------------------------------------------- Speex

#[repr(C)]
struct SpeexBits {
    chars: *mut i8,
    nb_bits: i32,
    char_ptr: i32,
    bit_ptr: i32,
    owner: i32,
    overflow: i32,
    buf_size: i32,
    reserved1: i32,
    reserved2: *mut std::ffi::c_void,
}

extern "C" {
    fn speex_lib_get_mode(mode: i32) -> *const std::ffi::c_void;
    fn speex_encoder_init(mode: *const std::ffi::c_void) -> *mut std::ffi::c_void;
    fn speex_encoder_destroy(st: *mut std::ffi::c_void);
    fn speex_encoder_ctl(st: *mut std::ffi::c_void, req: i32, ptr: *mut std::ffi::c_void) -> i32;
    fn speex_encode_int(st: *mut std::ffi::c_void, input: *mut i16, bits: *mut SpeexBits) -> i32;
    fn speex_decoder_init(mode: *const std::ffi::c_void) -> *mut std::ffi::c_void;
    fn speex_decoder_destroy(st: *mut std::ffi::c_void);
    fn speex_decoder_ctl(st: *mut std::ffi::c_void, req: i32, ptr: *mut std::ffi::c_void) -> i32;
    fn speex_decode_int(st: *mut std::ffi::c_void, bits: *mut SpeexBits, out: *mut i16) -> i32;
    fn speex_bits_init(bits: *mut SpeexBits);
    fn speex_bits_destroy(bits: *mut SpeexBits);
    fn speex_bits_reset(bits: *mut SpeexBits);
    fn speex_bits_write(bits: *mut SpeexBits, bytes: *mut i8, max_len: i32) -> i32;
    fn speex_bits_read_from(bits: *mut SpeexBits, bytes: *const i8, len: i32);
    fn speex_bits_remaining(bits: *mut SpeexBits) -> i32;
}

const SPEEX_SET_ENH: i32 = 0;
const SPEEX_SET_QUALITY: i32 = 4;

/// Speex narrowband (8 kHz, 160-sample frames) or wideband (16 kHz, 320).
pub struct Speex {
    enc: *mut std::ffi::c_void,
    dec: *mut std::ffi::c_void,
    ebits: Box<SpeexBits>,
    dbits: Box<SpeexBits>,
    pub frame: usize,
}

unsafe impl Send for Speex {}

impl Speex {
    /// `wide`: 16 kHz wideband; quality 8 (about 15 kbit/s narrow, 28 wide).
    pub fn new(wide: bool) -> Option<Speex> {
        unsafe {
            let mode = speex_lib_get_mode(if wide { 1 } else { 0 });
            if mode.is_null() {
                return None;
            }
            let enc = speex_encoder_init(mode);
            let dec = speex_decoder_init(mode);
            if enc.is_null() || dec.is_null() {
                return None;
            }
            let mut q: i32 = 8;
            speex_encoder_ctl(enc, SPEEX_SET_QUALITY, &mut q as *mut i32 as *mut _);
            let mut on: i32 = 1;
            speex_decoder_ctl(dec, SPEEX_SET_ENH, &mut on as *mut i32 as *mut _);
            let mut ebits: Box<SpeexBits> = Box::new(std::mem::zeroed());
            let mut dbits: Box<SpeexBits> = Box::new(std::mem::zeroed());
            speex_bits_init(&mut *ebits);
            speex_bits_init(&mut *dbits);
            Some(Speex {
                enc,
                dec,
                ebits,
                dbits,
                frame: if wide { 320 } else { 160 },
            })
        }
    }
    /// Whole frames of PCM to one RTP payload (frames packed back to back).
    pub fn encode(&mut self, pcm: &[i16]) -> Vec<u8> {
        unsafe {
            speex_bits_reset(&mut *self.ebits);
            for f in pcm.chunks_exact(self.frame) {
                let mut buf = f.to_vec();
                speex_encode_int(self.enc, buf.as_mut_ptr(), &mut *self.ebits);
            }
            let mut out = vec![0u8; 1024];
            let n = speex_bits_write(
                &mut *self.ebits,
                out.as_mut_ptr() as *mut i8,
                out.len() as i32,
            );
            out.truncate(n.max(0) as usize);
            out
        }
    }
    /// One RTP payload to PCM (every frame in it).
    pub fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        let mut out = Vec::new();
        unsafe {
            speex_bits_read_from(
                &mut *self.dbits,
                payload.as_ptr() as *const i8,
                payload.len() as i32,
            );
            for _ in 0..16 {
                if speex_bits_remaining(&mut *self.dbits) < 5 {
                    break;
                }
                let mut f = vec![0i16; self.frame];
                if speex_decode_int(self.dec, &mut *self.dbits, f.as_mut_ptr()) != 0 {
                    break;
                }
                out.extend(f);
            }
        }
        out
    }
}

impl Drop for Speex {
    fn drop(&mut self) {
        unsafe {
            speex_bits_destroy(&mut *self.ebits);
            speex_bits_destroy(&mut *self.dbits);
            speex_encoder_destroy(self.enc);
            speex_decoder_destroy(self.dec);
        }
    }
}

// ---------------------------------------------------------------- iLBC

extern "C" {
    fn WebRtcIlbcfix_EncoderCreate(inst: *mut *mut std::ffi::c_void) -> i16;
    fn WebRtcIlbcfix_DecoderCreate(inst: *mut *mut std::ffi::c_void) -> i16;
    fn WebRtcIlbcfix_EncoderFree(inst: *mut std::ffi::c_void) -> i16;
    fn WebRtcIlbcfix_DecoderFree(inst: *mut std::ffi::c_void) -> i16;
    fn WebRtcIlbcfix_EncoderInit(inst: *mut std::ffi::c_void, mode: i16) -> i16;
    fn WebRtcIlbcfix_DecoderInit(inst: *mut std::ffi::c_void, mode: i16) -> i16;
    fn WebRtcIlbcfix_Encode(
        inst: *mut std::ffi::c_void,
        speech: *const i16,
        len: usize,
        encoded: *mut u8,
    ) -> i32;
    fn WebRtcIlbcfix_Decode(
        inst: *mut std::ffi::c_void,
        encoded: *const u8,
        len: usize,
        decoded: *mut i16,
        speech_type: *mut i16,
    ) -> i32;
}

/// iLBC (RFC 3951) in 20 ms (38 bytes) or 30 ms (50 bytes) mode.
pub struct Ilbc {
    enc: *mut std::ffi::c_void,
    dec: *mut std::ffi::c_void,
    pub frame: usize,
}

unsafe impl Send for Ilbc {}

impl Ilbc {
    pub fn new(mode_ms: u32) -> Option<Ilbc> {
        let mode = if mode_ms == 20 { 20 } else { 30 };
        unsafe {
            let mut enc = std::ptr::null_mut();
            let mut dec = std::ptr::null_mut();
            if WebRtcIlbcfix_EncoderCreate(&mut enc) != 0
                || WebRtcIlbcfix_DecoderCreate(&mut dec) != 0
            {
                return None;
            }
            WebRtcIlbcfix_EncoderInit(enc, mode);
            WebRtcIlbcfix_DecoderInit(dec, mode);
            Some(Ilbc {
                enc,
                dec,
                frame: mode as usize * 8,
            })
        }
    }
    pub fn encode(&mut self, pcm: &[i16]) -> Vec<u8> {
        let n = pcm.len() / self.frame * self.frame;
        let mut out = vec![0u8; n / self.frame * 50 + 50];
        let k = unsafe { WebRtcIlbcfix_Encode(self.enc, pcm.as_ptr(), n, out.as_mut_ptr()) };
        out.truncate(k.max(0) as usize);
        out
    }
    pub fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        let mut out = vec![0i16; 240 * 8];
        let mut kind = 0i16;
        let k = unsafe {
            WebRtcIlbcfix_Decode(
                self.dec,
                payload.as_ptr(),
                payload.len(),
                out.as_mut_ptr(),
                &mut kind,
            )
        };
        out.truncate(k.max(0) as usize);
        out
    }
}

impl Drop for Ilbc {
    fn drop(&mut self) {
        unsafe {
            WebRtcIlbcfix_EncoderFree(self.enc);
            WebRtcIlbcfix_DecoderFree(self.dec);
        }
    }
}

// ---------------------------------------------------------------- G.729

/// G.729 Annex A: 10 ms frames, 80 samples at 8 kHz <-> 10 bytes; 2-byte
/// Annex B SID frames are decoded as comfort noise.
pub struct G729 {
    enc: g729_sys::Encoder,
    dec: g729_sys::Decoder,
}

impl G729 {
    pub fn new() -> G729 {
        G729 {
            enc: g729_sys::Encoder::new(false),
            dec: g729_sys::Decoder::new(),
        }
    }
    pub fn encode(&mut self, pcm: &[i16]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in pcm.chunks_exact(80) {
            let frame: &[i16; 80] = f.try_into().expect("80 samples");
            out.extend(self.enc.encode(frame));
        }
        out
    }
    pub fn decode(&mut self, payload: &[u8]) -> Vec<i16> {
        let mut out = Vec::new();
        let mut rest = payload;
        while rest.len() >= 10 {
            out.extend_from_slice(&self.dec.decode(&rest[..10], false, false, false));
            rest = &rest[10..];
        }
        if rest.len() == 2 {
            out.extend_from_slice(&self.dec.decode(rest, false, true, false));
        }
        out
    }
}

impl Default for G729 {
    fn default() -> Self {
        G729::new()
    }
}

// ---------------------------------------------------------------- resampling

/// Streaming windowed-sinc resampler between two rates (mono).
pub struct Resampler {
    ratio: f64,
    cutoff: f64,
    hist: Vec<f32>,
    pos: f64,
}

const RS_HALF: usize = 16;

impl Resampler {
    pub fn new(from: u32, to: u32) -> Resampler {
        Resampler {
            ratio: from as f64 / to as f64,
            // Low-pass below the lower Nyquist, a little under it.
            cutoff: (to.min(from) as f64 / from as f64) * 0.92,
            hist: vec![0.0; RS_HALF * 2],
            pos: RS_HALF as f64,
        }
    }
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        self.hist.extend(input.iter().map(|&x| x as f32));
        let mut out = Vec::with_capacity((input.len() as f64 / self.ratio) as usize + 2);
        while self.pos + (RS_HALF as f64) < self.hist.len() as f64 {
            let c = self.pos.floor() as isize;
            let frac = self.pos - c as f64;
            let mut acc = 0.0f64;
            let mut wsum = 0.0f64;
            for k in -(RS_HALF as isize) + 1..=RS_HALF as isize {
                let x = k as f64 - frac;
                let s = if x.abs() < 1e-9 {
                    1.0
                } else {
                    (std::f64::consts::PI * x * self.cutoff).sin()
                        / (std::f64::consts::PI * x * self.cutoff)
                };
                let w = 0.5 + 0.5 * (std::f64::consts::PI * x / RS_HALF as f64).cos();
                let tap = s * w;
                acc += tap * self.hist[(c + k) as usize] as f64;
                wsum += tap;
            }
            out.push((acc / wsum).round().clamp(-32768.0, 32767.0) as i16);
            self.pos += self.ratio;
        }
        // Keep the tail the filter still needs.
        let drop = (self.pos.floor() as usize).saturating_sub(RS_HALF);
        self.hist.drain(..drop);
        self.pos -= drop as f64;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A voice-like test signal: harmonics of a gliding pitch with syllables.
    pub fn voice(rate: u32, secs: f32) -> Vec<i16> {
        let n = (rate as f32 * secs) as usize;
        (0..n)
            .map(|i| {
                let t = i as f32 / rate as f32;
                let env = (t * 3.0 * std::f32::consts::PI).sin().abs();
                let f0 = 140.0 + 20.0 * (t * 1.3).sin();
                let w = 2.0 * std::f32::consts::PI * f0 * t;
                (env * (0.5 * w.sin() + 0.3 * (3.0 * w).sin() + 0.15 * (7.0 * w).sin()) * 9000.0)
                    as i16
            })
            .collect()
    }

    /// Best correlation of `b` against `a` over small delays.
    pub fn corr(a: &[i16], b: &[i16]) -> f64 {
        let mut best = 0.0f64;
        for d in 0..480 {
            let n = a.len().min(b.len().saturating_sub(d));
            if n < 1000 {
                continue;
            }
            let (mut xy, mut xx, mut yy) = (0.0, 0.0, 0.0);
            for i in 600..n {
                let x = a[i] as f64;
                let y = b[i + d] as f64;
                xy += x * y;
                xx += x * x;
                yy += y * y;
            }
            best = best.max(xy / (xx.sqrt() * yy.sqrt() + 1e-9));
        }
        best
    }

    #[test]
    fn g722_round_trip() {
        let pcm = voice(16000, 1.0);
        let mut e = g722::encoder::Encoder::new(g722::Bitrate::Mode1_64000, false, false);
        let mut d = g722::decoder::Decoder::new(g722::Bitrate::Mode1_64000, false, false);
        let mut out = Vec::new();
        for f in pcm.chunks(320) {
            let bytes = e.encode(f);
            assert_eq!(bytes.len(), 160, "64 kbit/s: one byte per two samples");
            out.extend(d.decode(&bytes));
        }
        let c = corr(&pcm, &out);
        assert!(c > 0.95, "G.722 correlation {c}");
    }

    #[test]
    fn g726_round_trip_both_packings() {
        let pcm = voice(8000, 1.0);
        for packing in [g726::G726Packing::Right, g726::G726Packing::Left] {
            let mut e = g726::G726Encoder::try_new(g726::G726Rate::Rate32000, packing).unwrap();
            let mut d = g726::G726Decoder::try_new(g726::G726Rate::Rate32000, packing).unwrap();
            let mut out = Vec::new();
            for f in pcm.chunks(160) {
                let mut buf = vec![0u8; 80];
                let n = e.encode_i16(f, &mut buf).unwrap();
                assert_eq!(n, 80);
                out.extend(d.decode_vec(&buf[..n]));
            }
            let c = corr(&pcm, &out);
            assert!(c > 0.95, "G.726 correlation {c}");
        }
    }

    #[test]
    fn speex_round_trip() {
        for (wide, rate) in [(false, 8000), (true, 16000)] {
            let pcm = voice(rate, 1.0);
            let mut sx = Speex::new(wide).unwrap();
            let mut out = Vec::new();
            for f in pcm.chunks_exact(sx.frame) {
                let p = sx.encode(f);
                assert!(!p.is_empty() && p.len() < 100, "speex payload {}", p.len());
                out.extend(sx.decode(&p));
            }
            assert_eq!(out.len(), pcm.len() / sx.frame * sx.frame);
            let c = corr(&pcm, &out);
            assert!(c > 0.6, "Speex wide={wide} correlation {c}");
        }
    }

    #[test]
    fn ilbc_round_trip() {
        for mode in [20u32, 30] {
            let pcm = voice(8000, 1.2);
            let mut il = Ilbc::new(mode).unwrap();
            let mut out = Vec::new();
            for f in pcm.chunks_exact(il.frame) {
                let p = il.encode(f);
                assert_eq!(p.len(), if mode == 20 { 38 } else { 50 });
                out.extend(il.decode(&p));
            }
            let c = corr(&pcm, &out);
            assert!(c > 0.6, "iLBC {mode} ms correlation {c}");
        }
    }

    #[test]
    fn g729_round_trip() {
        let pcm = voice(8000, 1.0);
        let mut g = G729::new();
        let mut out = Vec::new();
        for f in pcm.chunks_exact(160) {
            let p = g.encode(f);
            assert_eq!(p.len(), 20);
            out.extend(g.decode(&p));
        }
        let c = corr(&pcm, &out);
        assert!(c > 0.6, "G.729 correlation {c}");
    }

    #[test]
    fn resampler_keeps_a_tone() {
        let tone: Vec<i16> = (0..16000)
            .map(|i| {
                ((i as f32 * 2.0 * std::f32::consts::PI * 1000.0 / 16000.0).sin() * 10000.0) as i16
            })
            .collect();
        let mut up = Resampler::new(16000, 44100);
        let mut down = Resampler::new(44100, 16000);
        let mut back = Vec::new();
        for f in tone.chunks(320) {
            let u = up.process(f);
            back.extend(down.process(&u));
        }
        assert!(
            (back.len() as i64 - 16000).abs() < 100,
            "length {}",
            back.len()
        );
        let c = corr(&tone, &back);
        assert!(c > 0.98, "resampled tone correlation {c}");
    }

    #[test]
    fn gsm_round_trip() {
        let pcm = voice(8000, 1.0);
        let mut g = Gsm::new().unwrap();
        let mut h = Gsm::new().unwrap();
        let mut out = Vec::new();
        for f in pcm.chunks_exact(160) {
            out.extend(h.decode(&g.encode(f)));
        }
        let c = corr(&pcm, &out);
        assert!(c > 0.6, "GSM correlation {c}");
    }
}
