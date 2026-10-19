//! Decodes one RTP stream of a capture with the engine's decoders and prints
//! the level per second: `decode_stream file.pcapng <stream id> <codec name>`.
use sidetone_ua::media::{Codec, Decoder};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&a[1]).unwrap();
    let id: usize = a[2].parse().unwrap();
    let codec = Codec::from_name(&a[3]).unwrap();
    let sa = sidetone_core::audio::stream_audio(&bytes, id).unwrap();
    let mut dec = Decoder::new(codec);
    let mut pcm: Vec<i16> = Vec::new();
    for (_, f) in &sa.frames {
        if let Some(d) = dec.decode(codec.pt(), f) {
            pcm.extend(d);
        }
    }
    for (k, sec) in pcm.chunks(16000).enumerate() {
        let peak = sec.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
        let rate = codec.audio_rate() as f64;
        let share = |f: f64| {
            let w = 2.0 * std::f64::consts::PI * f / rate;
            let (mut s1, mut s2) = (0.0f64, 0.0f64);
            for &v in sec {
                let s0 = v as f64 + 2.0 * w.cos() * s1 - s2;
                s2 = s1;
                s1 = s0;
            }
            let p = s1 * s1 + s2 * s2 - 2.0 * w.cos() * s1 * s2;
            let e: f64 = sec.iter().map(|&v| (v as f64).powi(2)).sum();
            2.0 * p / (e * sec.len() as f64).max(1.0)
        };
        println!(
            "second {k}: {} samples, peak {peak}, 1k share {:.2}",
            sec.len(),
            share(1000.0)
        );
    }
}
