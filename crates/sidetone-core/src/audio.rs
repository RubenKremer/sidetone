//! The audio of one RTP stream in a capture, for listening and drawing its
//! waveform. G.711 is decoded here; for other codecs the payloads are handed
//! out with their timestamps so the caller can decode them (Opus on the
//! desktop, WebCodecs in the browser).

use crate::analysis::analyze_capture;
use crate::net::{self, Transport};
use crate::pcap::read_capture;
use crate::rtp::parse_rtp;
use serde::Serialize;

/// Longest audio returned, in seconds (keeps memory bounded on long captures).
const MAX_SECONDS: u64 = 600;

#[derive(Debug, Serialize, Default)]
pub struct StreamAudio {
    pub codec: String,
    pub clock_rate: u32,
    /// Decoded audio (G.711), mono 16-bit; empty when `frames` must be decoded.
    pub rate: u32,
    #[serde(skip)]
    pub pcm: Vec<i16>,
    /// Payloads the caller decodes: (RTP timestamp offset, payload).
    #[serde(skip)]
    pub frames: Vec<(u32, Vec<u8>)>,
    pub packets: usize,
    /// Gaps filled with silence (lost or late packets), in packets.
    pub missing: u64,
    pub dtmf_packets: usize,
    pub note: Option<String>,
}

pub fn ulaw(b: u8) -> i16 {
    let b = !b;
    let sign = b & 0x80;
    let exp = (b >> 4) & 0x07;
    let mant = (b & 0x0f) as i32;
    let s = (((mant << 3) + 0x84) << exp) - 0x84;
    (if sign != 0 { -s } else { s }) as i16
}

pub fn alaw(b: u8) -> i16 {
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

/// Extracts and, for G.711, decodes the stream with this id.
pub fn stream_audio(bytes: &[u8], stream_id: usize) -> Result<StreamAudio, String> {
    let cap = read_capture(bytes).map_err(|e| e.to_string())?;
    let report = analyze_capture(cap.clone());
    let st = report
        .streams
        .get(stream_id)
        .ok_or_else(|| format!("no stream {stream_id}"))?;
    let codec = st.codec.clone();
    let clock = st.clock_rate.max(8000);
    // Packets of this stream: same addresses and SSRC.
    let mut pkts: Vec<(u64, u32, u8, Vec<u8>)> = Vec::new();
    let mut last_seq: Option<u16> = None;
    let mut cycles: u64 = 0;
    for p in &cap.packets {
        let Some(d) = net::decode(p.linktype, &p.data) else {
            continue;
        };
        if d.transport != Transport::Udp
            || d.src.to_string() != st.src
            || d.dst.to_string() != st.dst
        {
            continue;
        }
        let Some(h) = parse_rtp(d.payload) else {
            continue;
        };
        if format!("0x{:08X}", h.ssrc) != st.ssrc {
            continue;
        }
        if let Some(l) = last_seq {
            if h.seq < l && l - h.seq > 0x8000 {
                cycles += 1;
            }
        }
        last_seq = Some(h.seq);
        let ext = (cycles << 16) | h.seq as u64;
        pkts.push((ext, h.ts, h.pt, d.payload[h.payload_offset..].to_vec()));
    }
    pkts.sort_by_key(|p| p.0);
    pkts.dedup_by_key(|p| p.0);
    // The audio payload type is the most common one (telephone-event is not audio).
    let mut counts: std::collections::HashMap<u8, usize> = Default::default();
    for p in &pkts {
        *counts.entry(p.2).or_default() += 1;
    }
    let main = counts
        .iter()
        .max_by_key(|(_, n)| **n)
        .map(|(pt, _)| *pt)
        .unwrap_or(0);
    let dtmf_packets = pkts.iter().filter(|p| p.2 != main).count();
    let audio: Vec<&(u64, u32, u8, Vec<u8>)> = pkts.iter().filter(|p| p.2 == main).collect();
    let mut out = StreamAudio {
        codec: codec.clone(),
        clock_rate: clock,
        packets: audio.len(),
        dtmf_packets,
        ..Default::default()
    };
    let Some(first) = audio.first() else {
        out.note = Some("no audio packets".into());
        return Ok(out);
    };
    let ts0 = first.1;
    let up = codec.to_ascii_uppercase();
    let g711 = match up.as_str() {
        "PCMU" => Some(ulaw as fn(u8) -> i16),
        "PCMA" => Some(alaw as fn(u8) -> i16),
        _ => None,
    };
    let max_units = clock as u64 * MAX_SECONDS;
    match g711 {
        Some(dec) => {
            out.rate = 8000;
            let mut prev_seq: Option<u64> = None;
            for p in &audio {
                let pos = p.1.wrapping_sub(ts0) as u64;
                if pos > max_units {
                    out.note = Some(format!("cut at {MAX_SECONDS} s"));
                    break;
                }
                if let Some(s) = prev_seq {
                    out.missing += p.0.saturating_sub(s + 1);
                }
                prev_seq = Some(p.0);
                let pos = pos as usize;
                if out.pcm.len() < pos {
                    out.pcm.resize(pos, 0);
                }
                for (k, b) in p.3.iter().enumerate() {
                    let i = pos + k;
                    if i < out.pcm.len() {
                        out.pcm[i] = dec(*b);
                    } else {
                        out.pcm.push(dec(*b));
                    }
                }
            }
        }
        None => {
            for p in &audio {
                let pos = p.1.wrapping_sub(ts0);
                if pos as u64 > max_units {
                    out.note = Some(format!("cut at {MAX_SECONDS} s"));
                    break;
                }
                out.frames.push((pos, p.3.clone()));
            }
            if !up.contains("OPUS") {
                out.note = Some(format!(
                    "{codec} is played by the desktop app; the browser plays G.711 and Opus"
                ));
            }
        }
    }
    Ok(out)
}

/// Mono 16-bit WAV.
pub fn wav_mono(pcm: &[i16], rate: u32) -> Vec<u8> {
    let data = pcm.len() * 2;
    let mut v = Vec::with_capacity(44 + data);
    v.extend_from_slice(b"RIFF");
    v.extend_from_slice(&((36 + data) as u32).to_le_bytes());
    v.extend_from_slice(b"WAVEfmt ");
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&rate.to_le_bytes());
    v.extend_from_slice(&(rate * 2).to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(b"data");
    v.extend_from_slice(&(data as u32).to_le_bytes());
    for s in pcm {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plays_a_sample_stream() {
        let bytes = crate::synth::generate("good-call").expect("sample");
        let r = crate::analysis::analyze_bytes(&bytes).unwrap();
        let id = r
            .streams
            .iter()
            .position(|s| s.codec.starts_with("PCM"))
            .expect("a G.711 stream");
        let a = stream_audio(&bytes, id).unwrap();
        assert_eq!(a.rate, 8000);
        assert!(
            a.pcm.len() > 8000,
            "at least a second of audio: {}",
            a.pcm.len()
        );
        let w = wav_mono(&a.pcm, a.rate);
        assert_eq!(&w[..4], b"RIFF");
        assert_eq!(ulaw(0xff), 0);
        assert!(alaw(0xd5).abs() < 16);
        let peak = a.pcm.iter().map(|v| v.unsigned_abs()).max().unwrap();
        assert!(
            peak > 2000,
            "the sample carries a voice-like signal: {peak}"
        );
    }
}
