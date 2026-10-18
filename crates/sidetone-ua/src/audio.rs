//! Sound card I/O for the phone engine: microphone and speaker through cpal,
//! converted to and from 8 kHz mono for G.711.

use crate::engine::AudioIo;
#[cfg_attr(not(feature = "audio"), allow(unused_imports))]
use crate::media::Ring;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[cfg_attr(not(feature = "audio"), allow(unused_imports))]
use std::sync::{mpsc, Arc};
use std::thread;
#[cfg_attr(not(feature = "audio"), allow(unused_imports))]
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Default)]
pub struct DeviceList {
    pub available: bool,
    pub host: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub default_input: Option<String>,
    pub default_output: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AudioStatus {
    pub running: bool,
    pub input: Option<String>,
    pub output: Option<String>,
    pub input_rate: Option<u32>,
    pub output_rate: Option<u32>,
    pub mic_level: u32,
    pub speaker_level: u32,
    pub loopback: bool,
    pub error: Option<String>,
}

/// Running sound card streams.
pub struct Audio {
    pub io: AudioIo,
    stop: Arc<AtomicBool>,
    loopback: Arc<AtomicBool>,
    mic_level: Arc<AtomicU32>,
    spk_level: Arc<AtomicU32>,
    status: AudioStatus,
    join: Option<thread::JoinHandle<()>>,
}

impl Audio {
    pub fn status(&self) -> AudioStatus {
        let mut s = self.status.clone();
        s.mic_level = self.mic_level.load(Ordering::Relaxed);
        s.speaker_level = self.spk_level.load(Ordering::Relaxed);
        s.loopback = self.loopback.load(Ordering::Relaxed);
        s
    }

    /// Plays the microphone back on the speaker (audio test).
    pub fn set_loopback(&self, on: bool) {
        self.loopback.store(on, Ordering::Relaxed);
        if !on {
            self.io.speaker.clear();
        }
    }
}

impl Drop for Audio {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(feature = "audio")]
mod imp {
    use super::*;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    use cpal::{SampleFormat, Stream};

    pub fn list() -> DeviceList {
        let host = cpal::default_host();
        let mut d = DeviceList {
            host: host.id().name().to_string(),
            ..Default::default()
        };
        match host.input_devices() {
            Ok(it) => d.inputs = it.filter_map(|x| x.name().ok()).collect(),
            Err(e) => d.error = Some(e.to_string()),
        }
        match host.output_devices() {
            Ok(it) => d.outputs = it.filter_map(|x| x.name().ok()).collect(),
            Err(e) => d.error = Some(e.to_string()),
        }
        d.default_input = host.default_input_device().and_then(|x| x.name().ok());
        d.default_output = host.default_output_device().and_then(|x| x.name().ok());
        d.available = !d.inputs.is_empty() || !d.outputs.is_empty();
        d
    }

    fn pick(
        devs: Option<impl Iterator<Item = cpal::Device>>,
        name: Option<&str>,
        default: Option<cpal::Device>,
    ) -> Option<cpal::Device> {
        match name.filter(|n| !n.is_empty() && *n != "default") {
            Some(n) => devs?
                .into_iter()
                .find(|d| d.name().map(|x| x == n).unwrap_or(false))
                .or(default),
            None => default,
        }
    }

    /// Converts the device rate to AUDIO_RATE: one-pole low-pass, then linear interpolation.
    struct Resampler {
        step: f64,
        pos: f64,
        prev: f32,
        /// Two one-pole low-pass stages against aliasing when downsampling.
        a: f32,
        lp1: f32,
        lp2: f32,
    }

    impl Resampler {
        fn new(from: u32, to: u32) -> Self {
            let a = if from > to {
                let fc = 0.45 * to as f32;
                1.0 - (-2.0 * std::f32::consts::PI * fc / from as f32).exp()
            } else {
                1.0
            };
            Resampler {
                step: from as f64 / to as f64,
                pos: 0.0,
                prev: 0.0,
                a,
                lp1: 0.0,
                lp2: 0.0,
            }
        }
        /// Feeds input samples, emitting output samples.
        fn process(&mut self, input: &[f32], out: &mut Vec<i16>) {
            for &x in input {
                self.lp1 += self.a * (x - self.lp1);
                self.lp2 += self.a * (self.lp1 - self.lp2);
                let x = self.lp2;
                // Emit every output point that falls between prev and x.
                while self.pos <= 1.0 {
                    let v = self.prev + (x - self.prev) * self.pos as f32;
                    out.push((v.clamp(-1.0, 1.0) * 32767.0) as i16);
                    self.pos += self.step;
                }
                self.pos -= 1.0;
                self.prev = x;
            }
        }
    }

    fn input_stream(
        dev: &cpal::Device,
        mic: Arc<Ring>,
        spk: Arc<Ring>,
        loopback: Arc<AtomicBool>,
        level: Arc<AtomicU32>,
    ) -> Result<(Stream, u32), String> {
        let cfg = dev.default_input_config().map_err(|e| e.to_string())?;
        let rate = cfg.sample_rate().0;
        let ch = cfg.channels() as usize;
        let fmt = cfg.sample_format();
        let mut rs = Resampler::new(rate, crate::media::AUDIO_RATE);
        let mut mono: Vec<f32> = Vec::new();
        let mut out: Vec<i16> = Vec::new();
        let mut handle = move |samples: &mut dyn Iterator<Item = f32>| {
            mono.clear();
            let mut acc = 0.0f32;
            let mut k = 0;
            for s in samples {
                acc += s;
                k += 1;
                if k == ch {
                    mono.push(acc / ch as f32);
                    acc = 0.0;
                    k = 0;
                }
            }
            out.clear();
            rs.process(&mono, &mut out);
            let peak = out
                .iter()
                .map(|s| s.unsigned_abs() as u32)
                .max()
                .unwrap_or(0);
            level.store(peak, Ordering::Relaxed);
            mic.push(&out);
            if loopback.load(Ordering::Relaxed) {
                spk.push(&out);
            }
        };
        let err = |e| eprintln!("sidetone audio input: {e}");
        let config: cpal::StreamConfig = cfg.into();
        let stream = match fmt {
            SampleFormat::F32 => dev.build_input_stream(
                &config,
                move |d: &[f32], _: &_| handle(&mut d.iter().copied()),
                err,
                None,
            ),
            SampleFormat::I16 => dev.build_input_stream(
                &config,
                move |d: &[i16], _: &_| handle(&mut d.iter().map(|s| *s as f32 / 32768.0)),
                err,
                None,
            ),
            SampleFormat::U16 => dev.build_input_stream(
                &config,
                move |d: &[u16], _: &_| {
                    handle(&mut d.iter().map(|s| (*s as f32 - 32768.0) / 32768.0))
                },
                err,
                None,
            ),
            SampleFormat::I32 => dev.build_input_stream(
                &config,
                move |d: &[i32], _: &_| handle(&mut d.iter().map(|s| *s as f32 / 2147483648.0)),
                err,
                None,
            ),
            f => return Err(format!("unsupported input sample format {f:?}")),
        }
        .map_err(|e| e.to_string())?;
        stream.play().map_err(|e| e.to_string())?;
        Ok((stream, rate))
    }

    fn output_stream(
        dev: &cpal::Device,
        spk: Arc<Ring>,
        level: Arc<AtomicU32>,
    ) -> Result<(Stream, u32), String> {
        let cfg = dev.default_output_config().map_err(|e| e.to_string())?;
        let rate = cfg.sample_rate().0;
        let ch = cfg.channels() as usize;
        let fmt = cfg.sample_format();
        // Upsample AUDIO_RATE to the device rate by interpolating between queued samples.
        let step = crate::media::AUDIO_RATE as f64 / rate as f64;
        let mut pos = 0.0f64;
        let mut cur = 0i16;
        let mut next = 0i16;
        let mut peak_acc = 0u32;
        let mut peak_n = 0usize;
        let mut gen = move || -> f32 {
            while pos >= 1.0 {
                pos -= 1.0;
                cur = next;
                next = spk.pop().unwrap_or(0);
            }
            let v = cur as f64 + (next as f64 - cur as f64) * pos;
            pos += step;
            let a = (v.abs()) as u32;
            peak_acc = peak_acc.max(a);
            peak_n += 1;
            if peak_n >= 960 {
                level.store(peak_acc, Ordering::Relaxed);
                peak_acc = 0;
                peak_n = 0;
            }
            (v / 32768.0) as f32
        };
        let err = |e| eprintln!("sidetone audio output: {e}");
        let config: cpal::StreamConfig = cfg.into();
        macro_rules! out {
            ($t:ty, $conv:expr) => {
                dev.build_output_stream(
                    &config,
                    move |d: &mut [$t], _: &_| {
                        for frame in d.chunks_mut(ch) {
                            let v = gen();
                            for s in frame.iter_mut() {
                                *s = $conv(v);
                            }
                        }
                    },
                    err,
                    None,
                )
            };
        }
        let stream = match fmt {
            SampleFormat::F32 => out!(f32, |v: f32| v),
            SampleFormat::I16 => out!(i16, |v: f32| (v * 32767.0) as i16),
            SampleFormat::U16 => out!(u16, |v: f32| ((v * 32767.0) + 32768.0) as u16),
            SampleFormat::I32 => out!(i32, |v: f32| (v * 2147483647.0) as i32),
            f => return Err(format!("unsupported output sample format {f:?}")),
        }
        .map_err(|e| e.to_string())?;
        stream.play().map_err(|e| e.to_string())?;
        Ok((stream, rate))
    }

    pub fn start(input: Option<&str>, output: Option<&str>) -> Result<Audio, String> {
        let mic = Ring::new(crate::media::SPMS * 500);
        let spk = Ring::new(crate::media::SPMS * 500);
        let stop = Arc::new(AtomicBool::new(false));
        let loopback = Arc::new(AtomicBool::new(false));
        let mic_level = Arc::new(AtomicU32::new(0));
        let spk_level = Arc::new(AtomicU32::new(0));
        let (tx, rx) = mpsc::channel::<AudioStatus>();
        let input = input.map(|s| s.to_string());
        let output = output.map(|s| s.to_string());
        let (m2, s2, st2, lb2, ml2, sl2) = (
            mic.clone(),
            spk.clone(),
            stop.clone(),
            loopback.clone(),
            mic_level.clone(),
            spk_level.clone(),
        );
        // cpal streams are not Send on every platform: they live on this thread.
        let join = thread::Builder::new()
            .name("sidetone-audio".into())
            .spawn(move || {
                let host = cpal::default_host();
                let mut st = AudioStatus::default();
                let mut errors = Vec::new();
                let idev = pick(
                    host.input_devices().ok(),
                    input.as_deref(),
                    host.default_input_device(),
                );
                let odev = pick(
                    host.output_devices().ok(),
                    output.as_deref(),
                    host.default_output_device(),
                );
                let mut keep = Vec::new();
                match &idev {
                    Some(d) => match input_stream(d, m2, s2.clone(), lb2, ml2) {
                        Ok((s, r)) => {
                            keep.push(s);
                            st.input = d.name().ok();
                            st.input_rate = Some(r);
                        }
                        Err(e) => errors.push(format!("microphone: {e}")),
                    },
                    None => errors.push("no microphone found".into()),
                }
                match &odev {
                    Some(d) => match output_stream(d, s2, sl2) {
                        Ok((s, r)) => {
                            keep.push(s);
                            st.output = d.name().ok();
                            st.output_rate = Some(r);
                        }
                        Err(e) => errors.push(format!("speaker: {e}")),
                    },
                    None => errors.push("no speaker found".into()),
                }
                st.running = !keep.is_empty();
                if !errors.is_empty() {
                    st.error = Some(errors.join("; "));
                }
                let _ = tx.send(st);
                while !st2.load(Ordering::Relaxed) && !keep.is_empty() {
                    thread::sleep(Duration::from_millis(100));
                }
                drop(keep);
            })
            .map_err(|e| e.to_string())?;
        let status = rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "audio devices did not open in time".to_string())?;
        if !status.running {
            stop.store(true, Ordering::Relaxed);
            let _ = join.join();
            return Err(status.error.unwrap_or_else(|| "no audio device".into()));
        }
        Ok(Audio {
            io: AudioIo { mic, speaker: spk },
            stop,
            loopback,
            mic_level,
            spk_level,
            status,
            join: Some(join),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resampler_ratio() {
            let mut r = Resampler::new(48000, 16000);
            let mut out = Vec::new();
            r.process(&vec![0.5f32; 4800], &mut out);
            assert!((1599..=1601).contains(&out.len()), "{}", out.len());
            // DC passes the low-pass once it settles.
            assert!((out[1500] as f32 / 32767.0 - 0.5).abs() < 0.01);
            let mut r = Resampler::new(44100, 16000);
            let mut out = Vec::new();
            r.process(&vec![0.0f32; 44100], &mut out);
            assert!((15999..=16001).contains(&out.len()), "{}", out.len());
        }
    }
}

#[cfg(feature = "audio")]
pub use imp::{list, start};

#[cfg(not(feature = "audio"))]
pub fn list() -> DeviceList {
    DeviceList {
        error: Some("this build has no sound card support".into()),
        ..Default::default()
    }
}

#[cfg(not(feature = "audio"))]
pub fn start(_input: Option<&str>, _output: Option<&str>) -> Result<Audio, String> {
    Err("this build has no sound card support".into())
}
