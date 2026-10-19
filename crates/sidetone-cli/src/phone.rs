//! Native softphone behind the local HTTP API: one engine, sound card,
//! persisted accounts, settings and call history.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sidetone_ua::audio::{self, Audio};
use sidetone_ua::engine::{AccountCfg, CallRequest, Cmd, Engine, HistoryEntry, PhoneSettings};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AudioPrefs {
    pub enabled: bool,
    pub input: Option<String>,
    pub output: Option<String>,
}

impl Default for AudioPrefs {
    fn default() -> Self {
        AudioPrefs {
            enabled: true,
            input: None,
            output: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PhoneConfig {
    pub accounts: Vec<AccountCfg>,
    pub settings: PhoneSettings,
    pub audio: AudioPrefs,
}

pub struct Phone {
    pub engine: Engine,
    audio: Mutex<Option<Audio>>,
    audio_error: Mutex<Option<String>>,
    /// Sound card self-test in progress: "recording", "playing" or "tone".
    audio_test: Arc<Mutex<Option<String>>>,
    config: Mutex<PhoneConfig>,
    dir: Option<PathBuf>,
}

/// Per-user configuration directory (SIDETONE_CONFIG_DIR overrides it).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("SIDETONE_CONFIG_DIR") {
        if !d.is_empty() {
            return Some(PathBuf::from(d));
        }
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let home = PathBuf::from(home);
    if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA")
            .map(|a| PathBuf::from(a).join("Sidetone"))
            .or(Some(home.join("AppData").join("Roaming").join("Sidetone")))
    } else if cfg!(target_os = "macos") {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("Sidetone"),
        )
    } else {
        Some(
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join("sidetone"),
        )
    }
}

fn write_private(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)
}

static PHONE: OnceLock<Phone> = OnceLock::new();

/// The phone, started on first use.
pub fn get() -> &'static Phone {
    PHONE.get_or_init(Phone::start)
}

pub fn started() -> bool {
    PHONE.get().is_some()
}

impl Phone {
    fn start() -> Phone {
        let dir = config_dir();
        let cfg: PhoneConfig = dir
            .as_ref()
            .and_then(|d| std::fs::read(d.join("phone.json")).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let history: Vec<HistoryEntry> = dir
            .as_ref()
            .and_then(|d| std::fs::read(d.join("history.json")).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let (aud, aerr) = if cfg.audio.enabled {
            match audio::start(cfg.audio.input.as_deref(), cfg.audio.output.as_deref()) {
                Ok(a) => (Some(a), None),
                Err(e) => (None, Some(e)),
            }
        } else {
            (None, None)
        };
        let engine = Engine::start(
            cfg.settings.clone(),
            cfg.accounts.clone(),
            aud.as_ref().map(|a| a.io.clone()),
        );
        engine.set_history(history);
        let p = Phone {
            engine,
            audio: Mutex::new(aud),
            audio_error: Mutex::new(aerr),
            audio_test: Arc::new(Mutex::new(None)),
            config: Mutex::new(cfg),
            dir,
        };
        // Persist history in the background as calls end, and keep each
        // call's own capture next to it a few seconds after it ends (so the
        // final BYE/200 and the last RTP are in).
        std::thread::spawn(|| {
            let mut tried: std::collections::HashSet<String> = Default::default();
            let mut pending: Vec<(String, std::time::Instant)> = Vec::new();
            let mut first = true;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let Some(p) = PHONE.get() else { continue };
                for h in p.engine.history() {
                    if tried.insert(h.call_id.clone())
                        && !first
                        && p.call_capture_path(&h.call_id).is_some_and(|f| !f.exists())
                    {
                        pending.push((h.call_id, std::time::Instant::now()));
                    }
                }
                first = false;
                let due: Vec<String> = pending
                    .iter()
                    .filter(|(_, t)| t.elapsed() > std::time::Duration::from_secs(3))
                    .map(|(id, _)| id.clone())
                    .collect();
                pending.retain(|(id, _)| !due.contains(id));
                for id in due {
                    p.save_call_capture(&id);
                }
                if p.engine.take_history_dirty() {
                    p.save_history();
                }
            }
        });
        p
    }

    fn save_config(&self) {
        if let Some(d) = &self.dir {
            let c = self.config.lock().unwrap().clone();
            if let Ok(b) = serde_json::to_vec_pretty(&c) {
                let _ = write_private(&d.join("phone.json"), &b);
            }
        }
    }

    /// Where the capture of one call from the history is kept.
    pub fn call_capture_path(&self, call_id: &str) -> Option<PathBuf> {
        let safe: String = call_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .take(120)
            .collect();
        if safe.is_empty() {
            return None;
        }
        self.dir
            .as_ref()
            .map(|d| d.join("calls").join(format!("{safe}.pcapng")))
    }

    /// Saves the SIP and RTP of one call from the session capture, and fills
    /// the codecs of the history entry from its SDP.
    fn save_call_capture(&self, call_id: &str) {
        let Some(path) = self.call_capture_path(call_id) else {
            return;
        };
        let bytes = self.engine.capture();
        let Ok(report) = sidetone_core::analyze_bytes(&bytes) else {
            return;
        };
        let Some(idx) = report.calls.iter().position(|c| c.call_id == call_id) else {
            return;
        };
        let c = &report.calls[idx];
        self.engine
            .set_history_codecs(call_id, c.offer_codecs.clone(), c.answer_codecs.clone());
        let mut opts = sidetone_core::export::ExportOptions {
            call: Some(idx),
            ..Default::default()
        };
        let mut out = sidetone_core::export::export_pcapng(&report, &opts);
        // Very long calls keep the signaling only.
        if out.len() > 50 * 1024 * 1024 {
            opts.sip_only = true;
            out = sidetone_core::export::export_pcapng(&report, &opts);
        }
        let _ = write_private(&path, &out);
    }

    /// The saved capture of a call from the history.
    pub fn call_capture(&self, call_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.call_capture_path(call_id)?).ok()
    }

    /// History with a flag telling which calls have a saved capture.
    pub fn history_view(&self) -> Vec<Value> {
        self.engine
            .history()
            .into_iter()
            .map(|h| {
                let has = self
                    .call_capture_path(&h.call_id)
                    .is_some_and(|f| f.exists());
                let mut v = json!(h);
                v["capture"] = json!(has);
                v
            })
            .collect()
    }

    fn remove_call_captures(&self, ids: &[String]) {
        for id in ids {
            if let Some(f) = self.call_capture_path(id) {
                let _ = std::fs::remove_file(f);
            }
        }
    }

    fn save_history(&self) {
        if let Some(d) = &self.dir {
            if let Ok(b) = serde_json::to_vec(&self.engine.history()) {
                let _ = write_private(&d.join("history.json"), &b);
            }
        }
    }

    pub fn config(&self) -> PhoneConfig {
        self.config.lock().unwrap().clone()
    }

    /// Applies a partial configuration {accounts?, settings?, audio?} and saves it.
    pub fn set_config(&self, v: &Value) -> Result<()> {
        let mut c = self.config.lock().unwrap().clone();
        if let Some(a) = v.get("accounts") {
            c.accounts = serde_json::from_value(a.clone()).map_err(|e| anyhow!("accounts: {e}"))?;
            let mut seen = std::collections::HashSet::new();
            for a in &c.accounts {
                if !seen.insert(a.id.clone()) {
                    return Err(anyhow!("duplicate account id {}", a.id));
                }
            }
            self.engine.cmd(Cmd::SetAccounts(c.accounts.clone()));
        }
        if let Some(s) = v.get("settings") {
            c.settings = serde_json::from_value(s.clone()).map_err(|e| anyhow!("settings: {e}"))?;
            self.engine.cmd(Cmd::SetSettings(c.settings.clone()));
        }
        let audio_changed = match v.get("audio") {
            Some(a) => {
                let new: AudioPrefs =
                    serde_json::from_value(a.clone()).map_err(|e| anyhow!("audio: {e}"))?;
                let changed = new.enabled != c.audio.enabled
                    || new.input != c.audio.input
                    || new.output != c.audio.output;
                c.audio = new;
                changed
            }
            None => false,
        };
        *self.config.lock().unwrap() = c.clone();
        if audio_changed {
            self.restart_audio(&c.audio);
        }
        self.save_config();
        Ok(())
    }

    fn restart_audio(&self, prefs: &AudioPrefs) {
        let mut g = self.audio.lock().unwrap();
        self.engine.cmd(Cmd::SetAudio(None));
        *g = None;
        *self.audio_error.lock().unwrap() = None;
        if prefs.enabled {
            match audio::start(prefs.input.as_deref(), prefs.output.as_deref()) {
                Ok(a) => {
                    self.engine.cmd(Cmd::SetAudio(Some(a.io.clone())));
                    *g = Some(a);
                }
                Err(e) => *self.audio_error.lock().unwrap() = Some(e),
            }
        }
    }

    pub fn audio_status(&self) -> Value {
        let g = self.audio.lock().unwrap();
        let st = g.as_ref().map(|a| a.status());
        json!({
            "status": st,
            "test": self.audio_test.lock().unwrap().clone(),
            "error": self.audio_error.lock().unwrap().clone(),
            "prefs": self.config.lock().unwrap().audio,
        })
    }

    pub fn audio_loopback(&self, on: bool) -> Result<()> {
        match self.audio.lock().unwrap().as_ref() {
            Some(a) => {
                a.set_loopback(on);
                Ok(())
            }
            None => Err(anyhow!("no sound card is open")),
        }
    }

    /// Plays a tone on the speaker: checks the output device and its volume.
    pub fn audio_tone(&self, hz: f32, ms: u64) -> Result<()> {
        let io = self.sound_io()?;
        let state = self.audio_test.clone();
        *state.lock().unwrap() = Some("tone".into());
        std::thread::spawn(move || {
            let rate = sidetone_ua::media::AUDIO_RATE as f32;
            let chunk = sidetone_ua::media::SPMS * 20;
            let total = (ms as usize * sidetone_ua::media::SPMS).max(chunk);
            let mut n = 0usize;
            let start = std::time::Instant::now();
            while n < total {
                let buf: Vec<i16> = (n..(n + chunk).min(total))
                    .map(|i| {
                        // Short fades avoid clicks at both ends.
                        let fade = (i.min(total - i) as f32 / (rate * 0.01)).min(1.0);
                        ((i as f32 * 2.0 * std::f32::consts::PI * hz / rate).sin() * 9000.0 * fade)
                            as i16
                    })
                    .collect();
                io.speaker.push(&buf);
                n += buf.len();
                let due =
                    start + std::time::Duration::from_millis((n / sidetone_ua::media::SPMS) as u64);
                if let Some(d) = due.checked_duration_since(std::time::Instant::now()) {
                    std::thread::sleep(d.saturating_sub(std::time::Duration::from_millis(60)));
                }
            }
            *state.lock().unwrap() = None;
        });
        Ok(())
    }

    /// Records the microphone for a few seconds, then plays it back: the
    /// quickest way to hear what the far end will hear.
    pub fn audio_record_test(&self, secs: u64) -> Result<()> {
        if self.engine.state().calls.iter().any(|c| c.state != "ended") {
            return Err(anyhow!("hang up first: a call is using the microphone"));
        }
        let io = self.sound_io()?;
        let state = self.audio_test.clone();
        if state.lock().unwrap().is_some() {
            return Err(anyhow!("a test is already running"));
        }
        *state.lock().unwrap() = Some("recording".into());
        std::thread::spawn(move || {
            let ms = sidetone_ua::media::SPMS;
            let want = secs.clamp(1, 10) as usize * 1000 * ms;
            let mut rec: Vec<i16> = Vec::with_capacity(want);
            io.mic.clear();
            let mut buf = vec![0i16; ms * 20];
            while rec.len() < want {
                let n = io.mic.pop_into(&mut buf);
                rec.extend_from_slice(&buf[..n]);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            *state.lock().unwrap() = Some("playing".into());
            let start = std::time::Instant::now();
            for (k, c) in rec.chunks(ms * 20).enumerate() {
                io.speaker.push(c);
                let due = start + std::time::Duration::from_millis(20 * (k as u64 + 1));
                if let Some(d) = due.checked_duration_since(std::time::Instant::now()) {
                    std::thread::sleep(d.saturating_sub(std::time::Duration::from_millis(60)));
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            *state.lock().unwrap() = None;
        });
        Ok(())
    }

    fn sound_io(&self) -> Result<sidetone_ua::engine::AudioIo> {
        match self.audio.lock().unwrap().as_ref() {
            Some(a) => Ok(a.io.clone()),
            None => Err(anyhow!(
                "no sound card is open: tick Use the sound card in Settings, Audio"
            )),
        }
    }

    pub fn delete_history(&self, call_ids: &[String]) {
        self.engine.delete_history(call_ids);
        self.remove_call_captures(call_ids);
        self.save_history();
    }

    pub fn clear_history(&self) {
        let ids: Vec<String> = self
            .engine
            .history()
            .into_iter()
            .map(|h| h.call_id)
            .collect();
        self.remove_call_captures(&ids);
        self.engine.clear_history();
        self.save_history();
    }

    /// Runs a phone command from JSON: {"cmd": "...", ...}.
    pub fn command(&self, v: &Value) -> Result<Value> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let line = || -> Result<u32> {
            v.get("line")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .ok_or_else(|| anyhow!("missing line"))
        };
        let on = v.get("on").and_then(|x| x.as_bool()).unwrap_or(true);
        let e = &self.engine;
        match s("cmd").as_str() {
            "call" => {
                let req: CallRequest =
                    serde_json::from_value(v.clone()).map_err(|e| anyhow!("{e}"))?;
                if req.target.trim().is_empty() {
                    return Err(anyhow!("missing target"));
                }
                let l = e.call(req);
                return Ok(json!({"ok": true, "line": l}));
            }
            "answer" => e.cmd(Cmd::Answer(line()?)),
            "reject" => {
                let code = v.get("code").and_then(|x| x.as_u64()).unwrap_or(486) as u16;
                e.cmd(Cmd::Reject(line()?, code))
            }
            "hangup" => e.cmd(Cmd::Hangup(line()?)),
            "hangup_all" => e.cmd(Cmd::HangupAll),
            "hold" => e.cmd(Cmd::Hold(line()?, on)),
            "mute" => e.cmd(Cmd::Mute(line()?, on)),
            "record" => e.cmd(Cmd::Record(line()?, on)),
            "dtmf" => e.cmd(Cmd::Dtmf(line()?, s("digits"))),
            "transfer" => e.cmd(Cmd::BlindTransfer(line()?, s("target"))),
            "attended_transfer" => {
                let to = v
                    .get("to_line")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| anyhow!("missing to_line"))? as u32;
                e.cmd(Cmd::AttendedTransfer(line()?, to))
            }
            "conference" => {
                let to = v
                    .get("to_line")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| anyhow!("missing to_line"))? as u32;
                e.cmd(Cmd::Conference(line()?, to, on))
            }
            "presence" => e.cmd(Cmd::SetPresence(s("account"), s("status"), s("note"))),
            "register" => e.cmd(Cmd::Register(s("account"))),
            "unregister" => e.cmd(Cmd::Unregister(s("account"))),
            "dnd" | "auto_answer" => {
                let mut c = self.config();
                if s("cmd") == "dnd" {
                    c.settings.dnd = on;
                } else {
                    c.settings.auto_answer = on;
                }
                self.set_config(&json!({"settings": c.settings}))?;
            }
            "clear_capture" => e.cmd(Cmd::ClearCapture),
            other => return Err(anyhow!("unknown command {other:?}")),
        }
        Ok(json!({"ok": true}))
    }
}

/// Unregisters and stops the phone if it was started (process exit).
pub fn shutdown() {
    if let Some(p) = PHONE.get() {
        p.engine.shutdown(std::time::Duration::from_millis(1500));
        p.save_history();
    }
}
