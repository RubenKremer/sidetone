//! Native softphone behind the local HTTP API: one engine, sound card,
//! persisted accounts, settings and call history.

use crate::provision::{account_from_provision_json, fetch_provision};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sidetone_ua::audio::{self, Audio};
use sidetone_ua::engine::{AccountCfg, CallRequest, Cmd, Engine, HistoryEntry, PhoneSettings};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

struct ProvisionRuntime {
    cursor: u64,
    last_attempt: HashMap<String, Instant>,
    due: HashMap<String, Instant>,
    in_flight: HashSet<String>,
    rerun: HashSet<String>,
    held: HashMap<String, Value>,
}

static PROVISION: Mutex<Option<ProvisionRuntime>> = Mutex::new(None);

fn accounts_json_equal(a: &AccountCfg, b: &AccountCfg) -> bool {
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(va), Ok(vb)) => va == vb,
        _ => false,
    }
}

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
        let cursor = engine.seq();
        let p = Phone {
            engine,
            audio: Mutex::new(aud),
            audio_error: Mutex::new(aerr),
            config: Mutex::new(cfg),
            dir,
        };
        // Persist history in the background as calls end.
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if let Some(p) = PHONE.get() {
                if p.engine.take_history_dirty() {
                    p.save_history();
                }
            }
        });
        *PROVISION.lock().unwrap() = Some(ProvisionRuntime {
            cursor,
            last_attempt: HashMap::new(),
            due: HashMap::new(),
            in_flight: HashSet::new(),
            rerun: HashSet::new(),
            held: HashMap::new(),
        });
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_millis(250));
            if let Some(p) = PHONE.get() {
                p.poll_provisioning();
            }
        });
        p
    }

    fn save_config(&self, c: &PhoneConfig) {
        if let Some(d) = &self.dir {
            if let Ok(b) = serde_json::to_vec_pretty(c) {
                let _ = write_private(&d.join("phone.json"), &b);
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
        // Parse before taking the lock so a bad payload cannot replace the
        // live config, and so a later error does not hold the mutex.
        let accounts = if let Some(a) = v.get("accounts") {
            let accounts: Vec<AccountCfg> =
                serde_json::from_value(a.clone()).map_err(|e| anyhow!("accounts: {e}"))?;
            let mut seen = std::collections::HashSet::new();
            for a in &accounts {
                if !seen.insert(a.id.clone()) {
                    return Err(anyhow!("duplicate account id {}", a.id));
                }
            }
            Some(accounts)
        } else {
            None
        };
        let settings = if let Some(s) = v.get("settings") {
            Some(
                serde_json::from_value(s.clone()).map_err(|e| anyhow!("settings: {e}"))?,
            )
        } else {
            None
        };
        let audio: Option<AudioPrefs> = if let Some(a) = v.get("audio") {
            Some(serde_json::from_value(a.clone()).map_err(|e| anyhow!("audio: {e}"))?)
        } else {
            None
        };
        let (audio_changed, audio_prefs, snapshot) = {
            let mut c = self.config.lock().unwrap();
            if let Some(accounts) = accounts {
                c.accounts = accounts;
                self.engine.cmd(Cmd::SetAccounts(c.accounts.clone()));
            }
            if let Some(settings) = settings {
                c.settings = settings;
                self.engine.cmd(Cmd::SetSettings(c.settings.clone()));
            }
            let audio_changed = match audio {
                Some(new) => {
                    let changed = new.enabled != c.audio.enabled
                        || new.input != c.audio.input
                        || new.output != c.audio.output;
                    c.audio = new;
                    changed
                }
                None => false,
            };
            let audio_prefs = c.audio.clone();
            let snapshot = c.clone();
            (audio_changed, audio_prefs, snapshot)
        };
        if audio_changed {
            self.restart_audio(&audio_prefs);
        }
        self.save_config(&snapshot);
        Ok(())
    }

    /// Replaces one account from provisioning while preserving id, URL, TLS, and profile name.
    pub fn replace_account(&self, id: &str, next: AccountCfg) -> Result<()> {
        let snapshot = {
            let mut c = self.config.lock().unwrap();
            let Some(idx) = c.accounts.iter().position(|a| a.id == id) else {
                drop(c);
                self.engine.emit(
                    "info",
                    Some(id.to_string()),
                    "provisioning skipped: account was deleted",
                );
                return Ok(());
            };
            let stored = &c.accounts[idx];
            let merged = AccountCfg {
                id: stored.id.clone(),
                label: next.label,
                enabled: next.enabled,
                register: next.register,
                retry_s: next.retry_s,
                blf: next.blf,
                profile: sidetone_ua::Profile {
                    name: stored.profile.name.clone(),
                    account: next.profile.account,
                    behavior: next.profile.behavior,
                },
                provision_url: stored.provision_url.clone(),
                provision_tls_verify: stored.provision_tls_verify,
            };
            if accounts_json_equal(&merged, &c.accounts[idx]) {
                return Ok(());
            }
            c.accounts[idx] = merged;
            self.engine.cmd(Cmd::SetAccounts(c.accounts.clone()));
            c.clone()
        };
        self.engine.emit(
            "provisioned",
            Some(id.to_string()),
            "provisioning applied",
        );
        self.save_config(&snapshot);
        Ok(())
    }

    fn account_has_live_call(&self, account_id: &str) -> bool {
        self.engine.state().calls.iter().any(|c| {
            c.account == account_id && c.state != "ended"
        })
    }

    fn poll_provisioning(&self) {
        let fetch_now = {
            let mut guard = PROVISION.lock().unwrap();
            let Some(rt) = guard.as_mut() else {
                return;
            };
            let events = self.engine.events_since(rt.cursor);
            for e in &events {
                rt.cursor = rt.cursor.max(e.seq);
                if e.kind == "resync" {
                    if let Some(id) = e.account.clone() {
                        if rt.in_flight.contains(&id) {
                            rt.rerun.insert(id);
                        } else {
                            Self::schedule_resync(rt, &id);
                        }
                    }
                }
            }
            let now = Instant::now();
            let ids: Vec<String> = rt
                .due
                .iter()
                .filter(|(id, t)| **t <= now && !rt.in_flight.contains(*id))
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                rt.due.remove(id);
                rt.in_flight.insert(id.clone());
                rt.last_attempt.insert(id.clone(), Instant::now());
            }
            ids
        };

        for id in fetch_now {
            Self::finish_provision_fetch(self, &id);
        }

        let held_ids: Vec<String> = {
            PROVISION
                .lock()
                .unwrap()
                .as_ref()
                .map(|rt| rt.held.keys().cloned().collect())
                .unwrap_or_default()
        };
        for id in held_ids {
            if !self.account_has_live_call(&id) {
                let json = PROVISION
                    .lock()
                    .unwrap()
                    .as_mut()
                    .and_then(|rt| rt.held.remove(&id));
                if let Some(json) = json {
                    self.apply_provision_json(&id, json);
                }
            }
        }
    }

    fn schedule_resync(rt: &mut ProvisionRuntime, id: &str) {
        let due = match rt.last_attempt.get(id) {
            None => Instant::now(),
            Some(t) if t.elapsed() >= Duration::from_secs(10) => Instant::now(),
            Some(t) => *t + Duration::from_secs(10),
        };
        rt.due.insert(id.to_string(), due);
    }

    fn finish_provision_fetch(p: &Phone, id: &str) {
        let (url, tls_verify) = {
            let cfg = p.config.lock().unwrap();
            let Some(acc) = cfg.accounts.iter().find(|a| a.id == id) else {
                PROVISION
                    .lock()
                    .unwrap()
                    .as_mut()
                    .map(|rt| rt.in_flight.remove(id));
                return;
            };
            let Some(url) = acc.provision_url.clone() else {
                drop(cfg);
                PROVISION
                    .lock()
                    .unwrap()
                    .as_mut()
                    .map(|rt| rt.in_flight.remove(id));
                p.engine.emit(
                    "info",
                    Some(id.to_string()),
                    "provisioning skipped: no provision URL",
                );
                return;
            };
            (url, acc.provision_tls_verify)
        };

        let fetch_result = fetch_provision(&url, tls_verify);

        let need_rerun = {
            let mut guard = PROVISION.lock().unwrap();
            let Some(rt) = guard.as_mut() else {
                return;
            };
            rt.in_flight.remove(id);
            rt.rerun.remove(id)
        };
        if need_rerun {
            let mut guard = PROVISION.lock().unwrap();
            if let Some(rt) = guard.as_mut() {
                Self::schedule_resync(rt, id);
            }
        }

        match fetch_result {
            Ok(json) => {
                if p.account_has_live_call(id) {
                    PROVISION
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|rt| rt.held.insert(id.to_string(), json));
                } else {
                    p.apply_provision_json(id, json);
                }
            }
            Err(e) => {
                p.engine.emit(
                    "error",
                    Some(id.to_string()),
                    format!("provisioning failed: {e}"),
                );
            }
        }
    }

    fn apply_provision_json(&self, id: &str, json: Value) {
        let stored = {
            let cfg = self.config.lock().unwrap();
            cfg.accounts.iter().find(|a| a.id == id).cloned()
        };
        let Some(stored) = stored else {
            self.engine.emit(
                "info",
                Some(id.to_string()),
                "provisioning skipped: account was deleted",
            );
            return;
        };
        match account_from_provision_json(&stored, json) {
            Ok(next) => {
                let _ = self.replace_account(id, next);
            }
            Err(e) => {
                self.engine.emit(
                    "error",
                    Some(id.to_string()),
                    format!("provisioning failed: {e}"),
                );
            }
        }
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

    pub fn clear_history(&self) {
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
