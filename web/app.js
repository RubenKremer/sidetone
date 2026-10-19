// Sidetone UI: softphone panel + workspace (calls, SIP trace, analysis,
// diagnostics, settings). One frontend for three hosts:
//  - desktop app / `sidetone serve`: native engine over the local HTTP API
//  - GitHub Pages: WASM analysis and a WebRTC phone (SIP over WebSocket)

import { NativeController, WebController, webAccountDefaults } from "./controllers.js";
import { initI18n, currentLang, setLang, LANGS, t } from "./i18n.js";
import { renderHelp } from "./help.js";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const store = {
  get(k, d) {
    try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; }
  },
  set(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ }
  },
};

const token = new URLSearchParams(location.search).get("token");

// ---------- analysis backends ----------

async function wasmBackend() {
  const w = await import("./pkg/sidetone_wasm.js");
  await w.default();
  return {
    kind: "wasm",
    features: [],
    analyze: async (b) => JSON.parse(w.analyze(b)),
    ladder: async (b, call) => w.ladder_svg(b, call ?? -1),
    exportPcap: async (b, opts) => w.export_capture(b, JSON.stringify(opts)),
    prompt: async (b, call, redact, lang, q) => JSON.parse(w.ai_prompt(b, call ?? -1, redact, lang, q || "")),
    ai: async (cfg, system, prompt) => {
      const req = JSON.parse(w.ai_request(JSON.stringify(cfg), system, prompt));
      let res;
      try {
        res = await fetch(req.url, { method: "POST", headers: Object.fromEntries(req.headers), body: req.body });
      } catch {
        throw new Error(`Could not reach ${req.url}. ${cfg.provider === "ollama" ? "Start Ollama with OLLAMA_ORIGINS set to this page's origin." : "The provider may block browser requests (CORS); use the desktop app or `sidetone serve`."}`);
      }
      return w.ai_parse(cfg.provider, await res.text());
    },
    samples: async () => JSON.parse(w.samples()),
    sample: async (n) => w.sample(n),
    captureFromLog: async (log) => w.capture_from_sip_log(JSON.stringify(log)),
    parseProvision: async (xml, kind) => {
      try {
        return JSON.parse(w.parse_provision(xml, kind));
      } catch (e) {
        throw new Error(e.message || String(e));
      }
    },
  };
}

async function httpBackend() {
  const headers = token ? { "x-sidetone-token": token } : {};
  const info = await (await fetch("api/info", { headers })).json();
  const check = async (r) => {
    if (!r.ok) {
      let msg = `${r.status}`;
      try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    return r;
  };
  const post = async (path, body, type = "application/octet-stream") => check(await fetch(path, { method: "POST", headers: { ...headers, "content-type": type }, body }));
  const get = async (path) => check(await fetch(path, { headers }));
  const q = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== false).map(([k, v]) => [k, v === true ? "1" : String(v)])).toString();
  return {
    kind: "http",
    features: info.features || [],
    get,
    post,
    analyze: async (b) => (await post("api/analyze", b)).json(),
    ladder: async (b, call) => (await post(`api/ladder?${q({ call })}`, b)).text(),
    exportPcap: async (b, o) => new Uint8Array(await (await post(`api/export?${q({ call: o.call, redact: o.redact, sip_only: o.sip_only, no_annotate: o.annotate === false })}`, b)).arrayBuffer()),
    prompt: async (b, call, redact, lang, question) => (await post(`api/prompt?${q({ call, redact, lang, question })}`, b)).json(),
    ai: async (cfg, _system, prompt) => (await (await post("api/ai", JSON.stringify({ config: cfg, prompt }), "application/json")).json()).text,
    samples: async () => [
      ["good-call", "Registration with digest auth and a clean call with RFC 4733 DTMF"],
      ["nat-one-way", "Remote phone behind NAT: private SDP, missing ACK, one-way audio, drop at 32 s"],
      ["codec-488", "Carrier rejects a G.729-only offer with 488"],
      ["bad-quality", "Answered call with packet loss, jitter and a dropout"],
      ["register-timeout", "REGISTER retransmitted to a registrar that never answers"],
      ["srtp-mismatch", "SRTP offered, plain RTP answered"],
      ["demo", "All scenarios in one capture"],
    ].map(([name, description]) => ({ name, description })),
    sample: async (n) => new Uint8Array(await (await get(`api/sample?${q({ name: n })}`)).arrayBuffer()),
    captureFromLog: async (log) => new Uint8Array(await (await post("api/sip-log-capture", JSON.stringify(log), "application/json")).arrayBuffer()),
    save: (info.features || []).includes("native-save") ? async (data, name) => (await post(`api/save?${q({ name })}`, data)).json() : null,
  };
}

async function pickBackend() {
  try {
    return await httpBackend();
  } catch {
    return await wasmBackend();
  }
}

// ---------- state ----------

const S = {
  be: null,
  ctl: null,
  st: null, // latest PhoneState
  sel: null, // selected line
  events: [],
  trace: [],
  trSel: null,
  trPaused: false,
  history: [],
  recordings: [],
  xfer: null, // { from, consult }
  errors: 0,
  // analysis
  bytes: null, name: "", report: null, call: null, msg: null, webrtc: null,
};
window.__sidetone = S;

function toast(text, ms = 2800) {
  const t = $("#toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toast.h);
  toast.h = setTimeout(() => t.classList.remove("show"), ms);
}

async function download(data, name, type) {
  if (S.be && S.be.save) {
    const r = await S.be.save(data, name);
    if (r.saved) toast(`Saved ${r.saved}`);
    return;
  }
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
function dur(ms) {
  if (ms == null || ms < 0) return "";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  return h ? `${h}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}` : `${Math.floor(s / 60)}:${pad(s % 60)}`;
}
function clock(ms, withMs = false) {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${withMs ? "." + pad(d.getMilliseconds(), 3) : ""}`;
}
function when(ms) {
  const d = new Date(ms);
  const today = new Date();
  const same = d.toDateString() === today.toDateString();
  return same ? clock(ms) : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
const setMeter = (el, pct) => {
  if (el) el.style.width = `${100 - pct}%`;
};
const levelPct = (v) => {
  if (!v) return 0;
  const db = 20 * Math.log10(v / 32767);
  return Math.max(0, Math.min(100, ((db + 60) / 60) * 100));
};

// ---------- workspace ----------

function showWs(name) {
  $$(".ws-tabs [data-ws]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.ws === name)));
  $$(".ws-page").forEach((p) => (p.hidden = p.dataset.page !== name));
  S.page = name;
  store.set("sidetone.page", name);
  if (name === "trace") renderTrace(true);
  if (name === "diag") diagOpen();
  if (name === "settings") settingsOpen();
  if (name === "calls") renderHistory();
  if (name === "help") {
    renderHelp($("#help-page"), {
      lang: currentLang(),
      version: S.version,
      mode: t(S.ctl.kind === "web" ? "Browser phone (WebRTC)" : "Desktop engine (UDP)"),
      langs: LANGS,
      onLang: setLang,
    });
  }
}

// ============================================================================
// Phone panel

const STATE_TEXT = { calling: "Calling", ringing: "Ringing", early: "Early media", incoming: "Incoming", connected: "Connected", ending: "Ending", ended: "Ended" };

function lines() {
  return S.st ? S.st.calls : [];
}
function line(id) {
  return lines().find((l) => l.line === id) || null;
}
function selLine() {
  return line(S.sel);
}
function liveLines() {
  return lines().filter((l) => l.state !== "ended");
}

function pickSelection() {
  const cur = selLine();
  const live = liveLines();
  if (cur && cur.state !== "ended") return;
  const incoming = live.find((l) => l.state === "incoming");
  const talking = live.find((l) => l.state === "connected" && !l.held);
  const next = incoming || talking || live[live.length - 1] || (cur ? cur : null);
  S.sel = next ? next.line : null;
}

function accLabel(a) {
  return a.label || `${a.user}@${a.domain}`;
}

function currentAccount() {
  const st = S.st;
  if (!st || !st.accounts.length) return null;
  const id = $("#acct").value;
  return st.accounts.find((a) => a.id === id) || st.accounts[0];
}

const REG_TEXT = {
  registered: "Registered",
  registering: "Registering",
  unregistering: "Unregistering",
  failed: "Registration failed",
  unreachable: "Server not answering",
  error: "Not ready",
  off: "Not registered",
};

function regClass(a) {
  if (!a || !a.enabled) return "off";
  return { registered: "ok", registering: "busy", unregistering: "busy", failed: "bad", unreachable: "bad", error: "bad" }[a.state] || (a.register ? "off" : "idle");
}

function accountStateText(a) {
  if (!a) return S.ctl && S.ctl.kind === "web" ? "Add a WebSocket SIP account in Settings to start." : "No account yet. Add one in Settings.";
  if (!a.enabled) return "Account disabled";
  if (a.state === "registered") return `Registered as ${a.user} at ${a.server || a.domain}${a.expires_in != null ? `, renews in ${a.expires_in > 90 ? Math.round(a.expires_in / 60) + " min" : a.expires_in + " s"}` : ""}`;
  if (a.state === "failed") return `Registration failed: ${a.code ?? ""} ${a.reason ?? ""}`.trim();
  if (a.state === "unreachable") return `${a.server || a.domain} is not answering. Check address, port and firewall.`;
  if (a.state === "error") return a.error || "Not ready";
  if (!a.register && !a.domain) return `Direct calls, no registrar: dial user@host or a SIP URI (port ${(a.local || "").split(":").pop()})`;
  if (a.state === "off" && !a.register) return `Ready to call from ${a.local || "here"} (registration off)`;
  return REG_TEXT[a.state] || a.state;
}

function renderAccounts() {
  const st = S.st;
  const sel = $("#acct");
  const want = sel.value || store.get("sidetone.acct", "");
  const opts = st.accounts.map((a) => `<option value="${esc(a.id)}">${esc(accLabel(a))}</option>`).join("");
  if (sel.dataset.sig !== opts) {
    sel.innerHTML = opts || `<option value="">No account</option>`;
    sel.dataset.sig = opts;
    if (st.accounts.some((a) => a.id === want)) sel.value = want;
  }
  const a = currentAccount();
  $("#acct-dot").className = `dot ${regClass(a)}`;
  $("#acct-state").textContent = accountStateText(a);
  $("#acct-state").classList.toggle("bad", regClass(a) === "bad");
}

const BLF_TEXT = { idle: "Free", ringing: "Ringing", busy: "Busy", error: "Error", unknown: "Unknown" };
const PRES_TEXT = { available: "Available", away: "Away", busy: "Busy", dnd: "Do not disturb", offline: "Offline", unknown: "Unknown" };

function renderBlf() {
  const a = currentAccount();
  const items = a && a.blf ? a.blf : [];
  $("#blf-box").hidden = !items.length;
  $("#blf").innerHTML = items
    .map((b) => {
      // A watched phone that is not registered reads as Offline, not Free.
      const lamp = b.presence === "offline" && b.state === "idle" ? "" : t(BLF_TEXT[b.state] || b.state);
      // Presence adds to the lamp only when it says something the lamp does not.
      const pres = b.presence && !(b.presence === "available" && b.state === "idle") && !(b.presence === "busy" && b.state !== "idle") ? t(PRES_TEXT[b.presence] || b.presence) : "";
      const note = b.note && !/^(ready|on the phone|ringing|unavailable)$/i.test(b.note) ? b.note : "";
      const sub = [lamp, pres, note].filter(Boolean).join(" · ");
      const title = [b.detail, b.presence ? `${t("Presence")}: ${t(PRES_TEXT[b.presence] || b.presence)}${b.note ? ` (${b.note})` : ""}` : ""].filter(Boolean).join("\n");
      return `<button type="button" class="blf-item blf-${esc(b.state)}${b.presence ? ` pres-${esc(b.presence)}` : ""}" data-dial="${esc(b.target)}" title="${esc(title)}"><span class="dot"></span><span class="blf-t">${esc(b.target)}</span><span class="blf-s">${esc(sub)}</span></button>`;
    })
    .join("");
  const native = S.ctl.kind === "native";
  $("#pres-row").hidden = !native || !a || a.register === false;
  if (native && a) {
    const sel = $("#my-pres");
    if (document.activeElement !== sel) sel.value = a.presence || "";
    const note = $("#my-pres-note");
    if (document.activeElement !== note && !note.dataset.dirty) note.value = a.presence_note || "";
    note.hidden = !a.presence;
    $("#pres-dot").className = `dot pres-${a.presence || "none"}`;
    $("#pres-err").hidden = !a.presence_error;
    $("#pres-err").textContent = a.presence_error ? `${t("The server did not take the presence")}: ${a.presence_error}` : "";
  }
}

function publishPresence() {
  const a = currentAccount();
  if (!a) return;
  const note = $("#my-pres-note");
  note.dataset.dirty = "";
  cmd({ cmd: "presence", account: a.id, status: $("#my-pres").value || "available", note: note.value.trim() });
}

function renderLines() {
  const ls = lines();
  $("#lines-empty").hidden = ls.length > 0;
  const live = liveLines().length;
  const max = S.st ? S.st.settings.max_lines : 1;
  $("#lines-count").textContent = ls.length ? `${live} of ${S.ctl.features.multiLine ? max : 1}` : "";
  const now = Date.now();
  $("#lines").innerHTML = ls
    .map((l) => {
      const tm = l.state === "connected" && l.answered_ms ? dur(now - l.answered_ms) : l.state === "ended" ? (l.answered_ms ? dur((l.ended_ms || now) - l.answered_ms) : "") : dur(now - l.started_ms);
      const stTxt = l.state === "connected" && l.held ? "On hold" : l.state === "connected" && l.remote_held ? "Held by remote" : STATE_TEXT[l.state] || l.state;
      const multi = S.st && S.st.accounts.length > 1;
      const meta = [
        multi ? accName(l.account) : "",
        l.srtp ? "SRTP" : "",
        l.conference ? `${t("Conference")} L${l.conference}` : "",
        l.codec,
        l.state !== "incoming" && (l.rtp_sent || l.rtp_received) ? `↑${l.rtp_sent} ↓${l.rtp_received}` : "",
        l.muted ? "muted" : "",
        l.recording ? "recording" : "",
        l.state === "ended" ? resultText(l.final_code, l.reason) : "",
        l.transfer || "",
      ].filter(Boolean).map(esc).join(" · ");
      const actions =
        l.state === "incoming"
          ? `<div class="ln-act"><button type="button" class="btn small ok" data-act="answer">Answer</button><button type="button" class="btn small" data-act="reject">Reject</button></div>`
          : l.state === "connected" && l.held
          ? `<div class="ln-act"><button type="button" class="btn small" data-act="resume">Resume</button><button type="button" class="btn small" data-act="hangup">Hang up</button></div>`
          : "";
      const cls = `line st-${l.state}${l.held ? " held" : ""}${l.line === S.sel ? " sel" : ""}`;
      return `<li class="${cls}" data-line="${l.line}" tabindex="0">
        <div class="ln-top"><span class="ln-dir"><svg><use href="#i-${l.direction === "in" ? "in" : "out"}"/></svg></span><span class="ln-state">${esc(stTxt)}</span><span class="ln-dur">${tm}</span></div>
        <div class="ln-remote">${l.remote_name ? `<b>${esc(l.remote_name)}</b> ` : ""}<span>${esc(l.remote)}</span></div>
        ${meta ? `<div class="ln-meta">${meta}</div>` : ""}${actions}
      </li>`;
    })
    .join("");
}

function renderControls() {
  const l = selLine();
  const live = l && l.state !== "ended";
  const connected = l && l.state === "connected";
  const incoming = l && l.state === "incoming";
  const callBtn = $("#btn-call");
  callBtn.querySelector("span").textContent = incoming ? "Answer" : "Call";
  callBtn.classList.toggle("pulse", !!incoming);
  $("#btn-hangup").disabled = !live;
  $("#btn-hangup").querySelector("span").textContent = incoming ? "Reject" : l && ["calling", "ringing", "early"].includes(l.state) ? "Cancel" : "Hang up";
  const tool = (n) => $(`.tool[data-tool="${n}"]`);
  tool("hold").disabled = !connected;
  tool("hold").setAttribute("aria-pressed", String(!!(connected && l.held)));
  tool("hold").querySelector("span").textContent = connected && l.held ? "Resume" : "Hold";
  tool("mute").disabled = !(connected || (l && l.state === "early"));
  tool("mute").setAttribute("aria-pressed", String(!!(l && l.muted)));
  tool("transfer").disabled = !connected;
  tool("record").disabled = !(connected && S.ctl.features.record);
  const others = liveLines().filter((x) => x.state === "connected" && (!l || x.line !== l.line));
  tool("conf").hidden = !(S.ctl.kind === "native" || S.ctl.features.conference);
  tool("conf").disabled = !(connected && (l.conference || others.length));
  tool("conf").setAttribute("aria-pressed", String(!!(l && l.conference)));
  tool("record").setAttribute("aria-pressed", String(!!(l && l.recording)));
  const st = S.st ? S.st.settings : {};
  tool("dnd").setAttribute("aria-pressed", String(!!st.dnd));
  tool("aa").setAttribute("aria-pressed", String(!!st.auto_answer));
  // Complete-transfer button appears once the consult call is up.
  if (S.xfer && S.xfer.consult) {
    const c = line(S.xfer.consult);
    const f = line(S.xfer.from);
    const ready = c && c.state === "connected" && f && f.state === "connected";
    $("#xfer-complete").hidden = !ready;
    $("#xfer-note").textContent = ready ? "Talk to the new party, then complete the transfer." : c && c.state !== "ended" ? `Consult call: ${STATE_TEXT[c.state] || c.state}` : "Consult call ended.";
  }
}

function renderMeters() {
  let l = selLine() || liveLines().find((x) => x.state === "connected");
  if (l && l.state === "ended") l = null;
  setMeter($("#m-tx"), l ? levelPct(l.tx_level) : 0);
  setMeter($("#m-rx"), l ? levelPct(l.rx_level) : 0);
  const st = S.st;
  let src = "";
  if (S.ctl.kind === "web") src = "Browser microphone and speaker";
  else if (st) {
    const s = st.settings.audio_source;
    src = s === "device" ? (st.audio_device ? "Sound card" : "No sound card: sending a test tone") : s === "tone" ? `Test tone ${st.settings.tone_hz} Hz` : s === "echo" ? "Echoing received audio" : "Sending silence";
  }
  $("#audio-src").textContent = src;
}

function renderStatus() {
  const st = S.st;
  const a = currentAccount();
  $("#st-acct").innerHTML = `<span class="dot ${regClass(a)}"></span><span>${a ? `${esc(accLabel(a))}: ${esc(REG_TEXT[a.state] || a.state)}` : "No account"}</span>`;
  $("#st-net").textContent = a && a.local ? (S.ctl.kind === "web" ? `WSS ${a.server || ""}` : `${a.transport || "UDP"} ${a.local} → ${a.server || "direct"}`) : "";
  $("#st-nat").textContent = !a || !a.public ? "" : S.ctl.kind === "web" ? `Server sees ${a.public}` : a.public !== a.local ? `Seen as ${a.public} (NAT)` : "No NAT on the signaling path";
  const live = liveLines().length;
  $("#st-lines").textContent = live ? `${live} call${live > 1 ? "s" : ""}` : "Idle";
  $("#st-cap").textContent = st ? `${st.capture_packets.toLocaleString()} packets captured` : "";
  $("#trace-count").textContent = S.trace.length ? S.trace.length.toLocaleString() : "";
  const e = $("#st-err");
  e.hidden = !S.errors;
  e.textContent = `${S.errors} problem${S.errors === 1 ? "" : "s"}`;
}

let lastIncoming = new Set();
function onState(st) {
  const prev = S.st;
  S.st = st;
  // New incoming calls take the selection and the user's attention.
  const inc = st.calls.filter((c) => c.state === "incoming").map((c) => c.line);
  for (const id of inc) {
    if (!lastIncoming.has(id)) {
      S.sel = id;
      const c = line(id);
      toast(`Incoming call from ${c.remote_name || c.remote}`);
      flashTitle(`Incoming: ${c.remote_name || c.remote}`);
    }
  }
  lastIncoming = new Set(inc);
  // Lines that just ended with a recording become downloadable.
  if (prev) {
    for (const c of st.calls) {
      const was = prev.calls.find((p) => p.line === c.line);
      if (was && was.state !== "ended" && c.state === "ended") {
        if (c.recording && S.ctl.features.record) S.recordings.unshift({ line: c.line, remote: c.remote, ended: c.ended_ms });
        if (S.page === "calls") setTimeout(renderHistory, 400);
      }
    }
  }
  pickSelection();
  renderAccounts();
  renderBlf();
  renderLines();
  renderControls();
  renderMeters();
  renderStatus();
  if (S.page === "calls") renderCallDetail();
  if (S.page === "calls" && !prev) renderHistory();
  if (S.page === "settings" && SET.cfg) renderSetNav();
}

function flashTitle(text) {
  clearInterval(flashTitle.t);
  let on = false;
  flashTitle.t = setInterval(() => {
    const ringing = liveLines().some((l) => l.state === "incoming");
    if (!ringing) {
      document.title = "Sidetone";
      clearInterval(flashTitle.t);
      return;
    }
    on = !on;
    document.title = on ? text : "Sidetone";
  }, 900);
}

async function cmd(o, quiet = false) {
  try {
    return await S.ctl.cmd(o);
  } catch (e) {
    if (!quiet) toast(e.message || String(e), 4500);
    return null;
  }
}

function parseHeaders(text) {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      return i > 0 ? [l.slice(0, i).trim(), l.slice(i + 1).trim()] : null;
    })
    .filter(Boolean);
}

function rememberDialed(t) {
  const h = store.get("sidetone.dialed", []).filter((x) => x !== t);
  h.unshift(t);
  store.set("sidetone.dialed", h.slice(0, 30));
  renderDialHistory();
}
function renderDialHistory() {
  $("#dial-history").innerHTML = store.get("sidetone.dialed", []).map((t) => `<option value="${esc(t)}">`).join("");
}

async function dial(target) {
  target = (target ?? $("#dial").value).trim();
  if (!target) {
    $("#dial").focus();
    return;
  }
  const a = currentAccount();
  const req = { cmd: "call", target, account: a ? a.id : null };
  const hdr = parseHeaders($("#opt-headers").value);
  if (hdr.length) req.headers = hdr;
  const ov = $("#opt-overrides").value.trim();
  if (ov && S.ctl.features.overrides) {
    try {
      req.overrides = JSON.parse(ov);
    } catch (e) {
      toast(`Profile overrides are not valid JSON: ${e.message}`, 5000);
      return;
    }
  }
  rememberDialed(target);
  const r = await cmd(req);
  if (r && r.line) S.sel = r.line;
  return r;
}

function callOrAnswer() {
  const l = selLine();
  if (l && l.state === "incoming") return cmd({ cmd: "answer", line: l.line });
  return dial();
}

function hangupSel() {
  const l = selLine();
  if (!l || l.state === "ended") return;
  if (l.state === "incoming") return cmd({ cmd: "reject", line: l.line, code: 486 });
  return cmd({ cmd: "hangup", line: l.line });
}

function keyPress(k) {
  const b = $(`#keypad [data-key="${CSS.escape(k)}"]`);
  if (b) {
    b.classList.add("hit");
    setTimeout(() => b.classList.remove("hit"), 140);
  }
  const l = selLine();
  if (l && (l.state === "connected" || l.state === "early")) cmd({ cmd: "dtmf", line: l.line, digits: k });
  else {
    const d = $("#dial");
    d.value += k;
  }
}

async function analyzeLine(callId) {
  try {
    const bytes = await S.ctl.capture(S.be);
    await load(bytes, `sidetone-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, S.ctl.kind === "web" ? S.ctl.lastSummary : null);
    showWs("analysis");
    if (callId && S.report) {
      const i = S.report.calls.findIndex((c) => c.call_id === callId);
      if (i >= 0) selectCall(i);
    }
  } catch (e) {
    toast(`Nothing to analyze yet: ${e.message || e}`, 4000);
  }
}

function openXfer() {
  const l = selLine();
  if (!l || l.state !== "connected") return;
  S.xfer = { from: l.line, consult: null };
  $("#xfer").hidden = false;
  $("#xfer-who").textContent = l.remote_name || l.remote;
  $("#xfer-complete").hidden = true;
  $("#xfer-consult").hidden = !S.ctl.features.attended;
  $("#xfer-note").textContent = S.ctl.features.attended ? "Blind sends the call away now. Consult calls the target first, then you complete the transfer." : "Blind transfer only on this account.";
  $("#xfer-to").value = "";
  $("#xfer-to").focus();
}
function closeXfer() {
  S.xfer = null;
  $("#xfer").hidden = true;
}

function bindPhone() {
  $("#acct").addEventListener("change", () => {
    store.set("sidetone.acct", $("#acct").value);
    if (S.ctl.kind === "web") S.ctl.activate($("#acct").value);
    renderAccounts();
    renderStatus();
  });
  $("#acct-reg").addEventListener("click", () => {
    const a = currentAccount();
    if (a) cmd({ cmd: "register", account: a.id });
  });
  $("#opts-toggle").addEventListener("click", () => {
    const o = $("#opts");
    o.hidden = !o.hidden;
    $("#opts-toggle").setAttribute("aria-expanded", String(!o.hidden));
  });
  $("#btn-call").addEventListener("click", callOrAnswer);
  $("#btn-hangup").addEventListener("click", hangupSel);
  $("#dial").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      callOrAnswer();
    }
  });
  $$("#keypad button").forEach((b) => b.addEventListener("click", () => keyPress(b.dataset.key)));

  $(".tools").addEventListener("click", async (e) => {
    const b = e.target.closest(".tool");
    if (!b || b.disabled) return;
    const l = selLine();
    const st = S.st ? S.st.settings : {};
    switch (b.dataset.tool) {
      case "hold":
        if (l) cmd({ cmd: "hold", line: l.line, on: !l.held });
        break;
      case "mute":
        if (l) cmd({ cmd: "mute", line: l.line, on: !l.muted });
        break;
      case "record":
        if (l) cmd({ cmd: "record", line: l.line, on: !l.recording });
        break;
      case "conf": {
        if (!l) break;
        if (l.conference) {
          cmd({ cmd: "conference", line: l.line, to_line: l.conference, on: false });
          break;
        }
        const other = liveLines()
          .filter((x) => x.state === "connected" && x.line !== l.line)
          .sort((a, b) => (b.answered_ms || 0) - (a.answered_ms || 0))[0];
        if (other) cmd({ cmd: "conference", line: l.line, to_line: other.line, on: true });
        break;
      }
      case "transfer":
        if ($("#xfer").hidden) openXfer();
        else closeXfer();
        break;
      case "keypad": {
        const on = $("#keypad").hidden;
        $("#keypad").hidden = !on;
        b.setAttribute("aria-pressed", String(on));
        store.set("sidetone.keypad", on);
        break;
      }
      case "dnd":
        await cmd({ cmd: "dnd", on: !st.dnd });
        toast(!st.dnd ? "Do not disturb: incoming calls are rejected" : "Do not disturb off");
        break;
      case "aa":
        await cmd({ cmd: "auto_answer", on: !st.auto_answer });
        toast(!st.auto_answer ? "Auto answer on" : "Auto answer off");
        break;
      case "analyze": {
        const target = l || lines()[lines().length - 1];
        analyzeLine(target ? target.call_id : null);
        break;
      }
    }
  });

  $("#my-pres").addEventListener("change", publishPresence);
  $("#my-pres-note").addEventListener("input", (e) => (e.target.dataset.dirty = "1"));
  $("#my-pres-note").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      publishPresence();
      e.target.blur();
    }
  });
  $("#my-pres-note").addEventListener("change", publishPresence);
  $("#blf").addEventListener("click", (e) => {
    const b = e.target.closest("[data-dial]");
    if (b) {
      $("#dial").value = b.dataset.dial;
      dial(b.dataset.dial);
    }
  });
  $("#lines").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-line]");
    if (!li) return;
    const id = +li.dataset.line;
    const act = e.target.closest("[data-act]");
    S.sel = id;
    if (act) {
      const a = act.dataset.act;
      if (a === "answer") cmd({ cmd: "answer", line: id });
      if (a === "reject") cmd({ cmd: "reject", line: id, code: 486 });
      if (a === "resume") cmd({ cmd: "hold", line: id, on: false });
      if (a === "hangup") cmd({ cmd: "hangup", line: id });
    }
    renderLines();
    renderControls();
    renderMeters();
    if (S.page === "calls") renderCallDetail();
  });

  $("#xfer-blind").addEventListener("click", async () => {
    const t = $("#xfer-to").value.trim();
    if (!t || !S.xfer) return;
    await cmd({ cmd: "transfer", line: S.xfer.from, target: t });
    closeXfer();
  });
  $("#xfer-consult").addEventListener("click", async () => {
    const t = $("#xfer-to").value.trim();
    if (!t || !S.xfer) return;
    const from = line(S.xfer.from);
    if (from && !from.held) await cmd({ cmd: "hold", line: from.line, on: true });
    const r = await dial(t);
    if (r && r.line) S.xfer.consult = r.line;
    renderControls();
  });
  $("#xfer-complete").addEventListener("click", async () => {
    if (!S.xfer || !S.xfer.consult) return;
    await cmd({ cmd: "attended_transfer", line: S.xfer.from, to_line: S.xfer.consult });
    toast("Transfer requested");
    closeXfer();
  });
  $("#xfer-cancel").addEventListener("click", closeXfer);
  $("#xfer-to").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("#xfer-blind").click();
    }
    if (e.key === "Escape") closeXfer();
  });

  // Hotkeys: Enter call/answer, Esc hang up, F2 transfer, F3 hold, F4 mute, digits send DTMF.
  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    const typing = ["input", "textarea", "select"].includes(tag) && e.target.id !== "dial";
    if (e.key === "F2") { e.preventDefault(); $('.tool[data-tool="transfer"]').click(); return; }
    if (e.key === "F3") { e.preventDefault(); $('.tool[data-tool="hold"]').click(); return; }
    if (e.key === "F4") { e.preventDefault(); $('.tool[data-tool="mute"]').click(); return; }
    if (typing) return;
    const l = selLine();
    if (e.key === "Escape") {
      if ($$(".menu.open").length) return;
      if (!$("#xfer").hidden) return closeXfer();
      if (l && l.state !== "ended") {
        e.preventDefault();
        hangupSel();
      }
      return;
    }
    if (e.target.id === "dial") return;
    if (e.key === "Enter" && l && l.state === "incoming") {
      e.preventDefault();
      cmd({ cmd: "answer", line: l.line });
      return;
    }
    if (/^[0-9*#]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
      if (l && (l.state === "connected" || l.state === "early")) {
        e.preventDefault();
        keyPress(e.key);
      } else {
        e.preventDefault();
        $("#dial").value += e.key;
        $("#dial").focus();
      }
    }
  });

  if (store.get("sidetone.keypad", true) === false) {
    $("#keypad").hidden = true;
    $('.tool[data-tool="keypad"]').setAttribute("aria-pressed", "false");
  }
  renderDialHistory();
  setInterval(() => {
    if (liveLines().length) renderLines();
  }, 1000);
}

// ============================================================================
// Calls page

function kv(rows) {
  return `<dl class="kv">${rows
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`)
    .join("")}</dl>`;
}

function renderCallDetail() {
  const l = selLine() || lines()[lines().length - 1];
  const body = $("#call-detail-body");
  if (!l) {
    body.innerHTML = `<p class="empty-note">Details of the selected line show here: media addresses, codec, packets, DTMF and transfer progress.</p>`;
    renderRecordings();
    return;
  }
  const now = Date.now();
  const m = (s) => `<span class="mono">${esc(s)}</span>`;
  body.innerHTML = `
    <div class="cd-head"><span class="badge st-${l.state}">${esc(STATE_TEXT[l.state] || l.state)}</span><b>${esc(l.remote_name || "")}</b> ${m(l.remote)}</div>
    ${kv([
      ["Direction", l.direction === "in" ? "Incoming" : "Outgoing"],
      ["Account", esc(accName(l.account))],
      ["Call-ID", m(l.call_id)],
      ["Talk time", l.answered_ms ? dur((l.ended_ms || now) - l.answered_ms) : ""],
      ["Codec", esc(l.codec || "")],
      ["Media encryption", S.ctl.kind !== "native" && l.state === "connected" ? "DTLS-SRTP (WebRTC)" : l.srtp ? `${esc(l.security || "SRTP")}${l.srtp_failed ? ` <span class="bad">${l.srtp_failed} packets failed authentication</span>` : ""}` : l.state === "connected" ? "none (RTP)" : ""],
      ["Local media", l.local_media ? m(l.local_media) : ""],
      ["Remote media", l.remote_media ? m(l.remote_media) : ""],
      ["RTP sent / received", l.rtp_sent || l.rtp_received ? `${l.rtp_sent.toLocaleString()} / ${l.rtp_received.toLocaleString()}${l.state === "connected" && !l.held && l.rtp_sent > 100 && l.rtp_received === 0 ? ` <span class="bad">no audio from the far end</span>` : ""}` : ""],
      ["Hold", l.held ? "held by you" : l.remote_held ? "held by the remote side" : ""],
      ["DTMF received", l.dtmf_rx ? m(l.dtmf_rx) : ""],
      ["Transfer", esc(l.transfer || "")],
      ["Result", l.final_code || l.reason ? esc(resultText(l.final_code, l.reason)) : ""],
      ["Ended by", esc(l.ended_by || "")],
    ])}
    <div class="row">
      <button type="button" class="btn small" id="cd-analyze">Analyze this call</button>
      ${l.recording && S.ctl.features.record ? `<button type="button" class="btn small" id="cd-rec">Download recording</button>` : ""}
    </div>`;
  $("#cd-analyze").addEventListener("click", () => analyzeLine(l.call_id));
  const rb = $("#cd-rec");
  if (rb) rb.addEventListener("click", () => downloadRecording(l.line, l.remote));
  renderRecordings();
}

async function downloadRecording(lineId, remote) {
  try {
    const w = await S.ctl.recording(lineId);
    await download(w, `sidetone-${String(remote).replace(/[^\w@.-]+/g, "_")}-line${lineId}.wav`, "audio/wav");
  } catch (e) {
    toast(e.message || String(e), 4000);
  }
}

function renderRecordings() {
  let el = $("#recs");
  if (!S.recordings.length) {
    if (el) el.remove();
    return;
  }
  if (!el) {
    $("#call-detail").insertAdjacentHTML("beforeend", `<div id="recs" class="recs"></div>`);
    el = $("#recs");
  }
  el.innerHTML = `<h3>Recordings this session</h3><ul>${S.recordings
    .map((r) => `<li><button type="button" class="linklike" data-rec="${r.line}">${esc(r.remote)}, ${clock(r.ended)}</button></li>`)
    .join("")}</ul><p class="hint">Stereo WAV: left is what Sidetone sent, right is what it received.</p>`;
  el.querySelectorAll("[data-rec]").forEach((b) => b.addEventListener("click", () => downloadRecording(+b.dataset.rec, S.recordings.find((r) => r.line === +b.dataset.rec).remote)));
}

const EV_KIND = { reg: "Registration", call: "Call", incoming: "Incoming", media: "Media", dtmf: "DTMF", transfer: "Transfer", error: "Problem", account: "Account", diag: "Diagnostics", message: "Message", info: "Info" };

function onEvents(evs) {
  for (const e of evs) {
    S.events.push(e);
    if (e.kind === "error") S.errors++;
    if (e.kind === "provisioned" && S.page === "settings" && SET.cfg) {
      if (SET.dirty) toast(t("Provisioning updated the saved account. Your unsaved edits are still here."));
      else {
        S.ctl.getConfig().then((c) => {
          SET.cfg = c;
          renderSetNav();
          renderSetBody();
        }).catch(() => {});
      }
    }
  }
  if (S.events.length > 1000) S.events.splice(0, S.events.length - 1000);
  renderEvents(evs);
}

function renderEvents(newOnes) {
  const ol = $("#events");
  const fmt = (e) => `<li class="ev-${esc(e.kind)}"><span class="ev-t">${clock(e.ts_ms)}</span><span class="ev-k">${esc(EV_KIND[e.kind] || e.kind)}${e.line ? ` L${e.line}` : ""}</span><span class="ev-x">${esc(e.text)}</span></li>`;
  if (!newOnes) {
    ol.innerHTML = S.events.slice(-300).reverse().map(fmt).join("");
    return;
  }
  ol.insertAdjacentHTML("afterbegin", newOnes.slice().reverse().map(fmt).join(""));
  while (ol.children.length > 300) ol.lastElementChild.remove();
}

/// "404 Not Found" from a code and a reason that may already start with it.
function resultText(code, reason) {
  if (reason && code && String(reason).startsWith(String(code))) return reason;
  return [code, reason].filter(Boolean).join(" ");
}

function accName(id) {
  const a = S.st && S.st.accounts.find((x) => x.id === id);
  return a ? accLabel(a) : id;
}

async function renderHistory() {
  try {
    S.history = await S.ctl.history();
  } catch {
    S.history = [];
  }
  const f = $("#hist-filter").value.trim().toLowerCase();
  const rows = S.history.filter((h) => !f || `${h.remote} ${h.remote_name || ""} ${h.final_code || ""} ${h.reason || ""} ${h.call_id}`.toLowerCase().includes(f));
  $("#hist-empty").hidden = rows.length > 0;
  $("#hist").innerHTML = rows
    .slice(0, 300)
    .map((h, i) => {
      const missed = h.direction === "in" && !h.answered;
      const icon = missed ? "missed" : h.direction === "in" ? "in" : "out";
      const result = h.answered ? "Answered" : resultText(h.final_code, h.reason) || "Not answered";
      return `<tr class="${missed ? "missed" : ""}">
        <td><svg class="hi" aria-label="${icon}"><use href="#i-${icon}"/></svg></td>
        <td>${h.remote_name ? `<b>${esc(h.remote_name)}</b> ` : ""}<span class="mono">${esc(h.remote)}</span></td>
        <td>${when(h.started_ms)}</td>
        <td class="num">${h.answered ? dur(h.duration_s * 1000) : ""}</td>
        <td class="${h.answered ? "" : "muted"}">${esc(result)}</td>
        <td class="muted">${esc(accName(h.account))}</td>
        <td class="acts"><button type="button" class="linklike" data-redial="${i}">Call</button> <button type="button" class="linklike" data-han="${i}">Analyze</button></td>
      </tr>`;
    })
    .join("");
  $("#hist").onclick = (e) => {
    const r = e.target.closest("[data-redial]");
    if (r) {
      const h = rows[+r.dataset.redial];
      $("#dial").value = h.remote;
      dial(h.remote);
    }
    const a = e.target.closest("[data-han]");
    if (a) analyzeLine(rows[+a.dataset.han].call_id);
  };
  renderCallDetail();
}

// ============================================================================
// SIP trace

function traceVisible(t) {
  if ($("#tr-hide-reg").checked && t.method === "REGISTER") return false;
  if ($("#tr-hide-opt").checked && ["OPTIONS", "NOTIFY", "SUBSCRIBE", "PUBLISH"].includes(t.method)) return false;
  const f = $("#tr-filter").value.trim().toLowerCase();
  if (!f) return true;
  return `${t.first_line} ${t.call_id} ${t.src} ${t.dst} ${t.cseq}`.toLowerCase().includes(f) || t.raw.toLowerCase().includes(f);
}

function traceRow(t) {
  const cls = t.status ? (t.status >= 400 ? "r-err" : t.status >= 300 ? "r-warn" : t.status >= 200 ? "r-ok" : "r-prov") : "r-req";
  return `<div class="tr-row ${t.dir} ${cls}${t.seq === S.trSel ? " sel" : ""}" data-seq="${t.seq}">
    <span class="tr-t">${clock(t.ts_ms, true)}</span>
    <span class="tr-d">${t.dir === "out" ? "→" : "←"}</span>
    <span class="tr-a">${esc(t.dir === "out" ? t.dst : t.src)}</span>
    <span class="tr-f">${esc(t.first_line)}</span>
    <span class="tr-c">${esc(t.call_id.slice(0, 14))}</span>
  </div>`;
}

function onTrace(items) {
  if (!items.length) return;
  for (const t of items) S.trace.push(t);
  if (S.trace.length > 5000) S.trace.splice(0, S.trace.length - 5000);
  if (S.page === "trace" && !S.trPaused) {
    const list = $("#tr-list");
    const atEnd = list.scrollTop + list.clientHeight >= list.scrollHeight - 30;
    list.insertAdjacentHTML("beforeend", items.filter(traceVisible).map(traceRow).join(""));
    while (list.children.length > 3000) list.firstElementChild.remove();
    if (atEnd) list.scrollTop = list.scrollHeight;
  }
  renderStatus();
}

function renderTrace(scroll) {
  const list = $("#tr-list");
  const rows = S.trace.filter(traceVisible).slice(-3000);
  list.innerHTML = rows.length ? rows.map(traceRow).join("") : `<p class="empty-note pad">${S.trace.length ? "No messages match the filter." : "SIP messages sent and received by the phone appear here live."}</p>`;
  if (scroll) list.scrollTop = list.scrollHeight;
}

function bindTrace() {
  ["tr-filter", "tr-hide-reg", "tr-hide-opt"].forEach((id) => $("#" + id).addEventListener("input", () => renderTrace(false)));
  $("#tr-list").addEventListener("click", (e) => {
    const r = e.target.closest(".tr-row");
    if (!r) return;
    S.trSel = +r.dataset.seq;
    $$(".tr-row.sel").forEach((x) => x.classList.remove("sel"));
    r.classList.add("sel");
    const t = S.trace.find((x) => x.seq === S.trSel);
    if (t) $("#tr-view").innerHTML = `<span class="muted">${esc(t.dir === "out" ? "Sent" : "Received")} ${clock(t.ts_ms, true)}, ${esc(t.transport)} ${esc(t.src)} → ${esc(t.dst)}, ${t.size} bytes</span>\n\n${highlightSip(t.raw)}`;
  });
  $("#tr-list").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const cur = $(".tr-row.sel");
    const next = cur ? (e.key === "ArrowDown" ? cur.nextElementSibling : cur.previousElementSibling) : $(".tr-row");
    if (next) {
      next.click();
      next.scrollIntoView({ block: "nearest" });
    }
  });
  $("#tr-pause").addEventListener("click", (e) => {
    S.trPaused = !S.trPaused;
    e.target.setAttribute("aria-pressed", String(S.trPaused));
    e.target.textContent = S.trPaused ? "Resume" : "Pause";
    if (!S.trPaused) renderTrace(true);
  });
  $("#tr-clear").addEventListener("click", async () => {
    S.trace = [];
    S.trSel = null;
    $("#tr-view").innerHTML = "";
    await S.ctl.clearCapture().catch(() => {});
    renderTrace(false);
    renderStatus();
  });
  $("#tr-save").addEventListener("click", async () => {
    try {
      const b = await S.ctl.capture(S.be);
      await download(b, `sidetone-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, "application/vnd.tcpdump.pcap");
    } catch (e) {
      toast(e.message || String(e), 4000);
    }
  });
  $("#tr-analyze").addEventListener("click", () => {
    const t = S.trace.find((x) => x.seq === S.trSel);
    analyzeLine(t ? t.call_id : null);
  });
}

// ============================================================================
// Analysis (captures)

async function load(bytes, name, webrtc = null) {
  try {
    const report = await S.be.analyze(bytes);
    Object.assign(S, { bytes, name, report, call: null, msg: null, webrtc });
  } catch (e) {
    toast(`Could not read ${name}: ${e.message || e}`, 5000);
    return;
  }
  $("#an-empty").hidden = true;
  $("#an").hidden = false;
  const s = S.report.summary;
  $("#capinfo").textContent = `${name}: ${s.calls} dialogs, ${s.sip_messages} SIP messages, ${s.rtp_streams} RTP streams, ${s.duration_s.toFixed(1)} s, ${s.errors} errors, ${s.warnings} warnings`;
  renderCalls();
  const r = S.report;
  const first = r.calls.findIndex((c) => c.errors > 0);
  const inv = r.calls.findIndex((c) => c.kind === "INVITE");
  await selectCall(first >= 0 ? first : inv >= 0 ? inv : r.calls.length ? 0 : null);
}

async function loadFile(f) {
  await load(new Uint8Array(await f.arrayBuffer()), f.name);
  showWs("analysis");
}

const AN_STATE = { answered: "Answered", failed: "Failed", cancelled: "Cancelled", in_progress: "No answer", non_invite: "" };

function renderCalls() {
  const r = S.report;
  $("#calls-count").textContent = r.calls.length;
  $("#calls").innerHTML = r.calls
    .map((c) => {
      const st = c.state;
      const label = st === "non_invite" ? (c.final_status ? `${c.final_status}` : "no answer") : `${AN_STATE[st]}${c.final_status ? " " + c.final_status : ""}`;
      const counts = `${c.errors ? `<span class="cnt-e">${c.errors} error${c.errors > 1 ? "s" : ""}</span>` : ""}${c.warnings ? `<span class="cnt-w">${c.warnings} warning${c.warnings > 1 ? "s" : ""}</span>` : ""}`;
      return `<li><button type="button" data-call="${c.index}">
        <span class="c-top"><span>${esc(c.kind)}</span><span class="state ${st}">${esc(label)}</span></span>
        <span class="c-parties">${esc(c.from)} → ${esc(c.to)}</span>
        <span class="c-meta"><span>+${c.start_rel_s.toFixed(1)} s</span>${c.talk_s != null ? `<span>${c.talk_s.toFixed(1)} s talk</span>` : ""}${counts}</span>
      </button></li>`;
    })
    .join("");
}

async function selectCall(i) {
  S.call = i;
  S.msg = null;
  $$("#calls button").forEach((b) => b.setAttribute("aria-current", String(+b.dataset.call === i)));
  const r = S.report;
  const c = i == null ? null : r.calls[i];
  $("#call-head").innerHTML = c
    ? `<h2>${esc(c.call_id)}</h2><dl>
        ${c.final_status ? `<div><dt>Final</dt><dd>${c.final_status} ${esc(c.final_reason || "")}</dd></div>` : ""}
        ${c.pdd_ms != null ? `<div><dt>Post-dial delay</dt><dd>${(c.pdd_ms / 1000).toFixed(2)} s</dd></div>` : ""}
        ${c.talk_s != null ? `<div><dt>Talk</dt><dd>${c.talk_s.toFixed(1)} s</dd></div>` : ""}
        ${c.ended_by ? `<div><dt>Ended by</dt><dd>${esc(c.ended_by)}</dd></div>` : ""}
        ${c.offer_codecs.length ? `<div><dt>Offer</dt><dd>${esc(c.offer_codecs.join(", "))}</dd></div>` : ""}
        ${c.answer_codecs.length ? `<div><dt>Answer</dt><dd>${esc(c.answer_codecs.join(", "))}</dd></div>` : ""}
        ${c.user_agents.length ? `<div><dt>Agents</dt><dd>${esc(c.user_agents.join(" / "))}</dd></div>` : ""}
      </dl>`
    : `<h2>All messages</h2>`;
  $("#ladder").innerHTML = await S.be.ladder(S.bytes, i);
  renderFindings();
  renderMedia();
  renderLog();
  $("#tab-message").innerHTML = `<p class="empty-note">Click an arrow in the ladder to see the full message.</p>`;
}

function callFindings() {
  return S.report.findings.filter((f) => S.call == null || f.call === S.call || f.call == null);
}

function renderFindings() {
  const fs = callFindings();
  $("#n-findings").textContent = fs.length || "";
  if (!fs.length) {
    $("#tab-findings").innerHTML = `<p class="empty-note">No findings for this dialog. Signaling and media look as expected.</p>`;
    return;
  }
  const sevName = { error: "Error", warning: "Warning", info: "Note" };
  $("#tab-findings").innerHTML = `<ul class="findings">${fs
    .map((f) => {
      const idx = S.report.findings.indexOf(f);
      return `<li class="${f.severity}" data-finding="${idx}" tabindex="0">
        <div><span class="f-sev">${sevName[f.severity]}</span><span class="f-title">${esc(f.title)}</span></div>
        <div class="f-detail">${esc(f.detail)}</div>
        <div class="f-rule">${esc(f.rule)}${f.messages.length ? `, messages ${f.messages.map((m) => "#" + m).join(" ")}` : ""}</div>
      </li>`;
    })
    .join("")}</ul>`;
}

function highlightSip(raw) {
  const sep = raw.search(/\r?\n\r?\n/);
  const head = sep >= 0 ? raw.slice(0, sep) : raw;
  const body = sep >= 0 ? raw.slice(sep).replace(/^\r?\n\r?\n/, "") : "";
  const ls = head.split(/\r?\n/);
  const out = [`<span class="sl">${esc(ls[0])}</span>`];
  for (const l of ls.slice(1)) {
    const i = l.indexOf(":");
    out.push(i > 0 ? `<span class="hn">${esc(l.slice(0, i))}</span>${esc(l.slice(i))}` : esc(l));
  }
  return out.join("\n") + (body ? `\n\n<span class="sdp">${esc(body)}</span>` : "");
}

function selectMessage(idx, switchTab = true) {
  S.msg = idx;
  $$("#ladder .msg").forEach((g) => g.classList.toggle("sel", +g.dataset.msg === idx));
  const g = $(`#ladder .msg[data-msg="${idx}"]`);
  if (g) g.scrollIntoView({ block: "nearest", inline: "nearest" });
  const m = S.report.messages[idx];
  const related = S.report.findings.filter((f) => f.messages.includes(idx));
  $("#tab-message").innerHTML = `
    <div class="msg-meta"><span>#${m.index}</span><span>frame ${m.frame}</span><span>+${m.rel_s.toFixed(3)} s</span><span>${esc(m.src)} → ${esc(m.dst)}</span><span>${m.transport}</span>${m.retransmission ? "<span>retransmission</span>" : ""}</div>
    ${m.parse_notes.length ? `<p class="msg-notes">${esc(m.parse_notes.join("; "))}</p>` : ""}
    ${related.length ? `<ul class="findings" style="margin-bottom:10px">${related.map((f) => `<li class="${f.severity}"><span class="f-title">${esc(f.title)}</span><div class="f-detail">${esc(f.detail)}</div></li>`).join("")}</ul>` : ""}
    <pre class="sipmsg">${highlightSip(m.raw)}</pre>`;
  if (switchTab) showTab("message");
}

function webrtcBlock() {
  const w = S.webrtc;
  if (!w) return "";
  const rows = [
    ["Codec", w.codec], ["Packets received", w.packets_received], ["Packets sent", w.packets_sent], ["Packets lost", w.packets_lost],
    ["Loss", `${w.loss_pct}%`], ["Max jitter", `${w.max_jitter_ms} ms`], ["Max round trip", `${w.max_rtt_ms} ms`], ["ICE path", w.ice_path], ["Seconds measured", w.seconds],
  ].filter(([, v]) => v !== undefined && v !== null);
  return `<section class="webrtc"><h3>Browser WebRTC statistics</h3><dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <p class="muted">Media was DTLS-SRTP inside the browser, so it is not part of the capture; these numbers come from getStats().</p></section>`;
}

function renderMedia() {
  const r = S.report;
  const streams = r.streams.filter((s) => S.call == null || s.call === S.call);
  $("#n-media").textContent = streams.length || (S.webrtc ? "1" : "");
  if (S.webrtc && !streams.length) {
    $("#tab-media").innerHTML = webrtcBlock();
    return;
  }
  if (!streams.length) {
    $("#tab-media").innerHTML = `<p class="empty-note">${r.streams.length ? "No RTP linked to this dialog." : "The capture has no RTP. Capture media too (not only port 5060) to analyze audio."}</p>`;
    return;
  }
  const cls = (v, w, b) => (v >= b ? "bad" : v >= w ? "warn" : "");
  $("#tab-media").innerHTML = `<table class="media"><thead><tr>
      <th>Stream</th><th>Codec</th><th>Packets</th><th>Lost</th><th>Loss</th><th>Jitter</th><th>Max jitter</th><th>Max gap</th><th>ptime</th><th>MOS est.</th><th>DTMF</th></tr></thead><tbody>
    ${streams
      .map(
        (s) => `<tr data-stream="${s.id}"><td>${esc(s.src)} → ${esc(s.dst)}<br><span class="muted">SSRC ${esc(s.ssrc)}</span></td>
        <td>${esc(s.codec)}</td><td>${s.packets}</td><td>${Math.max(0, s.lost)}</td>
        <td class="${cls(s.loss_pct, 1, 5)}">${s.loss_pct.toFixed(2)}%</td>
        <td class="${cls(s.jitter_ms, 30, 60)}">${s.jitter_ms.toFixed(1)} ms</td>
        <td class="${cls(s.max_jitter_ms, 50, 80)}">${s.max_jitter_ms.toFixed(1)} ms</td>
        <td class="${cls(s.max_gap_ms, 500, 1000)}">${s.max_gap_ms.toFixed(0)} ms</td>
        <td>${s.mean_ptime_ms ? s.mean_ptime_ms.toFixed(0) + " ms" : ""}</td>
        <td class="${s.mos == null ? "" : s.mos < 3.1 ? "bad" : s.mos < 3.6 ? "warn" : ""}">${s.mos == null ? "n/a" : s.mos.toFixed(2)}</td>
        <td>${esc(s.dtmf_events.join(""))}</td></tr>`
      )
      .join("")}</tbody></table>
    <p class="muted">MOS is an E-model (ITU-T G.107) estimate from loss and jitter at this capture point; network delay is approximated.</p>${webrtcBlock()}`;
}

function renderLog() {
  const r = S.report;
  const idxs = S.call == null ? r.messages.map((m) => m.index) : r.calls[S.call].messages;
  $("#tab-log").innerHTML = `<div class="trace">${idxs
    .map((i) => {
      const m = r.messages[i];
      const t = new Date(m.ts_ns / 1e6);
      const ts = `${t.toISOString().slice(0, 10)} ${t.toISOString().slice(11, 23)}`;
      return `<article><header><b>${esc(m.transport.toLowerCase())}:${esc(m.src)}</b> to <b>${esc(m.dst)}</b> at ${ts} (${new TextEncoder().encode(m.raw).length} bytes)${m.retransmission ? ", retransmission" : ""}</header><pre class="sipmsg">${highlightSip(m.raw)}</pre></article>`;
    })
    .join("")}</div>`;
}

function showTab(name) {
  $$(".tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $$(".tab-body").forEach((p) => (p.hidden = p.id !== `tab-${name}`));
}

// ---------- AI ----------

const AI_DEFAULT_MODEL = { anthropic: "claude-sonnet-5-5", openai: "", ollama: "" };
// OpenAI-compatible services: [label, base URL, example model]
const AI_PRESETS = [
  ["OpenAI", "https://api.openai.com", "gpt-4o-mini"],
  ["OpenRouter", "https://openrouter.ai/api", "anthropic/claude-sonnet-5-5"],
  ["Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash"],
  ["Groq", "https://api.groq.com/openai", "llama-3.3-70b-versatile"],
  ["Mistral", "https://api.mistral.ai", "mistral-large-latest"],
  ["DeepSeek", "https://api.deepseek.com", "deepseek-chat"],
  ["LM Studio (local)", "http://localhost:1234", "local-model"],
  ["vLLM (local)", "http://localhost:8000", ""],
];
let aiSessionKey = null; // key typed but not remembered: lives until the page closes

function aiSettings() {
  const s = store.get("sidetone.ai", {});
  return {
    provider: s.provider || "anthropic",
    model: s.model || AI_DEFAULT_MODEL[s.provider || "anthropic"],
    base_url: s.base_url || null,
    language: s.language || { pt: "Portuguese (Brazil)", es: "Spanish", de: "German" }[currentLang()] || "English",
    redact: s.redact !== false,
    key: s.key || aiSessionKey || null,
    remember: !!s.key,
  };
}

function saveAiSettings(v) {
  aiSessionKey = v.key || null;
  store.set("sidetone.ai", {
    provider: v.provider,
    model: v.model,
    base_url: v.base_url || null,
    language: v.language,
    redact: v.redact,
    key: v.remember && v.key ? v.key : undefined,
  });
  renderAiUsing();
}

function aiConfig() {
  const s = aiSettings();
  return { provider: s.provider, model: s.model || AI_DEFAULT_MODEL[s.provider], base_url: s.base_url, api_key: s.key, language: s.language, max_tokens: 2000 };
}

const PROVIDER_NAME = { anthropic: "Anthropic", openai: "OpenAI-compatible", ollama: "Ollama" };

/// Problem with the AI settings, or null when ready.
function aiNotReady() {
  const c = aiConfig();
  if (!c.model) return t("Choose a model in Settings, AI.");
  if (c.provider !== "ollama" && !c.api_key && S.be.kind === "wasm") return t("Enter an API key in Settings, AI. It stays on this device and goes only to the provider.");
  return null;
}

function renderAiUsing() {
  const c = aiConfig();
  const host = c.base_url ? ` · ${c.base_url.replace(/^https?:\/\//, "").split("/")[0]}` : "";
  const txt = `${PROVIDER_NAME[c.provider]} · ${c.model || "?"}${host}`;
  const u = $("#ai-using");
  if (u) u.textContent = txt;
  const d = $("#dock-using");
  if (d) d.textContent = txt;
  const r = $("#ai-redact");
  if (r) r.checked = aiSettings().redact;
}

function renderAnswer(text) {
  const ls = esc(text).split("\n").map((l) => {
    const h = l.match(/^#{1,4}\s+(.*)$/);
    if (h) return `<h3>${h[1]}</h3>`;
    return l.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  });
  return `<div class="answer">${ls.join("\n")}</div>`;
}

async function askAI(preview) {
  if (!S.bytes) return;
  const cfg = aiConfig();
  const out = $("#ai-out");
  let question = $("#ai-question").value;
  if (S.webrtc) question = `${question}\n\nBrowser WebRTC getStats() summary for this call (media is not in the capture): ${JSON.stringify(S.webrtc)}`.trim();
  const { system, prompt } = await S.be.prompt(S.bytes, S.call, $("#ai-redact").checked, cfg.language, question);
  if (preview) {
    out.innerHTML = `<p class="muted">${$("#ai-redact").checked ? "Masked" : "Unmasked"} prompt, ${prompt.length.toLocaleString()} characters:</p><pre>${esc(system)}\n\n${esc(prompt)}</pre>`;
    return;
  }
  const bad = aiNotReady();
  if (bad) {
    out.innerHTML = `<p class="err">${esc(bad)} <button type="button" class="linklike" data-goto-ai>${esc(t("Open Settings, AI"))}</button></p>`;
    return;
  }
  const btn = $("#ai-go");
  btn.disabled = true;
  out.innerHTML = `<p class="muted">Asking ${esc(PROVIDER_NAME[cfg.provider])} (${esc(cfg.model)})…</p>`;
  try {
    out.innerHTML = renderAnswer(await S.be.ai(cfg, system, prompt));
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
  } finally {
    btn.disabled = false;
  }
}

// ---------- AI panel (conversation) ----------

const DOCK = { turns: [], busy: false, ctx: null };

/// What the AI can look at right now: [id, label, call-id or null].
function dockContexts() {
  const out = [];
  if (S.report) {
    const c = S.call != null ? S.report.calls[S.call] : null;
    out.push(["an", c ? `${t("Analysis")}: ${c.kind} ${c.from} → ${c.to}` : `${t("Analysis")}: ${S.name}`, null]);
  }
  const l = selLine() || lines()[lines().length - 1];
  if (l && l.call_id) out.push(["line", `${t("Phone")}: ${l.remote}`, l.call_id]);
  const tr = S.trace.find((x) => x.seq === S.trSel);
  if (tr && tr.call_id && (!l || tr.call_id !== l.call_id)) out.push(["trace", `${t("SIP trace")}: ${tr.first_line.slice(0, 40)}`, tr.call_id]);
  out.push(["live", t("Everything the phone captured"), null]);
  return out;
}

function renderDockContexts() {
  const ctxs = dockContexts();
  const sel = $("#dock-ctx");
  const want = DOCK.ctx && ctxs.some(([id]) => id === DOCK.ctx) ? DOCK.ctx : S.page === "analysis" && S.report ? "an" : ctxs[0][0];
  sel.innerHTML = ctxs.map(([id, label]) => `<option value="${id}">${esc(label)}</option>`).join("");
  sel.value = want;
  DOCK.ctx = want;
}

function openDock(open = true) {
  $("#ai-dock").hidden = !open;
  document.body.classList.toggle("dock-open", open);
  $("#ai-toggle").setAttribute("aria-expanded", String(open));
  if (open) {
    renderDockContexts();
    renderAiUsing();
    renderDockChat();
    $("#dock-q").focus();
  }
}

function renderDockChat() {
  const el = $("#dock-chat");
  if (!DOCK.turns.length) {
    el.innerHTML = `<div class="ai-empty"><p>${esc(t("Ask anything about the selected call or the capture. The AI gets the findings, the ladder, RTP statistics and the relevant SIP messages, masked by default."))}</p>
      <div class="ai-suggest">${[
        "Why did this call fail?",
        "Is there a NAT problem here?",
        "Why is there one-way audio?",
        "What should I change on the SBC or PBX?",
      ].map((q) => `<button type="button" class="chip" data-q="${esc(t(q))}">${esc(t(q))}</button>`).join("")}</div></div>`;
    return;
  }
  el.innerHTML = DOCK.turns
    .map((x) => (x.role === "user" ? `<div class="msg-u">${esc(x.text)}</div>` : x.role === "error" ? `<div class="msg-e">${esc(x.text)}</div>` : x.role === "pre" ? `<pre class="msg-p">${esc(x.text)}</pre>` : `<div class="msg-a">${renderAnswer(x.text)}</div>`))
    .join("") + (DOCK.busy ? `<div class="msg-a muted">${esc(t("Thinking…"))}</div>` : "");
  el.scrollTop = el.scrollHeight;
}

/// Capture bytes and dialog index for the chosen context.
async function dockSource() {
  const ctx = dockContexts().find(([id]) => id === DOCK.ctx) || ["live", "", null];
  if (ctx[0] === "an") return { bytes: S.bytes, call: S.call, webrtc: S.webrtc };
  const bytes = await S.ctl.capture(S.be);
  let call = null;
  if (ctx[2]) {
    const rep = await S.be.analyze(bytes);
    const i = rep.calls.findIndex((c) => c.call_id === ctx[2]);
    call = i >= 0 ? i : null;
  }
  return { bytes, call, webrtc: S.ctl.kind === "web" ? S.ctl.lastSummary : null };
}

async function dockAsk(question, preview = false) {
  question = question.trim();
  if (!question && !preview) return;
  const cfg = aiConfig();
  const redact = aiSettings().redact;
  // Earlier turns ride along so follow-up questions make sense.
  const history = DOCK.turns
    .filter((x) => x.role === "user" || x.role === "ai")
    .slice(-8)
    .map((x) => `${x.role === "user" ? "Question" : "Your answer"}: ${x.text.slice(0, 3000)}`)
    .join("\n\n");
  let q = history ? `Earlier in this conversation:\n\n${history}\n\nNew question: ${question}` : question;
  try {
    const src = await dockSource();
    if (src.webrtc) q += `\n\nBrowser WebRTC getStats() summary for this call (media is not in the capture): ${JSON.stringify(src.webrtc)}`;
    const { system, prompt } = await S.be.prompt(src.bytes, src.call, redact, cfg.language, q);
    if (preview) {
      DOCK.turns.push({ role: "pre", text: `${system}\n\n${prompt}` });
      renderDockChat();
      return;
    }
    const bad = aiNotReady();
    if (bad) {
      DOCK.turns.push({ role: "error", text: bad });
      renderDockChat();
      return;
    }
    DOCK.turns.push({ role: "user", text: question });
    DOCK.busy = true;
    renderDockChat();
    const answer = await S.be.ai(cfg, system, prompt);
    DOCK.turns.push({ role: "ai", text: answer });
  } catch (e) {
    DOCK.turns.push({ role: "error", text: e.message || String(e) });
  } finally {
    DOCK.busy = false;
    renderDockChat();
  }
}

function bindDock() {
  $("#ai-toggle").addEventListener("click", () => openDock($("#ai-dock").hidden));
  $("#dock-close").addEventListener("click", () => openDock(false));
  $("#dock-new").addEventListener("click", () => {
    DOCK.turns = [];
    renderDockChat();
  });
  $("#dock-ctx").addEventListener("change", (e) => {
    DOCK.ctx = e.target.value;
  });
  $("#dock-ctx").addEventListener("focus", () => {
    const keep = DOCK.ctx;
    renderDockContexts();
    if (keep) $("#dock-ctx").value = keep;
  });
  $("#dock-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("#dock-q").value;
    $("#dock-q").value = "";
    dockAsk(q);
  });
  $("#dock-q").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("#dock-form").requestSubmit();
    }
  });
  $("#dock-preview").addEventListener("click", () => dockAsk($("#dock-q").value || "(no question yet)", true));
  $("#dock-chat").addEventListener("click", (e) => {
    const c = e.target.closest("[data-q]");
    if (c) dockAsk(c.dataset.q);
  });
  $("#ai-to-dock").addEventListener("click", () => {
    DOCK.ctx = "an";
    openDock(true);
    const q = $("#ai-question").value.trim();
    if (q) {
      $("#ai-question").value = "";
      dockAsk(q);
    }
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-goto-ai]")) {
      SET.section = "ai";
      showWs("settings");
    }
  });
  $("#ai-redact").addEventListener("change", (e) => saveAiSettings({ ...aiSettings(), redact: e.target.checked, key: aiSettings().key, remember: aiSettings().remember }));
}

function bindAnalysis() {
  $("#file").addEventListener("change", (e) => e.target.files[0] && loadFile(e.target.files[0]));
  document.addEventListener("dragover", (e) => {
    e.preventDefault();
    document.body.classList.add("dragging");
  });
  document.addEventListener("dragleave", (e) => {
    if (e.target === document.documentElement || !e.relatedTarget) document.body.classList.remove("dragging");
  });
  document.addEventListener("drop", (e) => {
    e.preventDefault();
    document.body.classList.remove("dragging");
    const f = e.dataTransfer.files[0];
    if (f) loadFile(f);
  });
  $$(".menu > .btn").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      const m = b.parentElement;
      const open = !m.classList.contains("open");
      $$(".menu").forEach((x) => x.classList.remove("open"));
      m.classList.toggle("open", open);
    })
  );
  document.addEventListener("click", () => $$(".menu").forEach((x) => x.classList.remove("open")));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $$(".menu").forEach((x) => x.classList.remove("open"));
  });
  $("#calls").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-call]");
    if (b) selectCall(+b.dataset.call);
  });
  $("#ladder").addEventListener("click", (e) => {
    const g = e.target.closest(".msg");
    if (g) selectMessage(+g.dataset.msg);
    if (e.target.closest(".stream")) showTab("media");
  });
  const openFinding = (li) => {
    const f = S.report.findings[+li.dataset.finding];
    if (f.messages.length) selectMessage(f.messages[0]);
    else if (f.stream != null) showTab("media");
  };
  $("#tab-findings").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-finding]");
    if (li) openFinding(li);
  });
  $("#tab-findings").addEventListener("keydown", (e) => {
    const li = e.target.closest("li[data-finding]");
    if (li && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      openFinding(li);
    }
  });
  $$(".tabs [role=tab]").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  $$("[data-export]").forEach((b) =>
    b.addEventListener("click", async () => {
      const kind = b.dataset.export;
      const base = S.name.replace(/\.(pcapng|pcap|cap)$/i, "");
      try {
        if (kind === "json") return download(JSON.stringify(S.report, null, 2), `${base}-report.json`, "application/json");
        if (kind === "svg") return download(await S.be.ladder(S.bytes, S.call), `${base}-call${S.call ?? "s"}.svg`, "image/svg+xml");
        const opts = { annotate: true, redact: kind === "redacted", call: kind === "all" ? null : S.call, sip_only: false };
        const data = await S.be.exportPcap(S.bytes, opts);
        const suffix = kind === "all" ? "annotated" : kind === "redacted" ? `call${S.call}-redacted` : `call${S.call}`;
        await download(data, `${base}-${suffix}.pcapng`, "application/vnd.tcpdump.pcap");
        if (!S.be.save) toast(kind === "redacted" ? "Exported with numbers, names, credentials and public IPs masked" : "Exported with findings as packet comments");
      } catch (e) {
        toast(`Export failed: ${e.message || e}`, 5000);
      }
    })
  );
  $("#ai-form").addEventListener("submit", (e) => {
    e.preventDefault();
    askAI(false);
  });
  $("#ai-preview").addEventListener("click", () => askAI(true));
}

// ============================================================================
// Diagnostics

function diagAccounts() {
  const opts = (S.st ? S.st.accounts : []).map((a) => `<option value="${esc(a.id)}">${esc(accLabel(a))}</option>`).join("");
  const sel = $("#dg-opt-acct");
  const keep = sel.value || $("#acct").value;
  sel.innerHTML = opts;
  if (keep) sel.value = keep;
}

function table(head, rows) {
  return `<table class="mini"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

let audioPoll = null;
async function diagOpen() {
  diagAccounts();
  if (S.ctl.kind === "native") (SN.loaded ? sniffPoll() : sniffLoad());
  const a = currentAccount();
  if (a && !$("#dg-dns-host").value) $("#dg-dns-host").value = (a.domain || "").replace(/:\d+$/, "");
  const nat = (S.st ? S.st.accounts : []).filter((x) => x.public);
  $("#dg-reg-nat").innerHTML = nat.length
    ? `<h3>What the SIP server sees</h3>${table(["Account", "Local", "Seen as", ""], nat.map((x) => [esc(accLabel(x)), `<span class="mono">${esc(x.local)}</span>`, `<span class="mono">${esc(x.public)}</span>`, x.public !== x.local ? `<span class="warn">NAT between you and the server</span>` : "same address, no NAT"]))}<p class="hint">From the received and rport parameters of the server's response to REGISTER.</p>`
    : "";
  if (S.ctl.kind === "native") {
    try {
      const d = await S.ctl.audio();
      const dev = d.devices;
      const st = d.audio;
      const prefs = st.prefs || {};
      const opt = (list, cur) => [`<option value="">System default</option>`, ...list.map((n) => `<option ${n === cur ? "selected" : ""}>${esc(n)}</option>`)].join("");
      $("#dg-audio").innerHTML = `
        <p class="muted">${st.status ? `Open: microphone <b>${esc(st.status.input || "none")}</b>${st.status.input_rate ? ` at ${st.status.input_rate} Hz` : ""}, speaker <b>${esc(st.status.output || "none")}</b>${st.status.output_rate ? ` at ${st.status.output_rate} Hz` : ""}.` : esc(st.error || dev.error || "No sound card is open. Calls send a test tone instead.")}</p>
        <div class="row">
          <label class="grow">Microphone <select id="dg-in">${opt(dev.inputs || [], prefs.input)}</select></label>
          <label class="grow">Speaker <select id="dg-out">${opt(dev.outputs || [], prefs.output)}</select></label>
          <button type="button" class="btn" id="dg-audio-apply">Use these</button>
        </div>
        <div class="meters">
          <div class="meter-row"><svg><use href="#i-mic"/></svg><div class="meter"><i id="dg-m-in"></i></div></div>
          <div class="meter-row"><svg><use href="#i-spk"/></svg><div class="meter"><i id="dg-m-out"></i></div></div>
        </div>
        <label class="check"><input type="checkbox" id="dg-loop"> Play the microphone on the speaker (use headphones)</label>
        <p class="hint">Audio host: ${esc(dev.host || "")}. Calls use the sound card when Settings, Audio, Send is set to Sound card.</p>`;
      $("#dg-audio-apply").addEventListener("click", async () => {
        const c = await S.ctl.getConfig();
        c.audio = { ...(c.audio || {}), enabled: true, input: $("#dg-in").value || null, output: $("#dg-out").value || null };
        await S.ctl.setConfig({ audio: c.audio });
        toast("Audio devices changed");
        diagOpen();
      });
      $("#dg-loop").addEventListener("change", async (e) => {
        try {
          await S.ctl.loopback(e.target.checked);
        } catch (err) {
          toast(err.message || String(err), 4000);
          e.target.checked = false;
        }
      });
      clearInterval(audioPoll);
      audioPoll = setInterval(async () => {
        if (S.page !== "diag") {
          clearInterval(audioPoll);
          S.ctl.loopback(false).catch(() => {});
          return;
        }
        try {
          const s = await S.ctl.audioStatus();
          if (s.status) {
            setMeter($("#dg-m-in"), levelPct(s.status.mic_level));
            setMeter($("#dg-m-out"), levelPct(s.status.speaker_level));
          }
        } catch { /* ignore */ }
      }, 200);
    } catch (e) {
      $("#dg-audio").innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
    }
  } else {
    $("#dg-audio").innerHTML = `<p class="muted">The browser phone uses the microphone and speaker chosen in the browser. Test the microphone level here:</p>
      <div class="meters"><div class="meter-row"><svg><use href="#i-mic"/></svg><div class="meter"><i id="dg-m-in"></i></div></div></div>
      <button type="button" class="btn" id="dg-mic">Test microphone</button>`;
    $("#dg-mic").addEventListener("click", async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const ac = new AudioContext();
        const an = ac.createAnalyser();
        ac.createMediaStreamSource(stream).connect(an);
        const buf = new Float32Array(an.fftSize);
        const t = setInterval(() => {
          an.getFloatTimeDomainData(buf);
          const peak = Math.max(...buf.map(Math.abs));
          setMeter($("#dg-m-in"), levelPct(peak * 32767));
        }, 100);
        setTimeout(() => {
          clearInterval(t);
          stream.getTracks().forEach((x) => x.stop());
          ac.close();
          setMeter($("#dg-m-in"), 0);
        }, 10000);
      } catch (e) {
        toast(`Microphone: ${e.message || e}`, 4000);
      }
    });
  }
}

// ---- passive capture on an interface (native only)

const SN = { seen: 0, rows: [], timer: null, loaded: false, running: false };

async function sniffLoad() {
  if (S.ctl.kind !== "native" || !S.ctl.sniffInterfaces) return;
  const sel = $("#sn-if");
  try {
    const r = await S.ctl.sniffInterfaces();
    if (r.error) {
      sel.innerHTML = "";
      $("#sn-err").innerHTML = `<p class="bad">${esc(r.error)}</p>`;
      $("#sn-go").disabled = true;
      return;
    }
    const cur = sel.value || store.get("sidetone.sniff.if", "");
    const list = r.interfaces.filter((i) => i.up || i.addresses.length);
    sel.innerHTML = list
      .map((i) => `<option value="${esc(i.name)}" ${i.name === cur ? "selected" : ""}>${esc(i.description && !/^\\Device/.test(i.description) ? `${i.description} (${i.name})` : i.name)}${i.addresses.length ? ` · ${esc(i.addresses.join(", "))}` : ""}</option>`)
      .join("");
    $("#sn-go").disabled = false;
    $("#sn-err").innerHTML = "";
    SN.loaded = true;
    $("#sn-status").textContent = r.library || "";
  } catch (e) {
    $("#sn-err").innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
  }
  sniffPoll();
}

function sniffRender(st) {
  SN.running = !!st.running;
  $("#sn-go").textContent = t(SN.running ? "Stop" : "Start");
  $("#sn-go").classList.toggle("danger", SN.running);
  $("#sn-analyze").disabled = !st.kept;
  $("#sn-save").disabled = !st.kept;
  if (st.iface) {
    const parts = [`${SN.running ? t("Capturing on") : t("Captured on")} ${st.iface}`, `${st.packets.toLocaleString()} ${t("packets")}`, `${st.sip.toLocaleString()} SIP`, `${st.rtp.toLocaleString()} RTP`];
    $("#sn-status").textContent = parts.join(" · ");
  }
  if (st.error) $("#sn-err").innerHTML = `<p class="warn">${esc(st.error)}</p>`;
  $("#sn-list").innerHTML = SN.rows.length
    ? table(
        [t("Time"), t("From"), t("To"), t("Message")],
        SN.rows
          .slice(-200)
          .reverse()
          .map((m) => [`<span class="mono">${clock(m.ts_ms, true)}</span>`, `<span class="mono">${esc(m.transport.toLowerCase())}:${esc(m.src)}</span>`, `<span class="mono">${esc(m.dst)}</span>`, `<span class="mono ${m.status >= 400 ? "bad" : m.status >= 200 ? "ok" : ""}">${esc(m.first_line)}</span>`])
      )
    : "";
}

async function sniffPoll() {
  clearTimeout(SN.timer);
  if (S.ctl.kind !== "native" || !S.ctl.sniffStatus) return;
  try {
    const r = await S.ctl.sniffStatus(SN.seen);
    for (const m of r.sip) SN.seen = Math.max(SN.seen, m.seq);
    SN.rows.push(...r.sip);
    if (SN.rows.length > 1000) SN.rows.splice(0, SN.rows.length - 1000);
    sniffRender(r.status);
    if (r.status.running && S.page === "diag") SN.timer = setTimeout(sniffPoll, 1000);
  } catch {
    /* server gone; the next page open retries */
  }
}

async function sniffToggle() {
  $("#sn-err").innerHTML = "";
  try {
    if (SN.running) {
      await S.ctl.sniffStop();
    } else {
      const iface = $("#sn-if").value;
      store.set("sidetone.sniff.if", iface);
      SN.rows = [];
      SN.seen = 0;
      await S.ctl.sniffStart(iface, $("#sn-filter").value);
    }
  } catch (e) {
    $("#sn-err").innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
  }
  sniffPoll();
}

function bindDiag() {
  $("#sn-go").addEventListener("click", sniffToggle);
  $("#sn-analyze").addEventListener("click", async () => {
    const b = await S.ctl.sniffPcap();
    await load(b, `sidetone-interface-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`);
    showWs("analysis");
  });
  $("#sn-save").addEventListener("click", async () => {
    const b = await S.ctl.sniffPcap();
    download(b, `sidetone-interface-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, "application/vnd.tcpdump.pcap");
  });
  $("#dg-opt-go").addEventListener("click", async () => {
    const out = $("#dg-opt-out");
    out.innerHTML = `<p class="muted">Waiting for a response (up to 32 s)…</p>`;
    try {
      const r = await S.ctl.options($("#dg-opt-acct").value || null, $("#dg-opt-target").value.trim());
      out.innerHTML = r && r.code ? `<p class="${r.code < 300 || r.code === 404 || r.code === 405 ? "ok" : "warn"}"><b>${esc(r.summary)}</b></p>` : `<p class="bad"><b>No response.</b> ${esc((r && r.summary) || "")}</p>`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-dns-go").addEventListener("click", async () => {
    const host = $("#dg-dns-host").value.trim();
    if (!host) return;
    const out = $("#dg-dns-out");
    out.innerHTML = `<p class="muted">Looking up ${esc(host)}…</p>`;
    try {
      const r = await S.ctl.dns(host);
      out.innerHTML = `
        ${r.chosen ? `<p class="ok"><b>UDP requests go to ${esc(r.chosen)}</b></p>` : `<p class="bad"><b>No usable address.</b></p>`}
        ${r.naptr.length ? `<h3>NAPTR</h3>${table(["Order", "Pref", "Flags", "Service", "Replacement"], r.naptr.map((n) => [n.order, n.preference, esc(n.flags), esc(n.service), `<span class="mono">${esc(n.replacement)}</span>`]))}` : ""}
        ${r.srv.length ? `<h3>SRV</h3>${table(["Name", "Prio", "Weight", "Port", "Target", "Addresses"], r.srv.map((s) => [`<span class="mono">${esc(s.name)}</span>`, s.priority, s.weight, s.port, `<span class="mono">${esc(s.target)}</span>`, `<span class="mono">${esc(s.addresses.join(", "))}</span>`]))}` : ""}
        <h3>Steps</h3><ol class="steps">${r.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        <p class="hint">${r.elapsed_ms} ms</p>`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-dns-host").addEventListener("keydown", (e) => e.key === "Enter" && $("#dg-dns-go").click());
  $("#dg-stun-go").addEventListener("click", async () => {
    const servers = $("#dg-stun-servers").value.split(/[,\s]+/).filter(Boolean);
    const out = $("#dg-stun-out");
    out.innerHTML = `<p class="muted">Asking ${servers.length} server${servers.length > 1 ? "s" : ""}…</p>`;
    try {
      const r = await S.ctl.stun(servers);
      out.innerHTML = `<p><b>${esc(r.nat)}</b></p>${table(["Server", "Seen as", "Round trip", ""], r.probes.map((p) => [`<span class="mono">${esc(p.server)}</span>`, `<span class="mono">${esc(p.mapped || "")}</span>`, p.rtt_ms != null ? `${p.rtt_ms} ms` : "", esc(p.error || "")]))}${r.local ? `<p class="hint">Local socket ${esc(r.local)}</p>` : ""}`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
}

// ============================================================================
// Settings

const get = (o, path) => path.split(".").reduce((x, k) => (x == null ? x : x[k]), o);
function set(o, path, v) {
  const ks = path.split(".");
  let x = o;
  for (const k of ks.slice(0, -1)) x = x[k] ??= {};
  x[ks[ks.length - 1]] = v;
}

// Field: [path, label, type, hint, extra]
const NATIVE_ACC_TABS = [
  ["Account", [
    ["label", "Name in the phone", "text", "e.g. Genesys lab 2001"],
    ["enabled", "Enabled", "bool"],
    ["profile.account.user", "User (extension or number)", "text"],
    ["profile.account.display_name", "Display name", "opt"],
    ["profile.account.auth_user", "Authentication user", "opt", "only when it differs from the user"],
    ["profile.account.password", "Password", "password"],
    ["profile.account.domain", "Domain or registrar", "text", "host or host:port. Without a port, DNS SRV (_sip._udp) is tried first. Leave it empty with Register off for an anonymous client that dials SIP URIs directly."],
  ]],
  ["Server and registration", [
    ["register", "Register", "bool", "turn off for trunks, peer-to-peer tests, call-only use or direct SIP URI dialing"],
    ["profile.account.outbound_proxy", "Outbound proxy", "opt", "host:port. Every request goes here, whatever the destination."],
    ["profile.account.expires", "Registration expiry (s)", "number"],
    ["retry_s", "Retry a failed registration after (s)", "number"],
    ["profile.account.q_value", "Contact q-value", "opt"],
    ["profile.behavior.keepalive_interval", "CRLF keepalive every (s)", "number", "0 = off. Keeps NAT bindings open."],
    ["profile.behavior.filter_registrar", "Accept requests only from the registrar", "bool"],
  ]],
  ["Network", [
    ["profile.behavior.transport", "SIP transport", "select", "TCP and TLS keep one connection to the server; with TLS and no port, 5061 and DNS _sips._tcp are used", [["udp", "UDP"], ["tcp", "TCP"], ["tls", "TLS"]]],
    ["profile.behavior.tls_verify", "Check the server's TLS certificate", "bool", "turn off for labs and PBXs with self-signed certificates"],
    ["profile.behavior.local_ip", "Local IP", "opt", "empty = the interface the OS routes to the server"],
    ["profile.behavior.local_port", "Local SIP port", "number", "0 = random. Use 5060 to look like a desk phone."],
    ["profile.behavior.rport", "Request rport (RFC 3581)", "bool"],
    ["profile.behavior.symmetric_rtp", "Symmetric RTP (send audio back where it comes from)", "bool"],
    ["profile.behavior.rtp_port_start", "RTP ports from", "number"],
    ["profile.behavior.rtp_port_end", "RTP ports to", "number"],
    ["profile.behavior.dscp_sip", "DSCP for SIP", "number", "24 = CS3, 26 = AF31"],
    ["profile.behavior.dscp_rtp", "DSCP for RTP", "number", "46 = EF"],
    ["profile.behavior.sdp_ip_override", "Address in SDP", "opt", "advertise another address, e.g. to reproduce one-way audio behind NAT"],
    ["profile.behavior.t1_ms", "Timer T1 (ms)", "number", "RFC 3261 retransmission base, 500 by default"],
  ]],
  ["Media", [
    ["profile.behavior.codecs", "Codecs, in order of preference", "codecs"],
    ["profile.behavior.srtp", "Media encryption (SRTP)", "select", "Optional offers SRTP and accepts plain RTP; Required hangs up or rejects calls without it.", [["off", "Off (RTP)"], ["optional", "Optional"], ["mandatory", "Required"]]],
    ["profile.behavior.srtp_keys", "SRTP keys", "select", "SDES puts the keys in the SDP (a=crypto): use it with TLS. DTLS-SRTP negotiates them on the media path and checks the far end's certificate against a=fingerprint.", [["sdes", "SDES (a=crypto)"], ["dtls", "DTLS-SRTP (a=fingerprint)"]]],
    ["profile.behavior.ptime_ms", "Packet time (ms)", "select", "", [["10", "10"], ["20", "20"], ["30", "30"], ["40", "40"], ["60", "60"]]],
    ["profile.behavior.sdp_direction", "Direction offered", "select", "", [["sendrecv", "sendrecv"], ["sendonly", "sendonly"], ["recvonly", "recvonly"], ["inactive", "inactive"]]],
  ]],
  ["DTMF", [
    ["profile.behavior.dtmf_mode", "Send DTMF as", "select", "", [["rfc4733", "RTP events (RFC 4733)"], ["info", "SIP INFO (dtmf-relay)"], ["inband", "Tones in the audio"]]],
    ["profile.behavior.dtmf_payload_type", "telephone-event payload type", "number"],
  ]],
  ["Advanced SIP", [
    ["profile.behavior.user_agent", "User-Agent", "text"],
    ["profile.behavior.max_forwards", "Max-Forwards", "number"],
    ["profile.behavior.session_timer", "Session timer (s)", "number", "0 = off; otherwise Session-Expires is requested and refreshed with UPDATE"],
    ["profile.behavior.user_phone", "Add user=phone to numeric destinations", "bool"],
    ["profile.behavior.compact_headers", "Compact header names (v, f, t, i, m, l)", "bool"],
    ["profile.behavior.require_prack", "Require reliable provisional responses (100rel)", "bool"],
    ["profile.behavior.offer_gruu", "Advertise GRUU", "bool"],
    ["profile.behavior.long_contact", "Long Contact (+sip.instance, feature tags)", "bool"],
    ["profile.behavior.proxy_require", "Proxy-Require", "opt"],
    ["profile.behavior.skip_ack", "Do not send ACK for 2xx (reproduces the 32 s drop)", "bool", "testing only"],
  ]],
  ["Headers", [["profile.behavior.extra_headers", "Headers added to every request", "headers"]]],
  ["BLF", [["blf", "Extensions to watch (busy lamp field)", "lines", "one per line: an extension, user@host or SIP URI. Sidetone subscribes to the dialog event package (RFC 4235) for the lamp and to presence (RFC 3856, PIDF) when the server offers it, once the account is registered; the PBX needs hints for them."]]],
];

const WEB_ACC_TABS = [
  ["Account", [
    ["label", "Name in the phone", "text"],
    ["enabled", "Enabled", "bool"],
    ["user", "User (extension or number)", "text"],
    ["displayName", "Display name", "text"],
    ["authUser", "Authentication user", "text", "only when it differs from the user"],
    ["password", "Password", "password"],
    ["rememberPassword", "Remember the password in this browser", "bool"],
    ["domain", "SIP domain", "text"],
  ]],
  ["Server and registration", [
    ["ws", "WebSocket URL", "text", "wss://pbx.example.com:8089/ws. Pages served over https need wss with a trusted certificate."],
    ["register", "Register", "bool"],
    ["expires", "Registration expiry (s)", "number"],
  ]],
  ["Network", [["ice", "STUN or TURN servers", "text", "comma separated, e.g. stun:stun.l.google.com:19302"]]],
];

const CALL_SETTINGS = [
  ["dnd", "Do not disturb", "bool"],
  ["dnd_code", "Reject calls in DND with", "select", "", [["486", "486 Busy Here"], ["480", "480 Temporarily Unavailable"], ["603", "603 Decline"]], "native"],
  ["auto_answer", "Auto answer", "bool"],
  ["auto_answer_delay_ms", "Auto answer after (ms)", "number"],
  ["intercom", "Answer intercom calls at once (Call-Info answer-after, Alert-Info)", "bool", "", null, "native"],
  ["max_lines", "Lines", "number"],
  ["auto_hold", "Put the other calls on hold when you answer or resume one", "bool"],
  ["busy_code", "When all lines are busy, reject with", "select", "", [["486", "486 Busy Here"], ["480", "480 Temporarily Unavailable"], ["503", "503 Service Unavailable"]], "native"],
  ["ring_timeout_s", "Cancel unanswered outgoing calls after (s)", "number", "", null, "native"],
];

function fieldHtml(f, value, id) {
  const [, label, type, hint = "", opts] = f;
  const h = hint ? `<span class="hint">${esc(hint)}</span>` : "";
  switch (type) {
    case "bool":
      return `<label class="check fld"><input type="checkbox" id="${id}" ${value ? "checked" : ""}> ${esc(label)} ${h}</label>`;
    case "number":
      return `<label class="fld">${esc(label)} ${h}<input type="number" id="${id}" value="${esc(value ?? "")}"></label>`;
    case "password":
      return `<label class="fld">${esc(label)} ${h}<input type="password" id="${id}" value="${esc(value ?? "")}" autocomplete="new-password"></label>`;
    case "select":
      return `<label class="fld">${esc(label)} ${h}<select id="${id}">${opts.map(([v, t]) => `<option value="${esc(v)}" ${String(value) === v ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>`;
    case "codecs": {
      const all = ["PCMU", "PCMA", "opus"];
      const CODEC_NAMES = { PCMU: "PCMU (G.711 μ-law)", PCMA: "PCMA (G.711 A-law)", opus: "Opus" };
      const cur = (value || []).filter((c) => all.includes(c));
      const order = [...cur, ...all.filter((c) => !cur.includes(c))];
      return `<div class="fld"><span>${esc(label)}</span><ol class="codecs" id="${id}">${order
        .map((c) => `<li data-codec="${c}"><label class="check"><input type="checkbox" ${cur.includes(c) ? "checked" : ""}> ${CODEC_NAMES[c]}</label><button type="button" class="linklike" data-up>Up</button></li>`)
        .join("")}</ol><span class="hint">Opus carries wideband audio (16 kHz, up to 7 kHz of voice) on a 48 kHz RTP clock, with in-band FEC. G.711 is converted to and from 8 kHz.</span></div>`;
    }
    case "lines":
      return `<label class="fld">${esc(label)} ${h}<textarea id="${id}" rows="6" spellcheck="false">${esc((value || []).join("\n"))}</textarea></label>`;
    case "headers": {
      const rows = (value || []).map(([k, v]) => `<div class="hdr-row"><input placeholder="Name" value="${esc(k)}"><input placeholder="Value" value="${esc(v)}"><button type="button" class="linklike" data-del>Remove</button></div>`).join("");
      return `<div class="fld"><span>${esc(label)}</span><div class="hdrs" id="${id}">${rows}</div><button type="button" class="btn small" data-addhdr="${id}">Add header</button></div>`;
    }
    case "opt":
    default:
      return `<label class="fld">${esc(label)} ${h}<input id="${id}" value="${esc(value ?? "")}" spellcheck="false"></label>`;
  }
}

function readField(f, id, obj) {
  const [path, , type] = f;
  const el = document.getElementById(id);
  if (!el) return;
  let v;
  switch (type) {
    case "bool": v = el.checked; break;
    case "number": v = el.value === "" ? 0 : Number(el.value); break;
    case "select": v = /^\d+$/.test(el.value) && typeof get(obj, path) === "number" ? Number(el.value) : el.value; break;
    case "lines": v = el.value.split("\n").map((x) => x.trim()).filter(Boolean); break;
    case "codecs": v = [...el.querySelectorAll("li")].filter((li) => li.querySelector("input").checked).map((li) => li.dataset.codec); break;
    case "headers": v = [...el.querySelectorAll(".hdr-row")].map((r) => [r.children[0].value.trim(), r.children[1].value.trim()]).filter(([k]) => k); break;
    case "opt": v = el.value.trim() || null; break;
    default: v = el.value;
  }
  set(obj, path, v);
}

const SET = { cfg: null, accId: null, accTab: 0, section: null, dirty: false };

function provisionUrlDisplay(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    return String(url).replace(/^(?<sch>[\w+.-]+:\/\/)(?<auth>[^@/]+@)/u, "$1");
  }
}

function applyNativeProvision(acc, p, url, tlsVerify) {
  const keepName = acc.profile?.name ?? "";
  const prevUa = acc.profile?.behavior?.user_agent;
  acc.label = p.label;
  acc.enabled = p.enabled;
  acc.register = p.register;
  if (p.retry_s != null) acc.retry_s = p.retry_s;
  if (p.blf) acc.blf = p.blf;
  if (!acc.profile) acc.profile = { name: keepName, account: {}, behavior: {} };
  acc.profile.name = keepName;
  Object.assign(acc.profile.account, p.profile.account);
  const beh = p.profile?.behavior || {};
  acc.profile.behavior = { ...(acc.profile.behavior || {}), ...beh };
  if (Object.prototype.hasOwnProperty.call(beh, "user_agent") && beh.user_agent === null) {
    acc.profile.behavior.user_agent = prevUa;
  }
  acc.provision_url = url;
  acc.provision_tls_verify = tlsVerify !== false;
}

function applyWebProvision(acc, p, url) {
  acc.label = p.label;
  acc.enabled = p.enabled;
  acc.register = p.register;
  acc.user = p.user;
  acc.authUser = p.authUser || "";
  acc.password = p.password || "";
  acc.displayName = p.displayName;
  acc.domain = p.domain;
  acc.ws = p.ws;
  acc.ice = p.ice || "";
  acc.expires = p.expires;
  acc.rememberPassword = !!p.rememberPassword;
  acc.provisionUrl = url;
}

function openProvisionDialog() {
  const dlg = $("#prov-dialog");
  const native = S.ctl.kind === "native";
  const acc = SET.cfg?.accounts.find((a) => a.id === SET.accId);
  $("#prov-title").textContent = t("Fetch provisioning");
  $("#prov-url-label").textContent = t("Provisioning URL");
  $("#prov-tls-label").textContent = t("Check the server's TLS certificate");
  $("#prov-fetch").textContent = t("Fetch");
  $("#prov-cancel").textContent = t("Cancel");
  $("#prov-err").hidden = true;
  $("#prov-err").textContent = "";
  $("#prov-tls-wrap").hidden = S.ctl.kind === "web";
  $("#prov-url").value = acc ? (native ? acc.provision_url || "" : acc.provisionUrl || "") : "";
  $("#prov-tls").checked = acc?.provision_tls_verify !== false;
  dlg.showModal();
}

async function runProvisionFetch() {
  const url = $("#prov-url").value.trim();
  if (!url) return;
  const errEl = $("#prov-err");
  errEl.hidden = true;
  const native = S.ctl.kind === "native";
  try {
    const parsed = await S.ctl.provision(url, $("#prov-tls").checked);
    const acc = SET.cfg.accounts.find((a) => a.id === SET.accId);
    if (!acc) return;
    if (native) applyNativeProvision(acc, parsed, url, $("#prov-tls").checked);
    else applyWebProvision(acc, parsed, url);
    if (!native && parsed.password) S.ctl.passwords[acc.id] = parsed.password;
    SET.dirty = true;
    $("#prov-dialog").close();
    renderSetBody();
    toast(t("Provisioning loaded. Save to keep it."));
  } catch (e) {
    errEl.textContent = e.message || String(e);
    errEl.hidden = false;
  }
}

async function settingsOpen() {
  SET.dirty = false;
  try {
    SET.cfg = await S.ctl.getConfig();
  } catch (e) {
    $("#set-body").innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
    return;
  }
  if (!SET.accId && !SET.section) SET.accId = SET.cfg.accounts.length ? SET.cfg.accounts[0].id : null;
  if (!SET.accId && !SET.section) SET.section = SET.cfg.accounts.length ? null : "new";
  renderSetNav();
  renderSetBody();
}

function renderSetNav() {
  $("#acc-list").innerHTML = SET.cfg.accounts
    .map((a) => {
      const live = S.st && S.st.accounts.find((x) => x.id === a.id);
      const name = a.label || (S.ctl.kind === "web" ? a.user : a.profile.account.user) || "Unnamed";
      return `<li><button type="button" data-acc="${esc(a.id)}" aria-current="${a.id === SET.accId && !SET.section}"><span class="dot ${regClass(live)}"></span>${esc(name)}</button></li>`;
    })
    .join("") || `<li class="muted small pad">No accounts</li>`;
  $$(".set-nav [data-set]").forEach((b) => b.setAttribute("aria-current", String(b.dataset.set === SET.section)));
}

function newNativeAccount() {
  const n = SET.cfg.accounts.length + 1;
  let id = String(n);
  while (SET.cfg.accounts.some((a) => a.id === id)) id = String(+id + 1);
  return { id, label: "", enabled: true, register: true, retry_s: 30, provision_url: null, provision_tls_verify: true, profile: { name: "", account: { user: "", auth_user: null, password: null, domain: "", display_name: null, outbound_proxy: null, expires: 300, q_value: null }, behavior: null } };
}

function markSetDirty() {
  SET.dirty = true;
  const d = $("#acc-dirty");
  if (d) d.textContent = t("Unsaved changes");
}

async function renderSetBody() {
  const body = $("#set-body");
  const native = S.ctl.kind === "native";
  if (SET.section === "new" || (!SET.section && !SET.accId)) {
    body.innerHTML = `<div class="set-empty"><h1>${esc(t("Add your first account"))}</h1><p class="muted">${esc(native ? t("Sidetone registers over UDP from this computer, like a desk phone. You need the server address, the extension and its password.") : t("In the browser Sidetone talks SIP over WebSocket (RFC 7118) with WebRTC audio. Your PBX needs a WSS listener, for example Asterisk on port 8089 or a Genesys/Ribbon SBC with WebRTC enabled."))}</p><div class="row"><button type="button" class="btn primary" id="acc-first">${esc(t("Add account"))}</button><button type="button" class="btn" id="acc-first-prov">${esc(t("Provision"))}</button></div></div>`;
    $("#acc-first").addEventListener("click", addAccount);
    $("#acc-first-prov").addEventListener("click", async () => {
      await addAccount();
      openProvisionDialog();
    });
    return;
  }
  if (SET.section) return renderGlobal(SET.section);
  const acc = SET.cfg.accounts.find((a) => a.id === SET.accId);
  if (!acc) {
    SET.accId = null;
    return renderSetBody();
  }
  // Fill behavior defaults so every field shows a value.
  if (native && !acc.profile.behavior) acc.profile.behavior = (await defaultBehavior()) || {};
  const tabs = native ? NATIVE_ACC_TABS : WEB_ACC_TABS;
  const tab = Math.min(SET.accTab, tabs.length - 1);
  const [, fields] = tabs[tab];
  body.innerHTML = `
    <div class="set-head">
      <h1>${esc(acc.label || (native ? acc.profile.account.user : acc.user) || "New account")}</h1>
      <div class="row"><button type="button" class="btn small" id="acc-prov">${esc(t("Provision"))}</button><button type="button" class="btn small" id="acc-dup">${esc(t("Duplicate"))}</button><button type="button" class="btn small danger" id="acc-del">${esc(t("Delete"))}</button></div>
    </div>
    <div class="seg" role="tablist">${tabs.map(([n], i) => `<button type="button" role="tab" data-acctab="${i}" aria-selected="${i === tab}">${esc(n)}</button>`).join("")}</div>
    <form class="set-form" id="acc-form" autocomplete="off">
      <div class="fields">${tab === 0 ? `<div class="fld"><span>${esc(t("Provisioning URL"))}</span><input readonly class="readonly" value="${esc(provisionUrlDisplay(native ? acc.provision_url : acc.provisionUrl))}"></div>` : ""}${fields.map((f, i) => fieldHtml(f, get(acc, f[0]), `af-${i}`)).join("")}</div>
      ${native && tabs[tab][0] === "Advanced SIP" ? `<h3>What an INVITE from this account looks like</h3><pre class="sipmsg preview" id="inv-preview"></pre>` : ""}
      <div class="set-actions"><span class="hint" id="acc-dirty"></span><button type="submit" class="btn primary">Save account</button></div>
    </form>`;
  const form = $("#acc-form");
  const collect = () => fields.forEach((f, i) => readField(f, `af-${i}`, acc));
  const preview = () => {
    const p = $("#inv-preview");
    if (p) {
      collect();
      p.innerHTML = highlightSip(invitePreview(acc));
    }
  };
  preview();
  if (SET.dirty) markSetDirty();
  form.addEventListener("input", () => {
    markSetDirty();
    preview();
  });
  form.addEventListener("click", (e) => {
    const up = e.target.closest("[data-up]");
    if (up) {
      const li = up.closest("li");
      if (li.previousElementSibling) li.parentElement.insertBefore(li, li.previousElementSibling);
      markSetDirty();
      preview();
    }
    const del = e.target.closest("[data-del]");
    if (del) {
      del.closest(".hdr-row").remove();
      markSetDirty();
    }
    const add = e.target.closest("[data-addhdr]");
    if (add) {
      $("#" + add.dataset.addhdr).insertAdjacentHTML("beforeend", `<div class="hdr-row"><input placeholder="Name"><input placeholder="Value"><button type="button" class="linklike" data-del>Remove</button></div>`);
      markSetDirty();
    }
  });
  $$("[data-acctab]").forEach((b) =>
    b.addEventListener("click", () => {
      collect();
      SET.accTab = +b.dataset.acctab;
      renderSetBody();
    })
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    collect();
    await saveAccounts();
  });
  $("#acc-del").addEventListener("click", async () => {
    SET.cfg.accounts = SET.cfg.accounts.filter((a) => a.id !== acc.id);
    SET.accId = SET.cfg.accounts.length ? SET.cfg.accounts[0].id : null;
    await saveAccounts();
  });
  $("#acc-prov").addEventListener("click", () => openProvisionDialog());
  $("#acc-dup").addEventListener("click", () => {
    collect();
    const copy = JSON.parse(JSON.stringify(acc));
    copy.id = native ? newNativeAccount().id : webAccountDefaults().id;
    copy.label = `${acc.label || "Account"} copy`;
    SET.cfg.accounts.push(copy);
    SET.accId = copy.id;
    renderSetNav();
    renderSetBody();
    toast("Copied. Save to keep it.");
  });
}

let behaviorDefaults = null;
async function defaultBehavior() {
  if (behaviorDefaults) return JSON.parse(JSON.stringify(behaviorDefaults));
  // The engine fills defaults for a missing behavior; save then read back gives them.
  behaviorDefaults = {
    transport: "udp", tls_verify: true, local_port: 0, local_ip: null, t1_ms: 500, max_forwards: 70, session_timer: 0, user_phone: false, compact_headers: false, require_prack: false,
    offer_gruu: false, long_contact: false, rport: true, codecs: ["PCMU", "PCMA"], ptime_ms: 20, dtmf_mode: "rfc4733", dtmf_payload_type: 101, srtp: "off", srtp_keys: "sdes",
    symmetric_rtp: true, rtcp: false, rtp_port_start: 40000, rtp_port_end: 49999, dscp_sip: 0, dscp_rtp: 0, keepalive_interval: 0, user_agent: `Sidetone/${S.version || ""}`,
    proxy_require: null, filter_registrar: false, extra_headers: [], sdp_direction: "sendrecv", skip_ack: false, sdp_ip_override: null,
  };
  return JSON.parse(JSON.stringify(behaviorDefaults));
}

async function addAccount() {
  const native = S.ctl.kind === "native";
  const a = native ? newNativeAccount() : webAccountDefaults();
  if (native) a.profile.behavior = await defaultBehavior();
  SET.cfg.accounts.push(a);
  SET.accId = a.id;
  SET.section = null;
  SET.accTab = 0;
  renderSetNav();
  renderSetBody();
}

async function saveAccounts() {
  try {
    await S.ctl.setConfig({ accounts: SET.cfg.accounts });
    toast("Saved. Registering…");
    const d = $("#acc-dirty");
    if (d) d.textContent = "";
    SET.dirty = false;
    SET.cfg = await S.ctl.getConfig();
    renderSetNav();
    renderSetBody();
  } catch (e) {
    toast(`Not saved: ${e.message || e}`, 5000);
  }
}

function invitePreview(acc) {
  const b = acc.profile.behavior;
  const a = acc.profile.account;
  const hn = (n) => (b.compact_headers ? { Via: "v", From: "f", To: "t", "Call-ID": "i", Contact: "m", "Content-Length": "l", "Content-Type": "c", Supported: "k" }[n] || n : n);
  const host = (a.domain || "pbx.example.com").replace(/:\d+$/, "");
  const target = `sip:600@${a.domain || "pbx.example.com"}${b.user_phone ? ";user=phone" : ""}`;
  const local = `${b.local_ip || "192.0.2.10"}:${b.local_port || 50600}`;
  const sup = ["replaces", "100rel", "norefersub", ...(b.session_timer > 0 ? ["timer"] : []), ...(b.offer_gruu ? ["gruu"] : [])];
  const lines = [
    `INVITE ${target} SIP/2.0`,
    `${hn("Via")}: SIP/2.0/UDP ${local};branch=z9hG4bK3f1c9a${b.rport ? ";rport" : ""}`,
    `Max-Forwards: ${b.max_forwards}`,
    `${hn("From")}: ${a.display_name ? `"${a.display_name}" ` : ""}<sip:${a.user || "2001"}@${host}>;tag=8d2e`,
    `${hn("To")}: <${target}>`,
    `${hn("Call-ID")}: 5b0c7e@${local.split(":")[0]}`,
    "CSeq: 1 INVITE",
    ...(b.proxy_require ? [`Proxy-Require: ${b.proxy_require}`] : []),
    `User-Agent: ${b.user_agent}`,
    `${hn("Contact")}: <sip:${a.user || "2001"}@${local}>${b.long_contact ? ';+sip.instance="<urn:uuid:…>";reg-id=1;audio;…' : ""}`,
    "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE",
    `${hn("Supported")}: ${sup.join(", ")}`,
    ...(b.require_prack ? ["Require: 100rel"] : []),
    ...(b.session_timer > 0 ? [`Session-Expires: ${b.session_timer};refresher=uac`, "Min-SE: 90"] : []),
    ...(b.extra_headers || []).map(([k, v]) => `${k}: ${v}`),
    `${hn("Content-Type")}: application/sdp`,
  ];
  const ip = b.sdp_ip_override || local.split(":")[0];
  const cpt = (c) => (c === "PCMA" ? 8 : c === "opus" ? 111 : 0);
  const pts = (b.codecs || []).map(cpt);
  const dt = b.dtmf_mode === "rfc4733" ? [b.dtmf_payload_type] : [];
  const sdp = [
    "v=0", `o=sidetone 1 1 IN IP4 ${ip}`, "s=Sidetone", `c=IN IP4 ${ip}`, "t=0 0",
    `m=audio ${b.rtp_port_start} RTP/AVP ${[...pts, ...dt].join(" ")}`,
    ...(b.codecs || []).flatMap((c) => (c === "opus" ? ["a=rtpmap:111 opus/48000/2", "a=fmtp:111 useinbandfec=1"] : [`a=rtpmap:${cpt(c)} ${c}/8000`])),
    ...(dt.length ? [`a=rtpmap:${dt[0]} telephone-event/8000`, `a=fmtp:${dt[0]} 0-16`] : []),
    `a=ptime:${b.ptime_ms}`, `a=${b.sdp_direction}`,
  ];
  return `${lines.join("\r\n")}\r\n\r\n${sdp.join("\r\n")}`;
}

async function renderGlobal(section) {
  const body = $("#set-body");
  const native = S.ctl.kind === "native";
  const st = SET.cfg.settings || {};
  if (section === "calls") {
    const fields = CALL_SETTINGS.filter((f) => native || f[5] !== "native");
    body.innerHTML = `<div class="set-head"><h1>Call handling</h1></div>
      <form class="set-form" id="g-form"><div class="fields">${fields.map((f, i) => fieldHtml(f, get(st, f[0]), `gf-${i}`)).join("")}</div>
      <div class="set-actions"><button type="submit" class="btn primary">Save</button></div></form>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      fields.forEach((f, i) => readField(f, `gf-${i}`, st));
      await S.ctl.setConfig({ settings: st });
      toast("Saved");
    });
  } else if (section === "audio") {
    if (!native) {
      body.innerHTML = `<div class="set-head"><h1>Audio</h1></div><p class="muted">The browser phone uses the browser's microphone and speaker. Choose devices in the browser's site settings. Echo cancellation and noise suppression are on.</p>`;
      return;
    }
    let dev = { devices: { inputs: [], outputs: [] }, audio: {} };
    try { dev = await S.ctl.audio(); } catch { /* keep empty */ }
    const ap = SET.cfg.audio || {};
    const opt = (list, cur) => [`<option value="">System default</option>`, ...list.map((n) => `<option ${n === cur ? "selected" : ""}>${esc(n)}</option>`)].join("");
    body.innerHTML = `<div class="set-head"><h1>Audio</h1></div>
      <form class="set-form" id="g-form"><div class="fields">
        <label class="check fld"><input type="checkbox" id="au-en" ${ap.enabled !== false ? "checked" : ""}> Use the sound card</label>
        <label class="fld">Microphone<select id="au-in">${opt(dev.devices.inputs || [], ap.input)}</select></label>
        <label class="fld">Speaker or headset<select id="au-out">${opt(dev.devices.outputs || [], ap.output)}</select></label>
        ${fieldHtml(["audio_source", "Send during calls", "select", "test tone and echo help when nobody is at the other end", [["device", "Sound card (microphone)"], ["tone", "Test tone"], ["echo", "Echo what is received"], ["silence", "Silence"]]], st.audio_source, "au-src")}
        ${fieldHtml(["tone_hz", "Test tone frequency (Hz)", "number"], st.tone_hz, "au-hz")}
      </div>
      <p class="hint">${esc(dev.audio && dev.audio.error ? `Sound card: ${dev.audio.error}` : dev.audio && dev.audio.status ? `Open: ${dev.audio.status.input || "no microphone"} / ${dev.audio.status.output || "no speaker"}` : "")}</p>
      <div class="set-actions"><button type="submit" class="btn primary">Save</button></div></form>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      st.audio_source = $("#au-src").value;
      st.tone_hz = Number($("#au-hz").value) || 440;
      const audio = { enabled: $("#au-en").checked, input: $("#au-in").value || null, output: $("#au-out").value || null };
      await S.ctl.setConfig({ settings: st, audio });
      SET.cfg = await S.ctl.getConfig();
      toast("Saved");
      renderGlobal("audio");
    });
  } else if (section === "capture") {
    if (!native) {
      body.innerHTML = `<div class="set-head"><h1>Capture and recording</h1></div><p class="muted">The browser phone logs every SIP message and rebuilds a pcapng from it for analysis. Media is DTLS-SRTP inside the browser, so quality comes from WebRTC statistics instead of RTP packets.</p>`;
      return;
    }
    const fields = [
      ["capture", "Capture every SIP packet in memory for analysis and pcapng export", "bool"],
      ["capture_rtp", "Include RTP (needed for jitter, loss and MOS)", "bool"],
      ["record_calls", "Record the audio of every call (WAV)", "bool", "you can also press Record during a call"],
    ];
    body.innerHTML = `<div class="set-head"><h1>Capture and recording</h1></div>
      <form class="set-form" id="g-form"><div class="fields">${fields.map((f, i) => fieldHtml(f, get(st, f[0]), `gf-${i}`)).join("")}</div>
      <p class="hint">${S.st ? `${S.st.capture_packets.toLocaleString()} packets in memory now.` : ""} Accounts, settings and call history are saved in your user configuration folder.</p>
      <div class="set-actions"><button type="button" class="btn" id="cap-clear">Clear capture now</button><button type="submit" class="btn primary">Save</button></div></form>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      fields.forEach((f, i) => readField(f, `gf-${i}`, st));
      await S.ctl.setConfig({ settings: st });
      toast("Saved");
    });
    $("#cap-clear").addEventListener("click", async () => {
      await S.ctl.clearCapture();
      S.trace = [];
      toast("Capture cleared");
    });
  } else if (section === "ai") {
    const a = aiSettings();
    const presetOpts = [`<option value="">${esc(t("Choose a service…"))}</option>`, ...AI_PRESETS.map(([n], i) => `<option value="${i}">${esc(n)}</option>`)].join("");
    body.innerHTML = `<div class="set-head"><h1>AI</h1></div>
      <form class="set-form" id="ai-set">
        <p class="muted">${esc(t("Sidetone has no AI of its own. Use the provider you prefer: your key goes only to that provider, and nothing is sent until you ask."))}</p>
        <div class="fields">
          <label class="fld">${esc(t("Provider"))}<select id="as-provider">
            <option value="anthropic">Anthropic (Claude)</option>
            <option value="openai">${esc(t("OpenAI-compatible (OpenAI, Gemini, OpenRouter, Groq, Mistral, LM Studio...)"))}</option>
            <option value="ollama">${esc(t("Ollama (local, nothing leaves this machine)"))}</option>
          </select></label>
          <label class="fld" id="as-preset-wrap">${esc(t("Service"))}<select id="as-preset">${presetOpts}</select></label>
          <label class="fld">${esc(t("Model"))}<input id="as-model" value="${esc(a.model || "")}" spellcheck="false"></label>
          <label class="fld">${esc(t("Base URL"))} <span class="hint">${esc(t("empty = the provider's default; a full .../chat/completions URL also works"))}</span><input id="as-base" value="${esc(a.base_url || "")}" spellcheck="false"></label>
          <label class="fld" id="as-key-wrap">${esc(t("API key"))}<input id="as-key" type="password" value="${esc(a.key || "")}" autocomplete="off"></label>
          <label class="check fld"><input type="checkbox" id="as-remember" ${a.remember ? "checked" : ""}> ${esc(t("Remember the key on this device"))}</label>
          <label class="fld">${esc(t("Answer in"))}<select id="as-lang">${["English", "Portuguese (Brazil)", "Spanish", "German"].map((l) => `<option value="${l}" ${l === a.language ? "selected" : ""}>${esc(t(l))}</option>`).join("")}</select></label>
          <label class="check fld"><input type="checkbox" id="as-redact" ${a.redact ? "checked" : ""}> ${esc(t("Mask numbers, names, credentials and public IPs before sending"))}</label>
        </div>
        <p class="hint">${esc(S.be.kind === "wasm" ? t("In the browser the request goes straight from this page to the provider; some providers block that (CORS). Anthropic, OpenRouter and a local Ollama with OLLAMA_ORIGINS work.") : t("Requests go from this computer to the provider."))}</p>
        <div class="set-actions"><span class="hint" id="as-status"></span><button type="button" class="btn" id="as-test">${esc(t("Test connection"))}</button><button type="submit" class="btn primary">${esc(t("Save"))}</button></div>
      </form>`;
    const prov = $("#as-provider");
    prov.value = a.provider;
    const sync = () => {
      const p = prov.value;
      $("#as-preset-wrap").hidden = p !== "openai";
      $("#as-key-wrap").hidden = p === "ollama";
      $("#as-model").placeholder = p === "ollama" ? "llama3.1" : p === "openai" ? "gpt-4o-mini" : "claude-sonnet-5-5";
      $("#as-base").placeholder = p === "ollama" ? "http://localhost:11434" : p === "openai" ? "https://api.openai.com" : "https://api.anthropic.com";
    };
    sync();
    prov.addEventListener("change", () => {
      $("#as-model").value = AI_DEFAULT_MODEL[prov.value] || "";
      $("#as-base").value = "";
      sync();
    });
    $("#as-preset").addEventListener("change", (e) => {
      const p = AI_PRESETS[+e.target.value];
      if (!p) return;
      $("#as-base").value = p[1];
      if (p[2]) $("#as-model").value = p[2];
    });
    const read = () => ({
      provider: prov.value,
      model: $("#as-model").value.trim(),
      base_url: $("#as-base").value.trim() || null,
      key: $("#as-key").value.trim() || null,
      remember: $("#as-remember").checked,
      language: $("#as-lang").value,
      redact: $("#as-redact").checked,
    });
    $("#ai-set").addEventListener("submit", (e) => {
      e.preventDefault();
      saveAiSettings(read());
      toast(t("Saved"));
    });
    $("#as-test").addEventListener("click", async () => {
      saveAiSettings(read());
      const st = $("#as-status");
      const bad = aiNotReady();
      if (bad) return (st.textContent = bad);
      st.textContent = t("Testing…");
      try {
        const r = await S.be.ai(aiConfig(), "You are a connectivity check.", "Reply with the single word OK.");
        st.textContent = `${t("Works")}: ${String(r).trim().slice(0, 60)}`;
        st.className = "hint ok";
      } catch (err) {
        st.textContent = err.message || String(err);
        st.className = "hint bad";
      }
    });
  } else if (section === "lang") {
    body.innerHTML = `<div class="set-head"><h1>Language</h1></div>
      <div class="set-form"><div class="fields">
        <label class="fld">Language<select id="lang-sel">${LANGS.map(([c, n]) => `<option value="${c}" ${c === currentLang() ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
      </div>
      <p class="hint">SIP messages, traces and analyzer findings stay in English, as they appear on the wire and in RFCs.</p></div>`;
    $("#lang-sel").addEventListener("change", (e) => setLang(e.target.value));
  } else if (section === "keys") {
    const rows = [
      ["Enter", "Call the number in the dial field, or answer the selected incoming call"],
      ["Esc", "Hang up, cancel or reject the selected line"],
      ["0 to 9, *, #", "Send DTMF on the selected call (outside text fields)"],
      ["F2", "Transfer"],
      ["F3", "Hold or resume"],
      ["F4", "Mute or unmute"],
      ["Up and down arrows", "Move through the SIP trace"],
    ];
    body.innerHTML = `<div class="set-head"><h1>Keyboard</h1></div>${table(["Key", "Action"], rows.map(([k, v]) => [`<kbd>${esc(k)}</kbd>`, esc(v)]))}`;
  }
}

function bindSettings() {
  $("#acc-list").addEventListener("click", (e) => {
    const b = e.target.closest("[data-acc]");
    if (!b) return;
    SET.accId = b.dataset.acc;
    SET.section = null;
    SET.dirty = false;
    renderSetNav();
    renderSetBody();
  });
  $$(".set-nav [data-set]").forEach((b) =>
    b.addEventListener("click", () => {
      SET.section = b.dataset.set;
      SET.dirty = false;
      renderSetNav();
      renderSetBody();
    })
  );
  $("#acc-add").addEventListener("click", addAccount);
  $("#prov-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runProvisionFetch();
  });
  $("#prov-cancel").addEventListener("click", () => $("#prov-dialog").close());
}

// ============================================================================
// Boot

function bindChrome() {
  $$(".ws-tabs [data-ws]").forEach((b) => b.addEventListener("click", () => showWs(b.dataset.ws)));
  const modes = ["system", "light", "dark"];
  const applyTheme = (m) => {
    if (m === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = m;
    $("#theme").textContent = { system: "Theme: auto", light: "Theme: light", dark: "Theme: dark" }[m];
  };
  let mode = store.get("sidetone.theme", "system");
  applyTheme(mode);
  $("#theme").addEventListener("click", () => {
    mode = modes[(modes.indexOf(mode) + 1) % modes.length];
    store.set("sidetone.theme", mode);
    applyTheme(mode);
  });
  $("#st-err").addEventListener("click", () => {
    S.errors = 0;
    renderStatus();
    showWs("calls");
  });
  $("#events-clear").addEventListener("click", () => {
    S.events = [];
    renderEvents();
  });
  $("#hist-filter").addEventListener("input", renderHistory);
  $("#hist-clear").addEventListener("click", async () => {
    await S.ctl.clearHistory();
    renderHistory();
  });
}

async function main() {
  initI18n();
  S.be = await pickBackend();
  if (S.be.kind === "http") {
    try { S.version = (await (await S.be.get("api/info")).json()).version; } catch { /* ignore */ }
  }
  $("#where").textContent = S.be.kind === "wasm" ? "in this browser" : "on this computer";
  // ?phone=web uses the browser phone (WebRTC) even when the native engine is available.
  const forceWeb = new URLSearchParams(location.search).get("phone") === "web";
  S.ctl = !forceWeb && S.be.kind === "http" && S.be.features.includes("phone") ? new NativeController(S.be) : new WebController();
  if (S.ctl.kind === "web" && S.be.parseProvision) {
    S.ctl.setProvisionParser((xml, kind) => S.be.parseProvision(xml, kind));
  }
  document.body.classList.toggle("web-mode", S.ctl.kind === "web");
  $("#st-mode").textContent = S.ctl.kind === "web" ? "Browser phone (WebRTC)" : "Desktop engine (UDP)";
  bindChrome();
  bindPhone();
  bindTrace();
  bindAnalysis();
  bindDiag();
  bindSettings();
  bindDock();
  renderAiUsing();

  S.ctl.on((u) => {
    if (u.error) toast(u.error, 6000);
    if (u.events && u.events.length) onEvents(u.events);
    if (u.trace && u.trace.length) onTrace(u.trace);
    if (u.state) onState(u.state);
  });
  await S.ctl.start();

  const samples = await S.be.samples();
  const open = async (n) => {
    await load(await S.be.sample(n), `${n}.pcapng`);
    showWs("analysis");
  };
  $("#samples-list").innerHTML = samples.map((s) => `<button type="button" role="menuitem" data-sample="${esc(s.name)}">${esc(s.name)}<small>${esc(s.description)}</small></button>`).join("");
  $("#sample-grid").innerHTML = samples.map((s) => `<button type="button" data-sample="${esc(s.name)}"><b>${esc(s.name)}</b><span>${esc(s.description)}</span></button>`).join("");
  $$("[data-sample]").forEach((b) => b.addEventListener("click", () => open(b.dataset.sample)));

  const params = new URLSearchParams(location.search);
  const want = params.get("sample");
  const noAccounts = S.st && !S.st.accounts.length;
  if (want) await open(want);
  else showWs(params.get("page") || (noAccounts ? "settings" : store.get("sidetone.page", "calls")));
}

main().catch((e) => {
  console.error(e);
  document.body.insertAdjacentHTML("beforeend", `<p style="padding:16px;color:#b91c1c">Sidetone could not start: ${esc(e.message || e)}</p>`);
});
