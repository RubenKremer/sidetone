// Sidetone web UI. One frontend, three backends:
//  - wasm: analysis in the browser (GitHub Pages build, ./pkg present)
//  - http: `sidetone serve` or the desktop app (native analysis, AI proxy, test calls)

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

// ---------- backends ----------

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
      } catch (e) {
        throw new Error(`Could not reach ${req.url}. ${cfg.provider === "ollama" ? "Start Ollama with OLLAMA_ORIGINS set to this page's origin." : "The provider may block browser requests (CORS); use the desktop app or `sidetone serve`."}`);
      }
      const text = await res.text();
      return w.ai_parse(cfg.provider, text);
    },
    samples: async () => JSON.parse(w.samples()),
    sample: async (n) => w.sample(n),
    captureFromLog: async (log) => w.capture_from_sip_log(JSON.stringify(log)),
  };
}

async function httpBackend() {
  const headers = token ? { "x-sidetone-token": token } : {};
  const info = await (await fetch("api/info", { headers })).json();
  const post = async (path, body, type = "application/octet-stream") => {
    const r = await fetch(path, { method: "POST", headers: { ...headers, "content-type": type }, body });
    if (!r.ok) {
      let msg = `${r.status}`;
      try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    return r;
  };
  const q = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== false).map(([k, v]) => [k, v === true ? "1" : String(v)])).toString();
  return {
    kind: "http",
    features: info.features || [],
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
    sample: async (n) => new Uint8Array(await (await fetch(`api/sample?${q({ name: n })}`, { headers })).arrayBuffer()),
    captureFromLog: async (log) => new Uint8Array(await (await post("api/sip-log-capture", JSON.stringify(log), "application/json")).arrayBuffer()),
    sipCall: async (params) => (await post("api/call", JSON.stringify(params), "application/json")).json(),
    sipOptions: async (params) => (await post("api/options", JSON.stringify(params), "application/json")).json(),
    sipRegister: async (params) => (await post("api/register", JSON.stringify(params), "application/json")).json(),
    save: (info.features || []).includes("native-save") ? async (data, name) => (await post(`api/save?${q({ name })}`, data)).json() : null,
  };
}

async function pickBackend() {
  try {
    return await wasmBackend();
  } catch {
    return await httpBackend();
  }
}

// ---------- state ----------

const S = { be: null, bytes: null, name: "", report: null, call: null, msg: null, stream: null };
window.__sidetone = S; // handy for debugging from the console

function toast(text, ms = 2600) {
  const t = $("#toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toast.h);
  toast.h = setTimeout(() => t.classList.remove("show"), ms);
}

function b64ToBytes(b64) {
  const s = atob(b64);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
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

// ---------- loading ----------

function setView(v) {
  $("#app").classList.toggle("view-phone", v === "phone");
  $("#app").classList.toggle("view-analysis", v === "analysis");
  $$(".view-btn").forEach((b) => b.setAttribute("aria-current", String(b.dataset.view === v)));
}

async function load(bytes, name, webrtc = null, show = true) {
  try {
    const report = await S.be.analyze(bytes);
    Object.assign(S, { bytes, name, report, call: null, msg: null, stream: null, webrtc });
  } catch (e) {
    toast(`Could not read ${name}: ${e.message || e}`, 5000);
    return;
  }
  const r = S.report;
  $('.view-btn[data-view="analysis"]').disabled = false;
  if (show) setView("analysis");
  $("#btn-export").disabled = false;
  const s = r.summary;
  $("#capinfo").textContent = `${name}: ${s.calls} calls, ${s.sip_messages} SIP messages, ${s.rtp_streams} RTP streams, ${s.duration_s.toFixed(1)} s`;
  renderCalls();
  const first = r.calls.findIndex((c) => c.errors > 0);
  const inv = r.calls.findIndex((c) => c.kind === "INVITE");
  selectCall(first >= 0 ? first : inv >= 0 ? inv : r.calls.length ? 0 : null);
}

async function loadFile(f) {
  const buf = new Uint8Array(await f.arrayBuffer());
  await load(buf, f.name);
}

// ---------- rendering ----------

const STATE_LABEL = { answered: "Answered", failed: "Failed", cancelled: "Cancelled", in_progress: "No answer", non_invite: "" };

function renderCalls() {
  const r = S.report;
  $("#calls-count").textContent = r.calls.length;
  $("#calls").innerHTML = r.calls
    .map((c) => {
      const st = c.state;
      const label = st === "non_invite" ? (c.final_status ? `${c.final_status}` : "no answer") : `${STATE_LABEL[st]}${c.final_status ? " " + c.final_status : ""}`;
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
  S.stream = null;
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
  const r = S.report;
  return r.findings.filter((f) => S.call == null || f.call === S.call || f.call == null);
}

function renderFindings() {
  const fs = callFindings();
  $("#n-findings").textContent = fs.length || "";
  if (!fs.length) {
    $("#tab-findings").innerHTML = `<p class="empty-note">No findings for this call. Signaling and media look as expected.</p>`;
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
  const lines = head.split(/\r?\n/);
  const out = [`<span class="sl">${esc(lines[0])}</span>`];
  for (const l of lines.slice(1)) {
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
    $("#tab-media").innerHTML = `<p class="empty-note">${r.streams.length ? "No RTP linked to this call." : "The capture has no RTP. Capture media too (not only port 5060) to analyze audio."}</p>`;
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

function aiSettingsLoad() {
  const s = store.get("sidetone.ai", {});
  $("#ai-provider").value = s.provider || "anthropic";
  $("#ai-model").value = s.model ?? AI_DEFAULT_MODEL[$("#ai-provider").value];
  $("#ai-base").value = s.base_url || "";
  $("#ai-lang").value = s.language || "English";
  $("#ai-redact").checked = s.redact !== false;
  $("#ai-remember").checked = !!s.key;
  $("#ai-key").value = s.key || "";
  aiPlaceholders();
}

function aiPlaceholders() {
  const p = $("#ai-provider").value;
  $("#ai-model").placeholder = p === "ollama" ? "e.g. llama3.1" : p === "openai" ? "model name" : "claude-sonnet-5-5";
  $("#ai-base").placeholder = p === "ollama" ? "http://localhost:11434" : p === "openai" ? "https://api.openai.com" : "https://api.anthropic.com";
  $("#ai-key").disabled = p === "ollama";
}

function aiConfig() {
  const provider = $("#ai-provider").value;
  const cfg = {
    provider,
    model: $("#ai-model").value.trim() || AI_DEFAULT_MODEL[provider],
    base_url: $("#ai-base").value.trim() || null,
    api_key: $("#ai-key").value.trim() || null,
    language: $("#ai-lang").value,
    max_tokens: 2000,
  };
  store.set("sidetone.ai", {
    provider,
    model: $("#ai-model").value.trim(),
    base_url: cfg.base_url,
    language: cfg.language,
    redact: $("#ai-redact").checked,
    key: $("#ai-remember").checked ? cfg.api_key : undefined,
  });
  return cfg;
}

function renderAnswer(text) {
  const lines = esc(text).split("\n").map((l) => {
    const h = l.match(/^#{1,4}\s+(.*)$/);
    if (h) return `<h3>${h[1]}</h3>`;
    return l.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  });
  return `<div class="answer">${lines.join("\n")}</div>`;
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
  if (!cfg.model) {
    out.innerHTML = `<p class="err">Enter a model name for this provider.</p>`;
    return;
  }
  if (cfg.provider !== "ollama" && !cfg.api_key && S.be.kind === "wasm") {
    out.innerHTML = `<p class="err">Enter an API key. It stays in this browser and goes only to the provider.</p>`;
    return;
  }
  const btn = $("#ai-go");
  btn.disabled = true;
  out.innerHTML = `<p class="muted">Asking ${esc(cfg.provider)} (${esc(cfg.model)})…</p>`;
  try {
    const text = await S.be.ai(cfg, system, prompt);
    out.innerHTML = renderAnswer(text);
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
  } finally {
    btn.disabled = false;
  }
}

// ---------- wiring ----------

function bind() {
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
    const st = e.target.closest(".stream");
    if (st) showTab("media");
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

  $("#ai-provider").addEventListener("change", () => {
    $("#ai-model").value = AI_DEFAULT_MODEL[$("#ai-provider").value];
    aiPlaceholders();
  });
  $("#ai-form").addEventListener("submit", (e) => {
    e.preventDefault();
    askAI(false);
  });
  $("#ai-preview").addEventListener("click", () => askAI(true));

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

  $$(".view-btn").forEach((b) => b.addEventListener("click", () => !b.disabled && setView(b.dataset.view)));
}

// ---------- web phone ----------

async function setupPhone() {
  const { WebPhone } = await import("./webphone.js");
  const native = S.be.features.includes("ua");
  const saved = store.get("sidetone.phone", {});
  const fields = [["p-ws", "ws"], ["p-domain", "domain"], ["p-user", "user"], ["p-auth", "authUser"], ["p-stun", "stun"], ["p-target", "target"], ["p-dur", "dur"]];
  for (const [id, k] of fields) if (saved[k] != null && saved[k] !== "") $("#" + id).value = saved[k];
  if (saved.profile) $("#p-profile").value = saved.profile;
  let mode = native && saved.mode === "udp" ? "udp" : "ws";
  let phone = null; // WebPhone in ws mode
  let udpReady = false;
  const logEl = $("#p-log");
  const busy = { on: false };

  const ui = {
    log: (t) => {
      logEl.textContent += `${new Date().toISOString().slice(11, 23)}  ${t}\n`;
      logEl.scrollTop = logEl.scrollHeight;
    },
    state: (t) => ($("#p-state").textContent = t ? t[0].toUpperCase() + t.slice(1) : ""),
    stats: (s) => ($("#p-stats").textContent = `${s.codec || ""}  rx ${s.recv ?? 0}  lost ${s.lost ?? 0}  jitter ${(s.jitter_ms ?? 0).toFixed(1)} ms  RTT ${(s.rtt_ms ?? 0).toFixed(0)} ms`),
    onIncoming: (from) => {
      ui.state(`incoming call from ${from.replace(/^.*<sip:([^>;]+).*$/, "$1")}`);
      $("#p-answer").hidden = false;
      $("#p-hangup").disabled = false;
      setView("phone");
    },
    onCallEnded: async (p, why) => {
      $("#p-answer").hidden = true;
      $("#p-hangup").disabled = true;
      $("#p-dial").disabled = false;
      $("#p-stats").textContent = "";
      await showResult(await S.be.captureFromLog(p.captureLog()), "web-phone-call.pcapng", p.summary());
    },
  };

  // After a call: analyze in the background and offer the result from the phone screen.
  async function showResult(bytes, name, webrtc) {
    try {
      await load(bytes, name, webrtc, false);
      const s = S.report.summary;
      const el = $("#p-result");
      el.hidden = false;
      el.innerHTML = `Call analyzed: ${s.errors} error${s.errors === 1 ? "" : "s"}, ${s.warnings} warning${s.warnings === 1 ? "" : "s"}. <a id="p-open">View analysis</a>`;
      $("#p-open").addEventListener("click", () => setView("analysis"));
    } catch (e) {
      ui.log(`could not analyze the call: ${e.message || e}`);
    }
  }

  const setMode = (m) => {
    mode = m;
    $$(".seg [data-mode]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.mode === m)));
    $$(".server-card [data-for]").forEach((el) => (el.hidden = el.dataset.for !== m));
    $("#p-connect").textContent = m === "ws" ? "Connect and register" : "Register";
    $("#p-dial").disabled = m === "ws" ? !phone : false;
    if (m === "udp") ui.state(udpReady ? "ready" : "ready to call over UDP");
    else ui.state(phone ? "connected" : "set up a SIP server to start");
  };
  if (native) $("#mode-udp").hidden = false;
  $$(".seg [data-mode]").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));

  const cfg = () => ({
    ws: $("#p-ws").value.trim(),
    domain: $("#p-domain").value.trim(),
    user: $("#p-user").value.trim(),
    authUser: $("#p-auth").value.trim() || null,
    password: $("#p-pass").value,
    stun: $("#p-stun").value.trim(),
  });
  const remember = () =>
    store.set("sidetone.phone", { ...cfg(), password: undefined, target: $("#p-target").value.trim(), dur: $("#p-dur").value, profile: $("#p-profile").value, mode });

  function udpParams(target) {
    const c = cfg();
    let profile = null;
    const raw = $("#p-profile").value.trim();
    if (raw) profile = JSON.parse(raw);
    if (c.authUser) profile = { ...(profile || {}), account: { ...((profile && profile.account) || {}), auth_user: c.authUser } };
    return { domain: c.domain, user: c.user, password: c.password, target, duration: +$("#p-dur").value || 20, audio: $("#p-audio-src").value, register: $("#p-register").checked, profile };
  }

  $("#p-connect").addEventListener("click", async () => {
    const c = cfg();
    remember();
    if (mode === "udp") {
      if (!c.domain) return ui.state("enter the server");
      ui.state("registering…");
      try {
        const res = await S.be.sipRegister(udpParams(""));
        (res.events || []).forEach((e) => ui.log(e.text));
        udpReady = res.status === 200;
        ui.state(res.status === 200 ? `registered as ${c.user} (from ${res.local})` : `register answered ${res.status ?? "nothing"}`);
        await showResult(b64ToBytes(res.pcap_b64), "register.pcapng", null);
      } catch (e) {
        ui.state(`register failed: ${e.message || e}`);
      }
      return;
    }
    if (!c.ws || !c.domain || !c.user) return ui.state("fill in WebSocket URL, domain and user");
    c.iceServers = c.stun ? [{ urls: c.stun }] : [];
    if (phone) phone.close();
    phone = new WebPhone(c, ui);
    window.__phone = phone;
    try {
      ui.state("connecting…");
      await phone.connect();
      const st = await phone.register();
      ui.state(st === 200 ? `registered as ${c.user}` : `register answered ${st ?? "nothing"}`);
      $("#p-dial").disabled = false;
    } catch (e) {
      ui.state(e.message);
    }
  });

  $("#p-options").addEventListener("click", async () => {
    remember();
    const p = udpParams($("#p-target").value.trim() || cfg().domain);
    ui.state(`OPTIONS to ${p.target}…`);
    try {
      const res = await S.be.sipOptions(p);
      ui.state(`OPTIONS: ${res.status ?? "no response"}${res.rtt_ms != null ? ` in ${res.rtt_ms} ms` : ""}`);
      (res.events || []).forEach((e) => ui.log(e.text));
      await showResult(b64ToBytes(res.pcap_b64), "options.pcapng", null);
    } catch (e) {
      ui.state(`OPTIONS failed: ${e.message || e}`);
    }
  });

  $("#p-dial").addEventListener("click", async () => {
    const t = $("#p-target").value.trim();
    if (!t || busy.on) return;
    remember();
    $("#p-result").hidden = true;
    $("#p-dial").disabled = true;
    if (mode === "udp") {
      const p = udpParams(t);
      busy.on = true;
      ui.state(`calling ${t}, ends after ${p.duration} s`);
      try {
        const res = await S.be.sipCall(p);
        const o = res.outcome;
        (res.events || []).forEach((e) => ui.log(e.text));
        ui.state(o.answered ? `call ended: ${o.final_status} ${o.final_reason || ""}, ${o.codec}, rx ${o.rtp_received} pkts` : `call failed: ${o.final_status ?? "no answer"} ${o.final_reason || ""}`);
        await showResult(b64ToBytes(res.pcap_b64), `call-${t}.pcapng`, null);
      } catch (e) {
        ui.state(`call failed: ${e.message || e}`);
      } finally {
        busy.on = false;
        $("#p-dial").disabled = false;
      }
      return;
    }
    if (!phone) return;
    $("#p-hangup").disabled = false;
    try {
      await phone.dial(t, $("#p-audio"));
    } catch (e) {
      ui.state(`call failed: ${e.message || e}`);
      $("#p-dial").disabled = false;
    }
  });
  $("#p-answer").addEventListener("click", async () => {
    $("#p-answer").hidden = true;
    await phone.answer($("#p-audio"));
  });
  $("#p-hangup").addEventListener("click", () => phone && phone.hangup());
  $("#p-backspace").addEventListener("click", () => ($("#p-target").value = $("#p-target").value.slice(0, -1)));

  // Keys dial the number when idle and send DTMF during a call; the keyboard works too.
  const press = (k) => {
    const b = $(`#p-keypad [data-key="${CSS.escape(k)}"]`);
    if (b) {
      b.classList.add("hit");
      setTimeout(() => b.classList.remove("hit"), 140);
    }
    if (phone && phone.call && phone.call.answered) phone.dtmf(k);
    else $("#p-target").value += k;
  };
  $$("#p-keypad button").forEach((b) => b.addEventListener("click", () => press(b.dataset.key)));
  $(".phone-card").addEventListener("keydown", (e) => {
    if (phone && phone.call && phone.call.answered && /^[0-9*#]$/.test(e.key)) {
      e.preventDefault();
      press(e.key);
    } else if (e.key === "Enter" && e.target.id === "p-target" && !$("#p-dial").disabled) {
      e.preventDefault();
      $("#p-dial").click();
    }
  });
  setMode(mode);
}

async function main() {
  S.be = await pickBackend();
  $("#where").textContent = S.be.kind === "wasm" ? "in this browser" : "on the machine running Sidetone";
  bind();
  aiSettingsLoad();
  setupPhone().catch((e) => console.warn("web phone unavailable", e));
  const samples = await S.be.samples();
  const open = async (n) => load(await S.be.sample(n), `${n}.pcapng`);
  $("#samples-list").innerHTML = samples.map((s) => `<button type="button" role="menuitem" data-sample="${esc(s.name)}">${esc(s.name)}<small>${esc(s.description)}</small></button>`).join("");
  $("#sample-grid").innerHTML = samples.map((s) => `<button type="button" data-sample="${esc(s.name)}"><b>${esc(s.name)}</b><span>${esc(s.description)}</span></button>`).join("");
  $$("[data-sample]").forEach((b) => b.addEventListener("click", () => open(b.dataset.sample)));
  const want = new URLSearchParams(location.search).get("sample");
  if (want) await open(want);
}

main().catch((e) => {
  document.body.insertAdjacentHTML("beforeend", `<p style="padding:16px;color:#b91c1c">Sidetone could not start: ${esc(e.message || e)}</p>`);
});
