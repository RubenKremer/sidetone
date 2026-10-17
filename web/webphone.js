// Browser SIP phone: SIP over WebSocket (RFC 7118) with WebRTC media.
// Every SIP message is logged with a timestamp so the call can be analyzed
// like a capture; WebRTC getStats() supplies the media metrics.

// ---------- MD5 (RFC 1321), needed for SIP digest auth ----------
function md5(str) {
  const bytes = new TextEncoder().encode(str);
  const len = bytes.length;
  const words = new Uint32Array((((len + 8) >> 6) + 1) * 16);
  for (let i = 0; i < len; i++) words[i >> 2] |= bytes[i] << ((i % 4) * 8);
  words[len >> 2] |= 0x80 << ((len % 4) * 8);
  words[words.length - 2] = len * 8;
  const K = new Uint32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));
  const R = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  for (let o = 0; o < words.length; o += 16) {
    let [a, b, c, d] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c;
      c = b;
      const x = (a + f + K[i] + words[o + g]) | 0;
      const s = R[(i >> 4) * 4 + (i % 4)];
      b = (b + ((x << s) | (x >>> (32 - s)))) | 0;
      a = tmp;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  return [a0, b0, c0, d0].map((v) => [0, 8, 16, 24].map((s) => ((v >>> s) & 255).toString(16).padStart(2, "0")).join("")).join("");
}

const rnd = (n = 10) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => (b % 36).toString(36)).join("");

const COMPACT = { i: "call-id", m: "contact", l: "content-length", c: "content-type", f: "from", t: "to", v: "via", k: "supported" };

function parse(text) {
  const sep = text.indexOf("\r\n\r\n");
  const head = sep >= 0 ? text.slice(0, sep) : text;
  const body = sep >= 0 ? text.slice(sep + 4) : "";
  const lines = head.split("\r\n");
  const first = lines.shift();
  const msg = { first, headers: {}, body, text };
  const m = first.match(/^SIP\/2\.0 (\d{3}) ?(.*)$/);
  if (m) {
    msg.status = +m[1];
    msg.reason = m[2];
  } else {
    [msg.method, msg.uri] = first.split(" ");
  }
  for (const l of lines) {
    const i = l.indexOf(":");
    if (i < 0) continue;
    let k = l.slice(0, i).trim().toLowerCase();
    k = COMPACT[k] || k;
    (msg.headers[k] ||= []).push(l.slice(i + 1).trim());
  }
  msg.h = (k) => (msg.headers[k] || [])[0];
  const via = msg.h("via") || "";
  msg.branch = (via.match(/branch=([^;,\s]+)/) || [])[1];
  msg.cseq = msg.h("cseq") || "";
  return msg;
}

const param = (v, name) => ((v || "").match(new RegExp(`${name}="?([^";,]+)"?`, "i")) || [])[1];

export class WebPhone {
  constructor(cfg, ui) {
    this.cfg = cfg; // {ws, domain, user, authUser, password, displayName, iceServers}
    this.ui = ui; // {log(text), state(text), onCallEnded(phone), onIncoming(from)}
    this.log = [];
    this.pending = new Map(); // branch -> resolve
    this.host = `${rnd(12)}.invalid`;
    this.regCallId = rnd(20);
    this.regTag = rnd(8);
    this.cseq = 1;
    this.nc = 0;
    this.call = null;
    this.stats = [];
  }

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.cfg.ws, "sip");
      this.ws = ws;
      const t = setTimeout(() => reject(new Error(`WebSocket ${this.cfg.ws} did not open in 8 s`)), 8000);
      ws.onopen = () => {
        clearTimeout(t);
        this.ui.state("connected");
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(t);
        reject(new Error(`WebSocket ${this.cfg.ws} failed (wrong URL, certificate not trusted, or the server rejected the "sip" subprotocol / Origin)`));
      };
      ws.onclose = (e) => this.ui.state(`disconnected (${e.code})`);
      ws.onmessage = (e) => this.onMessage(typeof e.data === "string" ? e.data : new TextDecoder().decode(e.data));
    });
  }

  send(text) {
    this.log.push({ t_ms: performance.timeOrigin + performance.now(), out: true, text });
    this.ui.log(`→ ${text.split("\r\n")[0]}`);
    this.ws.send(text);
  }

  aor() {
    return `sip:${this.cfg.user}@${this.cfg.domain}`;
  }

  contact() {
    return `<sip:${this.cfg.user}@${this.host};transport=ws>`;
  }

  build(method, uri, { from, to, callId, cseq, branch, extra = [], body = "", ctype = "application/sdp" }) {
    const lines = [
      `${method} ${uri} SIP/2.0`,
      `Via: SIP/2.0/WSS ${this.host};branch=${branch};rport`,
      "Max-Forwards: 70",
      `From: ${from}`,
      `To: ${to}`,
      `Call-ID: ${callId}`,
      `CSeq: ${cseq} ${method === "CANCEL" || method === "ACK" ? method : method}`,
      `Contact: ${this.contact()}`,
      "User-Agent: Sidetone Web Phone",
      ...extra,
    ];
    if (body) lines.push(`Content-Type: ${ctype}`);
    lines.push(`Content-Length: ${new TextEncoder().encode(body).length}`, "", body);
    return lines.join("\r\n");
  }

  digest(challenge, method, uri) {
    const realm = param(challenge, "realm");
    const nonce = param(challenge, "nonce");
    const qop = param(challenge, "qop");
    const opaque = param(challenge, "opaque");
    const user = this.cfg.authUser || this.cfg.user;
    const ha1 = md5(`${user}:${realm}:${this.cfg.password}`);
    const ha2 = md5(`${method}:${uri}`);
    let v = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", algorithm=MD5`;
    if (qop && qop.split(",").map((s) => s.trim()).includes("auth")) {
      const nc = (++this.nc).toString(16).padStart(8, "0");
      const cnonce = rnd(16);
      v += `, response="${md5(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`)}", qop=auth, nc=${nc}, cnonce="${cnonce}"`;
    } else {
      v += `, response="${md5(`${ha1}:${nonce}:${ha2}`)}"`;
    }
    if (opaque) v += `, opaque="${opaque}"`;
    return v;
  }

  request(text, branch, onProvisional) {
    return new Promise((resolve) => {
      this.pending.set(branch, { resolve, onProvisional });
      this.send(text);
      setTimeout(() => {
        if (this.pending.has(branch)) {
          this.pending.delete(branch);
          resolve(null);
        }
      }, 32000);
    });
  }

  onMessage(text) {
    if (!text.trim()) return; // keepalive
    this.log.push({ t_ms: performance.timeOrigin + performance.now(), out: false, text });
    const m = parse(text);
    this.ui.log(`← ${m.first}`);
    if (m.status) {
      const p = this.pending.get(m.branch);
      if (!p) {
        if (m.status >= 200 && m.cseq.endsWith("INVITE") && this.call && this.call.ack) this.send(this.call.ack); // 2xx retransmission
        return;
      }
      if (m.status < 200) {
        p.onProvisional && p.onProvisional(m);
        return;
      }
      this.pending.delete(m.branch);
      p.resolve(m);
      return;
    }
    this.onRequest(m);
  }

  reply(req, status, reason, { toTag, body = "", extra = [] } = {}) {
    const lines = [`SIP/2.0 ${status} ${reason}`];
    for (const v of req.headers["via"] || []) lines.push(`Via: ${v}`);
    for (const v of req.headers["record-route"] || []) lines.push(`Record-Route: ${v}`);
    lines.push(`From: ${req.h("from")}`);
    const to = req.h("to");
    lines.push(`To: ${toTag && !/;tag=/.test(to) ? `${to};tag=${toTag}` : to}`);
    lines.push(`Call-ID: ${req.h("call-id")}`, `CSeq: ${req.cseq}`, `Contact: ${this.contact()}`, "User-Agent: Sidetone Web Phone", ...extra);
    if (body) lines.push("Content-Type: application/sdp");
    lines.push(`Content-Length: ${new TextEncoder().encode(body).length}`, "", body);
    this.send(lines.join("\r\n"));
  }

  onRequest(m) {
    const c = this.call;
    switch (m.method) {
      case "OPTIONS":
        this.reply(m, 200, "OK");
        break;
      case "BYE":
        this.reply(m, 200, "OK");
        if (c && m.h("call-id") === c.callId) this.end("remote");
        break;
      case "CANCEL":
        this.reply(m, 200, "OK");
        if (c && c.incoming && m.h("call-id") === c.callId) {
          this.reply(c.invite, 487, "Request Terminated", { toTag: c.localTag });
          this.end("remote cancel");
        }
        break;
      case "INVITE":
        if (c && m.h("call-id") === c.callId) {
          // re-INVITE: keep media, answer with current description.
          this.reply(m, 200, "OK", { toTag: c.localTag, body: c.pc.localDescription.sdp });
          return;
        }
        if (c) {
          this.reply(m, 486, "Busy Here", { toTag: rnd(8) });
          return;
        }
        this.call = { incoming: true, invite: m, callId: m.h("call-id"), localTag: rnd(8) };
        this.reply(m, 180, "Ringing", { toTag: this.call.localTag });
        this.ui.onIncoming(m.h("from"));
        break;
      case "ACK":
        if (c) c.acked = true;
        break;
      case "NOTIFY":
      case "INFO":
      case "UPDATE":
        this.reply(m, 200, "OK");
        break;
      default:
        this.reply(m, 405, "Method Not Allowed");
    }
  }

  async register(expires = 300) {
    const uri = `sip:${this.cfg.domain}`;
    let auth = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const branch = `z9hG4bK${rnd(14)}`;
      const extra = [`Expires: ${expires}`];
      if (auth) extra.push(auth);
      const text = this.build("REGISTER", uri, { from: `<${this.aor()}>;tag=${this.regTag}`, to: `<${this.aor()}>`, callId: this.regCallId, cseq: this.cseq++, branch, extra });
      const r = await this.request(text, branch);
      if (!r) return null;
      if ((r.status === 401 || r.status === 407) && !auth && this.cfg.password) {
        const ch = r.status === 401 ? r.h("www-authenticate") : r.h("proxy-authenticate");
        auth = `${r.status === 401 ? "Authorization" : "Proxy-Authorization"}: ${this.digest(ch, "REGISTER", uri)}`;
        continue;
      }
      return r.status;
    }
    return null;
  }

  async media(remoteAudio) {
    const pc = new RTCPeerConnection({ iceServers: this.cfg.iceServers || [] });
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    stream.getTracks().forEach((t) => pc.addTrack(t, stream));
    pc.ontrack = (e) => {
      remoteAudio.srcObject = e.streams[0];
      remoteAudio.play().catch(() => {});
    };
    pc.oniceconnectionstatechange = () => this.ui.state(`ICE ${pc.iceConnectionState}`);
    return { pc, stream };
  }

  gathered(pc) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === "complete") return resolve();
      const done = () => pc.iceGatheringState === "complete" && resolve();
      pc.addEventListener("icegatheringstatechange", done);
      setTimeout(resolve, 2500); // send what we have
    });
  }

  targetUri(target) {
    if (/^sips?:/.test(target)) return target;
    return target.includes("@") ? `sip:${target}` : `sip:${target}@${this.cfg.domain}`;
  }

  async dial(target, remoteAudio) {
    const uri = this.targetUri(target);
    const { pc, stream } = await this.media(remoteAudio);
    const c = (this.call = { incoming: false, pc, stream, callId: rnd(20), localTag: rnd(8), uri, started: Date.now() });
    await pc.setLocalDescription(await pc.createOffer());
    await this.gathered(pc);
    let auth = null;
    let cseq = this.cseq++;
    for (let attempt = 0; attempt < 2; attempt++) {
      const branch = `z9hG4bK${rnd(14)}`;
      c.branch = branch;
      c.cseq = cseq;
      const extra = ["Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE", "Supported: replaces, ice"];
      if (auth) extra.push(auth);
      const text = this.build("INVITE", uri, { from: `<${this.aor()}>;tag=${c.localTag}`, to: `<${uri}>`, callId: c.callId, cseq, branch, extra, body: pc.localDescription.sdp });
      c.inviteText = text;
      this.ui.state("calling");
      const r = await this.request(text, branch, (p) => this.ui.state(`${p.status} ${p.reason}`));
      if (!r) {
        this.end("no answer (timeout)");
        return null;
      }
      if (r.status >= 300) {
        const to = r.h("to");
        this.send(this.build("ACK", uri, { from: `<${this.aor()}>;tag=${c.localTag}`, to, callId: c.callId, cseq, branch, extra: [] }));
      }
      if ((r.status === 401 || r.status === 407) && !auth && this.cfg.password) {
        const ch = r.status === 401 ? r.h("www-authenticate") : r.h("proxy-authenticate");
        auth = `${r.status === 401 ? "Authorization" : "Proxy-Authorization"}: ${this.digest(ch, "INVITE", uri)}`;
        cseq = this.cseq++;
        continue;
      }
      if (r.status >= 300) {
        this.end(`${r.status} ${r.reason}`);
        return r.status;
      }
      // 2xx: dialog established.
      c.remoteTag = param(r.h("to"), "tag");
      c.remoteTarget = (r.h("contact") || "").replace(/^.*<([^>]+)>.*$/, "$1") || uri;
      c.routes = (r.headers["record-route"] || []).slice().reverse();
      c.to = r.h("to");
      await pc.setRemoteDescription({ type: "answer", sdp: r.body });
      c.ack = this.inDialog("ACK", cseq);
      this.send(c.ack);
      c.answered = Date.now();
      this.ui.state("in call");
      this.startStats();
      return r.status;
    }
    return null;
  }

  inDialog(method, cseq, extra = [], body = "") {
    const c = this.call;
    const branch = `z9hG4bK${rnd(14)}`;
    const routes = (c.routes || []).map((r) => `Route: ${r}`);
    const from = c.incoming ? `${c.invite.h("to").replace(/;tag=.*$/, "")};tag=${c.localTag}` : `<${this.aor()}>;tag=${c.localTag}`;
    const to = c.incoming ? c.invite.h("from") : c.to;
    const text = this.build(method, c.remoteTarget, { from, to, callId: c.callId, cseq, branch, extra: [...routes, ...extra], body });
    return text;
  }

  async answer(remoteAudio) {
    const c = this.call;
    if (!c || !c.incoming) return;
    const { pc, stream } = await this.media(remoteAudio);
    Object.assign(c, { pc, stream, started: Date.now() });
    await pc.setRemoteDescription({ type: "offer", sdp: c.invite.body });
    await pc.setLocalDescription(await pc.createAnswer());
    await this.gathered(pc);
    c.remoteTarget = (c.invite.h("contact") || "").replace(/^.*<([^>]+)>.*$/, "$1");
    c.routes = c.invite.headers["record-route"] || [];
    this.reply(c.invite, 200, "OK", { toTag: c.localTag, body: pc.localDescription.sdp });
    c.answered = Date.now();
    this.ui.state("in call");
    this.startStats();
  }

  async hangup() {
    const c = this.call;
    if (!c) return;
    if (c.answered) {
      const text = this.inDialog("BYE", this.cseq++, ['Reason: Q.850;cause=16;text="Normal call clearing"']);
      const branch = text.match(/branch=([^;\r\n]+)/)[1];
      await this.request(text, branch);
      this.end("local");
    } else if (!c.incoming && c.branch) {
      const text = this.build("CANCEL", c.uri, { from: `<${this.aor()}>;tag=${c.localTag}`, to: `<${c.uri}>`, callId: c.callId, cseq: c.cseq, branch: c.branch });
      this.send(text);
    } else if (c.incoming) {
      this.reply(c.invite, 486, "Busy Here", { toTag: c.localTag });
      this.end("rejected");
    }
  }

  dtmf(digits) {
    const s = this.call && this.call.pc && this.call.pc.getSenders().find((x) => x.dtmf);
    if (s && s.dtmf.canInsertDTMF) s.dtmf.insertDTMF(digits, 160, 70);
  }

  startStats() {
    const pc = this.call.pc;
    this.stats = [];
    this.statsTimer = setInterval(async () => {
      if (!pc || pc.connectionState === "closed") return;
      const rep = await pc.getStats();
      const s = { t: Date.now() };
      rep.forEach((r) => {
        if (r.type === "inbound-rtp" && r.kind === "audio") Object.assign(s, { recv: r.packetsReceived, lost: r.packetsLost, jitter_ms: (r.jitter || 0) * 1000, codecId: r.codecId });
        if (r.type === "outbound-rtp" && r.kind === "audio") s.sent = r.packetsSent;
        if (r.type === "candidate-pair" && r.nominated && r.state === "succeeded") Object.assign(s, { rtt_ms: (r.currentRoundTripTime || 0) * 1000, pair: r.id, local: r.localCandidateId, remote: r.remoteCandidateId });
      });
      if (s.codecId) {
        const c = rep.get(s.codecId);
        if (c) s.codec = c.mimeType;
      }
      if (s.local) {
        const l = rep.get(s.local);
        const r = rep.get(s.remote);
        if (l && r) s.path = `${l.candidateType} ${l.address || l.ip}:${l.port} -> ${r.candidateType} ${r.address || r.ip}:${r.port} (${l.protocol})`;
      }
      this.stats.push(s);
      this.ui.stats && this.ui.stats(s);
    }, 1000);
  }

  summary() {
    const s = this.stats;
    if (!s.length) return null;
    const last = s[s.length - 1];
    const lossPct = last.recv ? (100 * (last.lost || 0)) / ((last.recv || 0) + (last.lost || 0)) : 0;
    return {
      codec: last.codec,
      packets_received: last.recv,
      packets_sent: last.sent,
      packets_lost: last.lost,
      loss_pct: +lossPct.toFixed(2),
      max_jitter_ms: +Math.max(...s.map((x) => x.jitter_ms || 0)).toFixed(1),
      max_rtt_ms: +Math.max(...s.map((x) => x.rtt_ms || 0)).toFixed(1),
      ice_path: last.path,
      seconds: s.length,
    };
  }

  end(why) {
    const c = this.call;
    if (!c) return;
    clearInterval(this.statsTimer);
    if (c.pc) c.pc.close();
    if (c.stream) c.stream.getTracks().forEach((t) => t.stop());
    this.call = null;
    this.ui.state(`call ended: ${why}`);
    this.ui.onCallEnded(this, why);
  }

  close() {
    if (this.ws) this.ws.close();
  }

  /// Log in the format expected by `capture_from_sip_log`.
  captureLog() {
    let remote = "192.0.2.20:443";
    try {
      const u = new URL(this.cfg.ws);
      const port = u.port || (u.protocol === "wss:" ? 443 : 80);
      if (/^[\d.]+$/.test(u.hostname)) remote = `${u.hostname}:${port}`;
      else if (u.hostname === "localhost") remote = `127.0.0.1:${port}`;
    } catch { /* keep placeholder */ }
    return { local: "192.0.2.10:50000", remote, note: `SIP over WebSocket ${this.cfg.ws}, logged by the Sidetone web phone (media is WebRTC/DTLS-SRTP, see getStats)`, entries: this.log };
  }
}
