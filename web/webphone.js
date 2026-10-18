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

export function parse(text) {
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
    // ui hooks get the call they are about: progress(c, r), ice(c, s), stats(c, s),
    // onIncoming(c, from, m), onNotify(c, frag), onDtmf(c, d), onCallEnded(phone, why, c)
    this.ui = ui;
    this.log = [];
    this.pending = new Map(); // branch -> {resolve, onProvisional}
    this.host = `${rnd(12)}.invalid`;
    this.regCallId = rnd(20);
    this.regTag = rnd(8);
    this.cseq = 1;
    this.nc = 0;
    this.calls = new Map(); // Call-ID -> call
  }

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.cfg.ws, "sip");
      this.ws = ws;
      const t = setTimeout(() => reject(new Error(`WebSocket ${this.cfg.ws} did not open in 8 s`)), 8000);
      ws.onopen = () => {
        clearTimeout(t);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(t);
        reject(new Error(`WebSocket ${this.cfg.ws} failed (wrong URL, certificate not trusted, or the server rejected the "sip" subprotocol / Origin)`));
      };
      ws.onclose = (e) => this.ui.closed && this.ui.closed(e.code);
      ws.onmessage = (e) => this.onMessage(typeof e.data === "string" ? e.data : new TextDecoder().decode(e.data));
    });
  }

  send(text) {
    const e = { t_ms: performance.timeOrigin + performance.now(), out: true, text };
    this.log.push(e);
    this.ui.trace && this.ui.trace(e);
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
      `CSeq: ${cseq} ${method}`,
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

  /// Sends an in-dialog request and repeats it once with credentials when challenged.
  async requestAuth(c, method, extra = [], body = "") {
    let auth = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const text = this.inDialog(c, method, this.cseq++, auth ? [...extra, auth] : extra, body);
      const branch = text.match(/branch=([^;\r\n]+)/)[1];
      const r = await this.request(text, branch);
      if (r && (r.status === 401 || r.status === 407) && !auth && this.cfg.password) {
        const ch = r.status === 401 ? r.h("www-authenticate") : r.h("proxy-authenticate");
        auth = `${r.status === 401 ? "Authorization" : "Proxy-Authorization"}: ${this.digest(ch, method, c.remoteTarget)}`;
        continue;
      }
      return { r, text, branch };
    }
    return { r: null };
  }

  onMessage(text) {
    if (!text.trim()) return; // keepalive
    const e = { t_ms: performance.timeOrigin + performance.now(), out: false, text };
    this.log.push(e);
    this.ui.trace && this.ui.trace(e);
    const m = parse(text);
    if (m.status) {
      const p = this.pending.get(m.branch);
      if (!p) {
        const c = this.calls.get(m.h("call-id"));
        if (m.status >= 200 && m.cseq.endsWith("INVITE") && c && c.ack) this.send(c.ack); // 2xx retransmission
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
    const c = this.calls.get(m.h("call-id"));
    switch (m.method) {
      case "OPTIONS":
        this.reply(m, 200, "OK");
        break;
      case "BYE":
        this.reply(m, c ? 200 : 481, c ? "OK" : "Call/Transaction Does Not Exist");
        if (c) this.end(c, "remote");
        break;
      case "CANCEL":
        this.reply(m, 200, "OK");
        if (c && c.incoming && !c.answered) {
          this.reply(c.invite, 487, "Request Terminated", { toTag: c.localTag });
          this.end(c, "remote cancel");
        }
        break;
      case "INVITE":
        if (c) {
          this.reinvited(c, m);
          return;
        }
        if (this.calls.size >= (this.maxLines || 4)) {
          this.reply(m, 486, "Busy Here", { toTag: rnd(8) });
          return;
        }
        {
          const nc = { incoming: true, invite: m, callId: m.h("call-id"), localTag: rnd(8), started: Date.now() };
          this.calls.set(nc.callId, nc);
          this.reply(m, 180, "Ringing", { toTag: nc.localTag });
          this.ui.onIncoming(nc, m.h("from"), m);
        }
        break;
      case "ACK":
        if (c) c.acked = true;
        break;
      case "NOTIFY":
        this.reply(m, 200, "OK");
        if (c && /refer/i.test(m.h("event") || "") && this.ui.onNotify) this.ui.onNotify(c, m.body.split("\r\n")[0] || m.body);
        break;
      case "INFO": {
        this.reply(m, 200, "OK");
        const d = (m.body.match(/Signal\s*=\s*(\S)/) || [])[1];
        if (c && d && this.ui.onDtmf) this.ui.onDtmf(c, d);
        break;
      }
      case "UPDATE":
      case "MESSAGE":
        this.reply(m, 200, "OK");
        break;
      default:
        this.reply(m, 405, "Method Not Allowed");
    }
  }

  /// re-INVITE from the far end (hold, codec change, session refresh).
  async reinvited(c, m) {
    if (!c.pc) {
      this.reply(m, 491, "Request Pending", { toTag: c.localTag });
      return;
    }
    try {
      if (m.body) {
        await c.pc.setRemoteDescription({ type: "offer", sdp: m.body });
        await c.pc.setLocalDescription(await c.pc.createAnswer());
        c.remoteHeld = /a=(sendonly|inactive)/.test(m.body);
        this.ui.progress && this.ui.progress(c, { status: 0, remoteHold: c.remoteHeld });
      }
      this.reply(m, 200, "OK", { toTag: c.localTag, body: c.pc.localDescription.sdp });
    } catch {
      this.reply(m, 488, "Not Acceptable Here", { toTag: c.localTag });
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
      if (r.status >= 200 && r.status < 300) {
        const mine = (r.headers["contact"] || []).find((c) => c.includes(this.host));
        this.granted = +(param(mine, "expires") || r.h("expires") || expires);
        const via = r.h("via") || "";
        const rcv = param(via, "received");
        const rport = param(via, "rport");
        this.publicAddr = rcv ? `${rcv}${rport ? ":" + rport : ""}` : null;
      }
      this.lastReg = { status: r.status, reason: r.reason };
      return r.status;
    }
    return null;
  }

  async options(target) {
    const uri = target ? this.targetUri(target) : `sip:${this.cfg.domain}`;
    const branch = `z9hG4bK${rnd(14)}`;
    const t = performance.now();
    const text = this.build("OPTIONS", uri, { from: `<${this.aor()}>;tag=${rnd(8)}`, to: `<${uri}>`, callId: rnd(20), cseq: 1, branch, extra: ["Accept: application/sdp"] });
    const r = await this.request(text, branch);
    return r ? { code: r.status, rtt_ms: Math.round(performance.now() - t), summary: `${r.status} ${r.reason} in ${Math.round(performance.now() - t)} ms${r.h("user-agent") || r.h("server") ? ", " + (r.h("user-agent") || r.h("server")) : ""}` } : null;
  }

  async reinvite(c, direction) {
    if (!c || !c.answered || !c.pc) return null;
    c.pc.getTransceivers().forEach((t) => {
      if (t.receiver.track && t.receiver.track.kind === "audio") t.direction = direction;
    });
    await c.pc.setLocalDescription(await c.pc.createOffer());
    await this.gathered(c.pc);
    const { r, text, branch } = await this.requestAuth(c, "INVITE", [], c.pc.localDescription.sdp);
    const cseq = text ? +text.match(/\r\nCSeq: (\d+)/)[1] : 0;
    if (r && r.status >= 200 && r.status < 300) {
      await c.pc.setRemoteDescription({ type: "answer", sdp: r.body });
      c.ack = this.inDialog(c, "ACK", cseq);
      this.send(c.ack);
      return r.status;
    }
    if (r && r.status >= 300) this.send(this.inDialog(c, "ACK", cseq).replace(/branch=[^;\r\n]+/, `branch=${branch}`));
    await c.pc.setLocalDescription({ type: "rollback" }).catch(() => {});
    return r ? r.status : null;
  }

  async hold(c, on) {
    const st = await this.reinvite(c, on ? "sendonly" : "sendrecv");
    if (st >= 200 && st < 300) {
      c.held = on;
      // A held call is not heard locally either.
      if (c.audio) c.audio.muted = on;
    }
    return st;
  }

  mute(c, on) {
    if (!c) return;
    c.muted = on;
    if (c.micGain) c.micGain.gain.value = on ? 0 : 1;
  }

  async refer(c, target, replaces) {
    if (!c || !c.answered) return null;
    let uri = this.targetUri(target);
    if (replaces) {
      // Attended transfer (RFC 3891): the target replaces our call with it.
      // to-tag is the far end's tag of that dialog, from-tag ours, whoever called whom.
      const r = replaces;
      const toTag = r.remoteTag || (r.incoming ? param(r.invite.h("from"), "tag") : param(r.to, "tag"));
      const rep = encodeURIComponent(`${r.callId};to-tag=${toTag};from-tag=${r.localTag}`);
      const party = r.incoming ? (r.invite.h("from").match(/<([^>]+)>/) || [, r.invite.h("from")])[1] : r.uri;
      uri = `${party.replace(/;.*$/, "")}?Replaces=${rep}`;
    }
    const { r } = await this.requestAuth(c, "REFER", [`Refer-To: <${uri}>`, `Referred-By: <${this.aor()}>`]);
    return r ? r.status : null;
  }

  reject(c, code = 486, reason = "Busy Here") {
    if (!c || !c.incoming || c.answered) return;
    this.reply(c.invite, code, reason, { toTag: c.localTag });
    this.end(c, `rejected with ${code}`);
  }

  audioCtx() {
    if (!this.ctx) this.ctx = new AudioContext();
    if (this.ctx.state === "suspended") this.ctx.resume().catch(() => {});
    return this.ctx;
  }

  /// One microphone for every call; each call sends mic + whatever is
  /// mixed into it (the other party during a conference).
  async media(c) {
    const pc = new RTCPeerConnection({ iceServers: this.cfg.iceServers || [] });
    if (!this.mic) this.mic = await navigator.mediaDevices.getUserMedia({ audio: true });
    const ctx = this.audioCtx();
    const out = ctx.createMediaStreamDestination();
    const micGain = ctx.createGain();
    if (!this.micSrc) this.micSrc = ctx.createMediaStreamSource(this.mic);
    this.micSrc.connect(micGain);
    micGain.connect(out);
    const track = out.stream.getAudioTracks()[0];
    pc.addTrack(track, out.stream);
    const audio = new Audio();
    audio.autoplay = true;
    pc.ontrack = (e) => {
      c.remoteStream = e.streams[0];
      audio.srcObject = e.streams[0];
      audio.play().catch(() => {});
    };
    pc.oniceconnectionstatechange = () => this.ui.ice && this.ui.ice(c, pc.iceConnectionState);
    Object.assign(c, { pc, out, micGain, audio });
    return pc;
  }

  /// Three-way conference in the browser: each side also hears the other.
  conference(a, b, on) {
    const ctx = this.audioCtx();
    const link = (from, to) => {
      if (!from.remoteStream) return null;
      const src = ctx.createMediaStreamSource(from.remoteStream);
      src.connect(to.out);
      return src;
    };
    for (const c of [a, b]) {
      (c.confLinks || []).forEach((n) => n.disconnect());
      c.confLinks = [];
      c.conference = null;
    }
    if (!on) return true;
    const ab = link(a, b);
    const ba = link(b, a);
    if (!ab || !ba) return false;
    b.confLinks.push(ab);
    a.confLinks.push(ba);
    a.conference = b.callId;
    b.conference = a.callId;
    return true;
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

  /// Starts a call; `created(c)` runs as soon as the call (and its Call-ID) exists.
  async dial(target, created) {
    const uri = this.targetUri(target);
    const c = { incoming: false, callId: rnd(20), localTag: rnd(8), uri, started: Date.now() };
    this.calls.set(c.callId, c);
    created && created(c);
    let pc;
    try {
      pc = await this.media(c);
      await pc.setLocalDescription(await pc.createOffer());
      await this.gathered(pc);
    } catch (e) {
      this.end(c, `microphone or WebRTC failed: ${e.message || e}`);
      throw e;
    }
    if (c.ended) return null;
    let auth = null;
    let cseq = this.cseq++;
    for (let attempt = 0; attempt < 2; attempt++) {
      const branch = `z9hG4bK${rnd(14)}`;
      c.branch = branch;
      c.cseq = cseq;
      const extra = ["Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, REFER, NOTIFY", "Supported: replaces, ice"];
      if (auth) extra.push(auth);
      const text = this.build("INVITE", uri, { from: `<${this.aor()}>;tag=${c.localTag}`, to: `<${uri}>`, callId: c.callId, cseq, branch, extra, body: pc.localDescription.sdp });
      c.inviteText = text;
      const r = await this.request(text, branch, (p) => {
        c.provisional = p.status;
        if (p.status > 100) c.ringing = true;
        this.ui.progress && this.ui.progress(c, p);
      });
      if (!r) {
        this.end(c, "no answer (timeout)");
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
        c.final = r.status;
        this.end(c, `${r.status} ${r.reason}`);
        return r.status;
      }
      // 2xx: dialog established.
      c.remoteTag = param(r.h("to"), "tag");
      c.remoteTarget = (r.h("contact") || "").replace(/^.*<([^>]+)>.*$/, "$1") || uri;
      c.routes = (r.headers["record-route"] || []).slice().reverse();
      c.to = r.h("to");
      await pc.setRemoteDescription({ type: "answer", sdp: r.body });
      c.ack = this.inDialog(c, "ACK", cseq);
      this.send(c.ack);
      c.answered = Date.now();
      c.final = r.status;
      this.ui.progress && this.ui.progress(c, r);
      this.startStats(c);
      if (c.ended) return r.status;
      return r.status;
    }
    return null;
  }

  inDialog(c, method, cseq, extra = [], body = "") {
    const branch = `z9hG4bK${rnd(14)}`;
    const routes = (c.routes || []).map((r) => `Route: ${r}`);
    const from = c.incoming ? `${c.invite.h("to").replace(/;tag=.*$/, "")};tag=${c.localTag}` : `<${this.aor()}>;tag=${c.localTag}`;
    const to = c.incoming ? c.invite.h("from") : c.to;
    return this.build(method, c.remoteTarget, { from, to, callId: c.callId, cseq, branch, extra: [...routes, ...extra], body });
  }

  async answer(c) {
    if (!c || !c.incoming || c.answered) return;
    const pc = await this.media(c);
    c.started = Date.now();
    await pc.setRemoteDescription({ type: "offer", sdp: c.invite.body });
    await pc.setLocalDescription(await pc.createAnswer());
    await this.gathered(pc);
    c.remoteTarget = (c.invite.h("contact") || "").replace(/^.*<([^>]+)>.*$/, "$1");
    c.routes = c.invite.headers["record-route"] || [];
    c.remoteTag = param(c.invite.h("from"), "tag");
    this.reply(c.invite, 200, "OK", { toTag: c.localTag, body: pc.localDescription.sdp });
    c.answered = Date.now();
    c.final = 200;
    this.ui.progress && this.ui.progress(c, { status: 200, reason: "OK" });
    this.startStats(c);
  }

  async hangup(c) {
    if (!c || c.ended) return;
    if (c.answered) {
      const text = this.inDialog(c, "BYE", this.cseq++, ['Reason: Q.850;cause=16;text="Normal call clearing"']);
      const branch = text.match(/branch=([^;\r\n]+)/)[1];
      this.end(c, "local");
      await this.request(text, branch);
    } else if (!c.incoming && c.branch) {
      this.send(this.build("CANCEL", c.uri, { from: `<${this.aor()}>;tag=${c.localTag}`, to: `<${c.uri}>`, callId: c.callId, cseq: c.cseq, branch: c.branch }));
    } else if (!c.incoming) {
      this.end(c, "cancelled before the INVITE");
    } else {
      this.reject(c, 603, "Decline");
    }
  }

  dtmf(c, digits) {
    const s = c && c.pc && c.pc.getSenders().find((x) => x.dtmf);
    if (s && s.dtmf.canInsertDTMF) s.dtmf.insertDTMF(digits, 160, 70);
  }

  startStats(c) {
    const pc = c.pc;
    c.stats = [];
    c.statsTimer = setInterval(async () => {
      if (!pc || pc.connectionState === "closed") return;
      const rep = await pc.getStats();
      const s = { t: Date.now() };
      rep.forEach((r) => {
        if (r.type === "inbound-rtp" && r.kind === "audio") Object.assign(s, { recv: r.packetsReceived, lost: r.packetsLost, jitter_ms: (r.jitter || 0) * 1000, codecId: r.codecId, rx_level: r.audioLevel });
        if (r.type === "outbound-rtp" && r.kind === "audio") s.sent = r.packetsSent;
        if (r.type === "media-source" && r.kind === "audio") s.tx_level = r.audioLevel;
        if (r.type === "candidate-pair" && r.nominated && r.state === "succeeded") Object.assign(s, { rtt_ms: (r.currentRoundTripTime || 0) * 1000, pair: r.id, local: r.localCandidateId, remote: r.remoteCandidateId });
      });
      if (s.codecId) {
        const cd = rep.get(s.codecId);
        if (cd) s.codec = cd.mimeType;
      }
      if (s.local) {
        const l = rep.get(s.local);
        const r = rep.get(s.remote);
        if (l && r) s.path = `${l.candidateType} ${l.address || l.ip}:${l.port} -> ${r.candidateType} ${r.address || r.ip}:${r.port} (${l.protocol})`;
      }
      c.stats.push(s);
      this.ui.stats && this.ui.stats(c, s);
    }, 1000);
  }

  summary(c) {
    const s = (c && c.stats) || [];
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

  end(c, why) {
    if (!c || c.ended) return;
    c.ended = true;
    clearInterval(c.statsTimer);
    if (c.conference) {
      const o = this.calls.get(c.conference);
      if (o) this.conference(c, o, false);
    }
    if (c.pc) c.pc.close();
    if (c.micGain) c.micGain.disconnect();
    if (c.audio) c.audio.srcObject = null;
    this.calls.delete(c.callId);
    if (!this.calls.size && this.mic) {
      // Release the microphone when no call is left.
      this.mic.getTracks().forEach((t) => t.stop());
      if (this.micSrc) this.micSrc.disconnect();
      this.mic = null;
      this.micSrc = null;
    }
    this.ui.onCallEnded(this, why, c);
  }

  close() {
    for (const c of [...this.calls.values()]) this.end(c, "account closed");
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
