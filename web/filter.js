// Display filters in the spirit of Wireshark, for SIP messages.
//
//   ip.addr == 10.0.0.5 && sip.method == INVITE
//   sip.status >= 400 || sip.from contains "2001"
//   !(sip.method == OPTIONS) and port == 5060
//   sdp.ip == 192.168.1.50      sdp.codec == PCMA      "Busy Here"
//
// A bare word or a quoted string searches the whole message text.

export const FIELDS = {
  "ip.addr": (r) => [host(r.src), host(r.dst)],
  "ip.src": (r) => [host(r.src)],
  "ip.dst": (r) => [host(r.dst)],
  port: (r) => [port(r.src), port(r.dst)],
  "port.src": (r) => [port(r.src)],
  "port.dst": (r) => [port(r.dst)],
  "udp.port": (r) => (/udp/i.test(r.transport) ? [port(r.src), port(r.dst)] : []),
  "tcp.port": (r) => (/tcp|tls/i.test(r.transport) ? [port(r.src), port(r.dst)] : []),
  transport: (r) => [String(r.transport || "").toLowerCase()],
  "sip.method": (r) => [r.method || ""],
  "sip.status": (r) => (r.status ? [r.status] : []),
  "sip.code": (r) => (r.status ? [r.status] : []),
  "sip.request": (r) => [!r.status],
  "sip.response": (r) => [!!r.status],
  "sip.call_id": (r) => [r.call_id || ""],
  "sip.cseq": (r) => [r.cseq || ""],
  "sip.from": (r) => [hdr(r.raw, "From|f")],
  "sip.to": (r) => [hdr(r.raw, "To|t")],
  "sip.contact": (r) => [hdr(r.raw, "Contact|m")],
  "sip.via": (r) => [hdr(r.raw, "Via|v")],
  "sip.ua": (r) => [hdr(r.raw, "User-Agent") || hdr(r.raw, "Server")],
  "sip.uri": (r) => [r.status ? "" : (r.raw.split(/\r?\n/)[0] || "").split(" ")[1] || ""],
  "sip.ruri": (r) => [r.status ? "" : (r.raw.split(/\r?\n/)[0] || "").split(" ")[1] || ""],
  "sip.reason": (r) => [hdr(r.raw, "Reason")],
  "sip.first_line": (r) => [r.raw.split(/\r?\n/)[0] || ""],
  sip: (r) => [r.raw],
  sdp: (r) => [body(r.raw)],
  "sdp.ip": (r) => [...body(r.raw).matchAll(/^c=IN IP[46] (\S+)/gm)].map((m) => m[1]),
  "sdp.port": (r) => [...body(r.raw).matchAll(/^m=\w+ (\d+)/gm)].map((m) => +m[1]),
  "sdp.codec": (r) => [...body(r.raw).matchAll(/^a=rtpmap:\d+ ([^/\s]+)/gm)].map((m) => m[1]),
  "sdp.direction": (r) => [...body(r.raw).matchAll(/^a=(sendrecv|sendonly|recvonly|inactive)\s*$/gm)].map((m) => m[1]),
  frame: (r) => (r.frame != null ? [r.frame] : []),
};

export const FIELD_NAMES = Object.keys(FIELDS);

const host = (a) => (a || "").replace(/^\[/, "").replace(/\](:\d+)?$/, "").replace(/:\d+$/, "");
const port = (a) => +((a || "").match(/:(\d+)$/) || [])[1] || 0;
const hdr = (raw, name) => ((raw.match(new RegExp(`^(?:${name}):[ \\t]*(.*)$`, "mi")) || [])[1] || "").trim();
const body = (raw) => {
  const i = raw.search(/\r?\n\r?\n/);
  return i >= 0 ? raw.slice(i).trim() : "";
};

function lex(src) {
  const out = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    const two = src.slice(i, i + 2);
    if (["==", "!=", ">=", "<=", "&&", "||"].includes(two)) { out.push({ t: "op", v: two }); i += 2; continue; }
    if ("()!<>~".includes(c)) { out.push({ t: "op", v: c }); i++; continue; }
    if (c === '"' || c === "'") {
      const j = src.indexOf(c, i + 1);
      if (j < 0) throw new Error("unclosed quote");
      out.push({ t: "str", v: src.slice(i + 1, j) });
      i = j + 1;
      continue;
    }
    const m = src.slice(i).match(/^[^\s()!<>=~&|"']+/);
    if (!m) throw new Error(`unexpected "${c}"`);
    const w = m[0];
    const lw = w.toLowerCase();
    if (lw === "and") out.push({ t: "op", v: "&&" });
    else if (lw === "or") out.push({ t: "op", v: "||" });
    else if (lw === "not") out.push({ t: "op", v: "!" });
    else if (lw === "contains" || lw === "matches") out.push({ t: "op", v: lw === "matches" ? "~" : "contains" });
    else if (lw === "eq") out.push({ t: "op", v: "==" });
    else if (lw === "ne") out.push({ t: "op", v: "!=" });
    else out.push({ t: "word", v: w });
    i += w.length;
  }
  return out;
}

function parse(tokens) {
  let p = 0;
  const peek = () => tokens[p];
  const eat = (v) => {
    if (peek() && peek().t === "op" && peek().v === v) { p++; return true; }
    return false;
  };
  const orExpr = () => {
    let a = andExpr();
    while (eat("||")) { const l = a, r = andExpr(); a = (x) => l(x) || r(x); }
    return a;
  };
  const andExpr = () => {
    let a = notExpr();
    for (;;) {
      if (eat("&&")) { const l = a, r = notExpr(); a = (x) => l(x) && r(x); continue; }
      // Juxtaposition means "and", like typing several words.
      const n = peek();
      if (n && (n.t !== "op" || n.v === "(" || n.v === "!")) { const l = a, r = notExpr(); a = (x) => l(x) && r(x); continue; }
      return a;
    }
  };
  const notExpr = () => {
    if (eat("!")) { const e = notExpr(); return (x) => !e(x); }
    return atom();
  };
  const atom = () => {
    if (eat("(")) {
      const e = orExpr();
      if (!eat(")")) throw new Error("missing )");
      return e;
    }
    const tok = tokens[p++];
    if (!tok) throw new Error("incomplete filter");
    if (tok.t === "str") {
      const s = tok.v.toLowerCase();
      return (r) => r.raw.toLowerCase().includes(s);
    }
    if (tok.t !== "word") throw new Error(`unexpected "${tok.v}"`);
    const name = tok.v.toLowerCase();
    const get = FIELDS[name];
    const op = peek() && peek().t === "op" && ["==", "!=", ">", "<", ">=", "<=", "contains", "~"].includes(peek().v) ? tokens[p++].v : null;
    if (!get) {
      if (op) throw new Error(`unknown field "${tok.v}"`);
      // A plain word: search the message text.
      const s = tok.v.toLowerCase();
      return (r) => r.raw.toLowerCase().includes(s);
    }
    if (!op) return (r) => get(r).some((v) => v !== "" && v !== false && v != null);
    const vt = tokens[p++];
    if (!vt || (vt.t !== "word" && vt.t !== "str")) throw new Error(`value missing after ${op}`);
    const want = vt.v;
    const num = Number(want);
    const isNum = want !== "" && !Number.isNaN(num);
    const re = op === "~" ? new RegExp(want, "i") : null;
    const cmp = (v) => {
      if (op === "contains") return String(v).toLowerCase().includes(want.toLowerCase());
      if (op === "~") return re.test(String(v));
      if (isNum && typeof v === "number") {
        return { "==": v === num, "!=": v !== num, ">": v > num, "<": v < num, ">=": v >= num, "<=": v <= num }[op];
      }
      const a = String(v).toLowerCase(), b = want.toLowerCase();
      return { "==": a === b, "!=": a !== b, ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b }[op];
    };
    // "!=" means none of the values matches, like Wireshark's "!(x == y)".
    if (op === "!=") return (r) => !get(r).some((v) => !cmp(v));
    return (r) => get(r).some(cmp);
  };
  const e = orExpr();
  if (p < tokens.length) throw new Error(`unexpected "${tokens[p].v}"`);
  return e;
}

/// Compiles a filter; returns {fn} or {error}. An empty filter matches everything.
export function compileFilter(src) {
  const s = (src || "").trim();
  if (!s) return { fn: null };
  try {
    return { fn: parse(lex(s)) };
  } catch (e) {
    return { error: e.message };
  }
}
