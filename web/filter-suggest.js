// Query helper for the display filters, in the spirit of Grafana's query
// builder: while typing it offers the fields, then the operators, then the
// values seen in the data (with how many messages carry each), then && / ||.

import { FIELDS } from "./filter.js";
import { t } from "./i18n.js";

const FIELD_HELP = {
  "ip.addr": "Source or destination IP",
  "ip.src": "Source IP",
  "ip.dst": "Destination IP",
  port: "Source or destination port",
  "port.src": "Source port",
  "port.dst": "Destination port",
  "udp.port": "Port, SIP over UDP only",
  "tcp.port": "Port, SIP over TCP or TLS only",
  transport: "udp, tcp, tls, wss",
  "sip.method": "INVITE, BYE, REGISTER... (requests and the method in CSeq)",
  "sip.status": "Response code (180, 200, 404...)",
  "sip.code": "Response code (same as sip.status)",
  "sip.request": "Only requests",
  "sip.response": "Only responses",
  "sip.call_id": "Call-ID",
  "sip.cseq": "CSeq",
  "sip.from": "From header",
  "sip.to": "To header",
  "sip.contact": "Contact header",
  "sip.via": "Top Via header",
  "sip.ua": "User-Agent or Server",
  "sip.uri": "Request-URI",
  "sip.ruri": "Request-URI",
  "sip.reason": "Reason header",
  "sip.first_line": "Request or status line",
  sip: "Whole SIP message text",
  sdp: "Whole SDP body",
  "sdp.ip": "Media IP in c=",
  "sdp.port": "Media port in m=",
  "sdp.codec": "Codec in a=rtpmap",
  "sdp.direction": "sendrecv, sendonly, recvonly, inactive",
  frame: "Frame number in the capture",
};
const NUMERIC = new Set(["port", "port.src", "port.dst", "udp.port", "tcp.port", "sip.status", "sip.code", "sdp.port", "frame"]);
const FLAGS = new Set(["sip.request", "sip.response"]);
const NO_VALUES = new Set(["sip", "sdp", "sip.cseq"]);
const OPS = [
  ["==", "equals"],
  ["!=", "is not"],
  ["contains", "contains the text"],
  ["~", "matches a regular expression"],
  [">", "greater than"],
  [">=", "greater or equal"],
  ["<", "less than"],
  ["<=", "less or equal"],
];
const OP_RE = "==|!=|>=|<=|>|<|~|contains|matches|eq|ne";

/// Distinct values of a field across the rows, most frequent first.
function valuesOf(field, rows) {
  const get = FIELDS[field];
  const n = new Map();
  for (const r of rows) {
    let vs;
    try { vs = get(r); } catch { continue; }
    for (const v of new Set(vs)) {
      if (v === "" || v == null || v === false || v === 0) continue;
      const k = String(v);
      if (k.length > 120) continue;
      n.set(k, (n.get(k) || 0) + 1);
    }
  }
  return [...n.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/// What to offer for the text before the caret: [items, start of the part to replace].
function suggestions(prefix, rows) {
  // Value after "field op".
  let m = prefix.match(new RegExp(`([A-Za-z_][\\w.]*)\\s*(${OP_RE})\\s*("?)([^"\\s()]*)$`, "i"));
  if (m && FIELDS[m[1].toLowerCase()]) {
    const field = m[1].toLowerCase();
    if (NO_VALUES.has(field)) return [[], prefix.length];
    const part = m[4].toLowerCase();
    const items = valuesOf(field, rows)
      .filter(([v]) => !part || v.toLowerCase().includes(part))
      .slice(0, 40)
      .map(([v, c]) => ({ label: v, insert: /[\s()&|!=<>~"]/.test(v) || !/^[\w.:@+\-/*]+$/.test(v) ? `"${v.replace(/"/g, "")}"` : v, desc: `${c} ${t(c === 1 ? "message" : "messages")}`, kind: "value" }));
    return [items, prefix.length - m[4].length - m[3].length];
  }
  // Operator after a field.
  m = prefix.match(/([A-Za-z_][\w.]*)\s+([=!<>~a-z]*)$/i);
  if (m && FIELDS[m[1].toLowerCase()] && !/^(and|or|not)$/i.test(m[2])) {
    const field = m[1].toLowerCase();
    const part = m[2].toLowerCase();
    const ops = OPS.filter(([o]) => (NUMERIC.has(field) || !/^[<>]/.test(o)) && (!part || o.startsWith(part)));
    const items = ops.map(([o, d]) => ({ label: o, insert: o, desc: t(d), kind: "op" }));
    if (!part) items.push({ label: "&&", insert: "&&", desc: t("and: both conditions"), kind: "join" }, { label: "||", insert: "||", desc: t("or: either condition"), kind: "join" });
    return [items, prefix.length - m[2].length];
  }
  // A field (or a joiner after a finished condition).
  const word = (prefix.match(/[\w.]*$/) || [""])[0];
  const before = prefix.slice(0, prefix.length - word.length).trimEnd();
  const afterCond = before && !/(&&|\|\||[(!]|\b(and|or|not))$/i.test(before) && !new RegExp(`(${OP_RE})$`, "i").test(before);
  const items = [];
  if (afterCond && !word) {
    items.push({ label: "&&", insert: "&&", desc: t("and: both conditions"), kind: "join" }, { label: "||", insert: "||", desc: t("or: either condition"), kind: "join" });
  }
  const w = word.toLowerCase();
  if (!afterCond || word) {
    for (const f of Object.keys(FIELDS)) {
      if (w && !f.includes(w)) continue;
      items.push({ label: f, insert: f, desc: t(FIELD_HELP[f] || ""), kind: "field" });
    }
    if (!w) items.push({ label: "!", insert: "!", desc: t("not: the opposite of the next condition"), kind: "join" }, { label: "( )", insert: "(", desc: t("group conditions"), kind: "join" });
  }
  return [items, prefix.length - word.length];
}

/// Attaches the helper to a filter input. getRows() gives the messages to draw values from.
export function attachSuggest(input, getRows) {
  input.removeAttribute("list");
  const box = document.createElement("div");
  box.className = "fsuggest";
  box.hidden = true;
  box.setAttribute("role", "listbox");
  input.parentElement.style.position ||= "relative";
  input.insertAdjacentElement("afterend", box);
  let items = [];
  let start = 0;
  let active = 0;

  const close = () => {
    box.hidden = true;
    items = [];
  };
  const render = () => {
    if (!items.length) return close();
    box.innerHTML = items
      .map((it, i) => `<div class="fs-item${i === active ? " on" : ""} fs-${it.kind}" data-i="${i}" role="option"><span class="fs-l">${esc(it.label)}</span><span class="fs-d">${esc(it.desc)}</span></div>`)
      .join("");
    box.style.left = `${input.offsetLeft}px`;
    box.style.top = `${input.offsetTop + input.offsetHeight + 2}px`;
    box.style.minWidth = `${Math.max(260, input.offsetWidth)}px`;
    box.hidden = false;
    const on = box.querySelector(".on");
    if (on) on.scrollIntoView({ block: "nearest" });
  };
  const update = () => {
    const caret = input.selectionStart ?? input.value.length;
    [items, start] = suggestions(input.value.slice(0, caret), getRows() || []);
    active = 0;
    render();
  };
  const accept = (it) => {
    const caret = input.selectionStart ?? input.value.length;
    const after = input.value.slice(caret).replace(/^[^\s()]*/, "");
    const ins = it.insert === "(" ? "(" : `${it.insert} `;
    input.value = input.value.slice(0, start) + ins + after.replace(/^\s+/, "");
    const pos = start + ins.length;
    input.setSelectionRange(pos, pos);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    update();
  };

  input.addEventListener("input", update);
  input.addEventListener("focus", update);
  input.addEventListener("click", update);
  input.addEventListener("blur", () => setTimeout(close, 150));
  input.addEventListener("keydown", (e) => {
    if (box.hidden) {
      if (e.key === "ArrowDown") {
        update();
        e.preventDefault();
      }
      return;
    }
    if (e.key === "ArrowDown") active = Math.min(items.length - 1, active + 1);
    else if (e.key === "ArrowUp") active = Math.max(0, active - 1);
    else if (e.key === "Tab" || (e.key === "Enter" && items[active])) {
      accept(items[active]);
    } else if (e.key === "Escape") {
      close();
      return;
    } else return;
    e.preventDefault();
    if (!box.hidden) render();
  });
  box.addEventListener("mousedown", (e) => {
    const el = e.target.closest("[data-i]");
    if (!el) return;
    e.preventDefault();
    accept(items[+el.dataset.i]);
  });
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
