// Browser phone against the Asterisk lab: two calls with automatic hold, a
// conference, call waiting and an attended transfer. Needs a running
// `sidetone serve` whose native account "1" is 2001 (see readme-shots.mjs).
//   node scripts/web-multiline-test.mjs http://127.0.0.1:8640
import puppeteer from "puppeteer-core";
const base = process.argv[2];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const api = async (path, body) => (await fetch(base + path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {})).json();
const b = await puppeteer.launch({ executablePath: process.env.CHROME_PATH, headless: true, args: ["--no-sandbox", "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", "--autoplay-policy=no-user-gesture-required"], defaultViewport: { width: 1440, height: 900 } });
const p = await b.newPage();
p.on("pageerror", (e) => console.log("pageerror:", e.message));
p.on("console", (m) => { if (m.type() === "error") console.log("console:", m.text()); });
await p.goto(base + "/?phone=web&page=calls", { waitUntil: "load" }); await wait(1500);
await p.evaluate(async () => {
  await window.__sidetone.ctl.setConfig({ accounts: [{ id: "w1", label: "WebRTC 4001", enabled: true, register: true, user: "4001", authUser: "", password: "secret4001", displayName: "", domain: "127.0.0.1", ws: "ws://127.0.0.1:8088/ws", ice: "", expires: 300 }] });
});
await wait(2500);
const ctl = (o) => p.evaluate((o) => window.__sidetone.ctl.cmd(o).then((r) => r, (e) => ({ error: e.message })), o);
const lines = () => p.evaluate(() => window.__sidetone.ctl.snapshot().calls.map((l) => ({ line: l.line, state: l.state, held: l.held, conf: l.conference, remote: l.remote, rx: l.rx_level, recv: l.rtp_received })));
const until = async (what, f, ms = 10000) => {
  const t = Date.now();
  while (Date.now() - t < ms) { const ls = await lines(); if (f(ls)) { console.log("ok:", what); return ls; } await wait(250); }
  console.log("FAIL:", what, JSON.stringify(await lines())); process.exitCode = 1; return null;
};
const r1 = await ctl({ cmd: "call", target: "600" });
await until("L1 600 connected", (ls) => ls.find((l) => l.line === r1.line)?.state === "connected");
const r2 = await ctl({ cmd: "call", target: "600" });
await until("L2 connected and L1 auto-held", (ls) => ls.find((l) => l.line === r2.line)?.state === "connected" && ls.find((l) => l.line === r1.line)?.held);
const c = await ctl({ cmd: "conference", line: r2.line, to_line: r1.line, on: true });
if (c && c.error) console.log("conference error:", c.error);
await until("conference joined, both resumed", (ls) => { const a = ls.find((l) => l.line === r1.line), bb = ls.find((l) => l.line === r2.line); return a.conf === r2.line && bb.conf === r1.line && !a.held && !bb.held; });
await p.screenshot({ path: "/tmp/claude-0/shots/out/web-conf.png" });
await ctl({ cmd: "conference", line: r2.line, to_line: r1.line, on: false });
await ctl({ cmd: "hangup_all" });
await until("all ended", (ls) => ls.every((l) => l.state === "ended"));
// Call waiting: web talks to 600, native 2001 calls 800 (rings 4001).
const r3 = await ctl({ cmd: "call", target: "600" });
await until("L3 connected", (ls) => ls.find((l) => l.line === r3.line)?.state === "connected");
const n = await api("/api/phone/cmd", { cmd: "call", account: "1", target: "800" });
const inc = await until("call waiting rings", (ls) => ls.some((l) => l.state === "incoming"));
const li = inc && inc.find((l) => l.state === "incoming").line;
await ctl({ cmd: "answer", line: li });
await until("answered, 600 held", (ls) => ls.find((l) => l.line === li)?.state === "connected" && ls.find((l) => l.line === r3.line)?.held);
// Attended transfer: join 2001 with the echo service.
await ctl({ cmd: "attended_transfer", line: r3.line, to_line: li });
await until("browser lines released after the transfer", (ls) => ls.every((l) => l.state === "ended"), 12000);
const st = await api("/api/phone/state");
const nat = st.state.calls.find((x) => x.line === n.line);
console.log("native 2001 after transfer:", nat && nat.state, nat && nat.remote);
await api("/api/phone/cmd", { cmd: "hangup_all" });
await b.close();
