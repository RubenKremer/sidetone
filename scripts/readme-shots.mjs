// Captures the README screenshots from a running Sidetone and the Asterisk lab.
//
//   ./lab/run-asterisk.sh /tmp/lab
//   SIDETONE_CONFIG_DIR=$(mktemp -d) sidetone serve --listen 127.0.0.1:8640 --no-token &
//   CHROME_PATH=/path/to/chrome node scripts/readme-shots.mjs http://127.0.0.1:8640 docs/images
//
// Needs `npm i puppeteer-core`. Use an empty config dir: the script replaces
// the accounts with the lab ones (2001, 3001 over UDP, 4001 over WebSocket).
// Screenshots are PNG; convert to JPEG for the README.
import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";

const [, , base = "http://127.0.0.1:8640", out = "docs/images"] = process.argv;
mkdirSync(out, { recursive: true });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH,
  headless: true,
  args: ["--no-sandbox", "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", "--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"],
  defaultViewport: { width: 1440, height: 900 },
});

const api = async (path, body) => {
  const r = await fetch(base + path, body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
};

async function shot(name, { dark = false, url = "/", steps = async () => {} } = {}) {
  const p = await browser.newPage();
  await p.emulateMediaFeatures([{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }]);
  // The phone polls the engine, so the network never goes idle: wait for load instead.
  await p.goto(base + url, { waitUntil: "load" });
  await wait(1500);
  await steps(p);
  await wait(700);
  await p.screenshot({ path: `${out}/${name}.png` });
  await p.close();
  console.log("captured", name);
}

const selectCall = (p, pred) =>
  p.evaluate((src) => {
    const S = window.__sidetone;
    const i = S.report.calls.findIndex(new Function("c", `return ${src}`));
    document.querySelector(`#calls button[data-call="${i}"]`).click();
  }, pred);
const tab = (p, t) => p.click(`[data-tab="${t}"]`);

// ---- lab accounts on the native engine
const lab = (id, label, user, pass) => ({
  id, label, enabled: true, register: true, retry_s: 30,
  profile: { name: "", account: { user, auth_user: null, password: pass, domain: "127.0.0.1:5070", display_name: label, outbound_proxy: null, expires: 300, q_value: null } },
});
const cfg = await api("/api/phone/config");
const behavior = cfg.accounts[0]?.profile?.behavior;
const accounts = [lab("1", "Lab 2001", "2001", "secret2001"), lab("2", "Lab 3001", "3001", "secret3001")];
if (behavior) accounts.forEach((a) => (a.profile.behavior = behavior));
// No sound card on a CI or headless machine: calls send a test tone.
await api("/api/phone/config", { accounts, settings: { ...cfg.settings, audio_source: "tone", auto_hold: false, record_calls: false }, audio: { enabled: false } });
await api("/api/phone/history/clear", {});
await wait(1500);

// ---- analysis
await shot("sidetone-hero", { url: "/?sample=demo", steps: async (p) => { await wait(800); await selectCall(p, "c.call_id.startsWith('nat-')"); } });
await shot("sidetone-message", {
  dark: true,
  url: "/?sample=demo",
  steps: async (p) => {
    await wait(800);
    await selectCall(p, "c.call_id.startsWith('nat-')");
    await wait(500);
    await p.evaluate(() => {
      const f = window.__sidetone.report.findings.find((x) => x.rule === "sdp.private_ip");
      document.querySelector(`#ladder .msg[data-msg="${f.messages[0]}"]`).dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
  },
});
await shot("sidetone-media", { url: "/?sample=demo", steps: async (p) => { await wait(800); await selectCall(p, "c.call_id.startsWith('q-')"); await wait(400); await tab(p, "media"); } });
await shot("sidetone-ai", {
  dark: true,
  url: "/?sample=nat-one-way",
  steps: async (p) => {
    await wait(800);
    await tab(p, "ai");
    await p.$eval("#ai-question", (e) => (e.value = "Why does the remote worker hear nothing, and why does the call drop?"));
    await p.click("#ai-preview");
    await wait(800);
    await p.evaluate(() => document.querySelector(".detail .tab-body:not([hidden])").scrollTo(0, 0));
  },
});

// ---- some history first: an echo test, a busy number and an unallocated one
for (const [t, ms] of [["600", 2500], ["602", 1500], ["603", 1500]]) {
  const r = await api("/api/phone/cmd", { cmd: "call", account: "1", target: t });
  await wait(ms);
  await api("/api/phone/cmd", { cmd: "hangup", line: r.line });
  await wait(600);
}
await wait(1000);

// ---- the phone: 2001 talks to 3001 (held) and consults the echo service
await shot("sidetone-phone", {
  url: "/?page=calls",
  steps: async (p) => {
    const a = await api("/api/phone/cmd", { cmd: "call", account: "1", target: "700" });
    await wait(1500);
    const st = await api("/api/phone/state");
    const inc = st.state.calls.find((c) => c.state === "incoming");
    if (inc) await api("/api/phone/cmd", { cmd: "answer", line: inc.line });
    await wait(1500);
    await api("/api/phone/cmd", { cmd: "dtmf", line: inc.line, digits: "42" });
    await api("/api/phone/cmd", { cmd: "hold", line: a.line, on: true });
    await wait(800);
    await p.evaluate(() => { document.getElementById("dial").value = "600"; });
    await p.click("#btn-call");
    await wait(3500);
    await p.click(`#lines li[data-line="${a.line}"]`);
    await wait(300);
    await p.click('.tool[data-tool="transfer"]');
    await p.type("#xfer-to", "600");
    await wait(600);
  },
});
await shot("sidetone-trace-live", {
  dark: true,
  url: "/?page=trace",
  steps: async (p) => {
    await wait(600);
    await p.evaluate(() => {
      const rows = [...document.querySelectorAll(".tr-row")];
      const r = rows.find((x) => /INVITE sip:600/.test(x.textContent)) || rows[0];
      r && r.click();
    });
  },
});
await api("/api/phone/cmd", { cmd: "hangup_all" });
await wait(1500);

await shot("sidetone-settings", {
  url: "/?page=settings",
  steps: async (p) => {
    await wait(500);
    await p.click('[data-acctab="5"]');
    await wait(300);
    await p.click("#af-3"); // user=phone
    await p.click("#af-4"); // compact headers
    await wait(300);
    await p.evaluate(() => document.querySelector(".ws").scrollTo(0, 160));
  },
});
await shot("sidetone-diag", {
  dark: true,
  url: "/?page=diag",
  steps: async (p) => {
    await p.click("#dg-opt-go");
    await wait(600);
    await p.$eval("#dg-dns-host", (e) => (e.value = "127.0.0.1:5070"));
    await p.click("#dg-dns-go");
    await wait(600);
  },
});

// ---- the browser phone (WebRTC to the lab's WebSocket listener)
await shot("sidetone-webrtc", {
  url: "/?phone=web&page=calls",
  steps: async (p) => {
    await p.evaluate(async () => {
      const S = window.__sidetone;
      await S.ctl.setConfig({ accounts: [{ id: "w1", label: "WebRTC 4001", enabled: true, register: true, user: "4001", authUser: "", password: "secret4001", displayName: "", domain: "127.0.0.1", ws: "ws://127.0.0.1:8088/ws", ice: "", expires: 300 }] });
    });
    await wait(2000);
    await p.evaluate(() => { document.getElementById("dial").value = "600"; });
    await p.click("#btn-call");
    await wait(4500);
    await p.click('#keypad [data-key="5"]');
    await wait(1200);
  },
});

await browser.close();
