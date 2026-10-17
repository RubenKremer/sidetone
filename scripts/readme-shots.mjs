// Captures the README screenshots from a running `sidetone serve --no-token`
// and the Asterisk lab (lab/run-asterisk.sh). Usage:
//   CHROME_PATH=/path/to/chrome node scripts/readme-shots.mjs http://127.0.0.1:8640 docs/images
// Needs `npm i puppeteer-core`. Chrome gets fake audio devices for the web phone shot.
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

async function shot(name, { dark = false, url = "/", steps = async () => {} } = {}) {
  const p = await browser.newPage();
  await p.emulateMediaFeatures([{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }]);
  await p.goto(base + url, { waitUntil: "networkidle0" });
  await wait(600);
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

await shot("hero", { url: "/?sample=demo", steps: async (p) => { await wait(800); await selectCall(p, "c.call_id.startsWith('nat-')"); } });

await shot("message", {
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

await shot("media", { url: "/?sample=demo", steps: async (p) => { await wait(800); await selectCall(p, "c.call_id.startsWith('q-')"); await wait(400); await tab(p, "media"); } });

await shot("trace", { url: "/?sample=good-call", steps: async (p) => { await wait(800); await selectCall(p, "c.kind === 'INVITE'"); await wait(400); await tab(p, "log"); } });

await shot("ai", {
  dark: true,
  url: "/?sample=nat-one-way",
  steps: async (p) => {
    await wait(800);
    await tab(p, "ai");
    await p.$eval("#ai-question", (e) => (e.value = "Why does the remote worker hear nothing, and why does the call drop?"));
    await p.click("#ai-preview");
    await wait(800);
    await p.evaluate(() => document.querySelector(".detail").scrollTo(0, 0));
  },
});

await shot("phone", {
  steps: async (p) => {
    await p.evaluate(() => {
      const set = (id, v) => (document.getElementById(id).value = v);
      set("p-ws", "ws://127.0.0.1:8088/ws"); set("p-domain", "127.0.0.1"); set("p-user", "4001"); set("p-pass", "secret4001"); set("p-target", "");
    });
    await p.click("#p-connect");
    await wait(2000);
    for (const k of ["6", "0", "0"]) await p.click(`#p-keypad [data-key="${k}"]`);
    await p.click("#p-dial");
    await wait(4000);
    await p.click('#p-keypad [data-key="5"]');
    await wait(1500);
  },
});

await shot("phone-udp", {
  dark: true,
  steps: async (p) => {
    await p.click('.seg [data-mode="udp"]');
    await p.evaluate(() => {
      const set = (id, v) => (document.getElementById(id).value = v);
      set("p-domain", "127.0.0.1:5070"); set("p-user", "2001"); set("p-pass", "secret2001"); set("p-target", "600"); set("p-dur", "3");
    });
    await p.click("#p-dial");
    await wait(5500);
  },
});

await browser.close();
