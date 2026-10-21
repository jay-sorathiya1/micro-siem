// Capture the report screenshots from the running stack with headless Chromium.
// 1024 px wide CSS viewport at 2x pixel density, so text stays sharp and large enough
// once the image is scaled to the page; text-heavy screens are cropped to their panel.
//
// Usage: node docs/report/screenshots.mjs docs/report/screenshots   (stack must be up)
import { spawn } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const OUT = process.argv[2];
const env = Object.fromEntries(readFileSync(new URL("../../.env", import.meta.url), "utf8")
  .split("\n").filter(l => l.includes("=") && !l.startsWith("#")).map(l => l.split("=")));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const W = 1024, H = 680, DPR = 2;

const profile = mkdtempSync(`${tmpdir()}/siem-shots-`);
const chrome = spawn("chromium", ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
  "--remote-debugging-port=9335", `--user-data-dir=${profile}`, `--window-size=${W},${H}`, "about:blank"], { stdio: "ignore" });
let ws;
for (let i = 0; i < 40 && !ws; i++) {
  await sleep(250);
  try { const p = (await (await fetch("http://127.0.0.1:9335/json")).json()).find(t => t.type === "page"); if (p) ws = new WebSocket(p.webSocketDebuggerUrl); } catch {}
}
await new Promise(r => ws.addEventListener("open", r, { once: true }));
let id = 0; const pending = new Map(); const errors = [];
const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
ws.addEventListener("message", ev => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result || m); pending.delete(m.id); }
  if (m.method === "Page.javascriptDialogOpening") send("Page.handleJavaScriptDialog", { accept: true });
  if (m.method === "Runtime.exceptionThrown") errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
});
const js = async e => (await send("Runtime.evaluate", { expression: e, awaitPromise: true, returnByValue: true })).result?.value;
const go = async (url, wait = 2000) => { await send("Page.navigate", { url }); await sleep(wait); };
// shot(name) = whole viewport; shot(name, selector, pad) = crop to that element
const shot = async (name, sel = null, pad = 6, full = false) => {
  const params = { format: "png", captureBeyondViewport: full };
  if (sel) {
    const r = await js(`(() => { const b = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return {x:b.x,y:b.y + window.scrollY,w:b.width,h:b.height}; })()`);
    params.clip = { x: Math.max(0, r.x - pad), y: Math.max(0, r.y - pad), width: Math.min(W, r.w + 2 * pad), height: full ? r.h + 2 * pad : Math.min(H, r.h + 2 * pad), scale: 1 };
  }
  const res = await send("Page.captureScreenshot", params);
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(res.data, "base64"));
  console.log("saved", name);
};
await send("Page.enable"); await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: DPR, mobile: false });
const login = async (user, pass) => {
  await go("http://localhost:8090/login.html", 1500);
  await js(`sessionStorage.clear(); document.getElementById('username').value=${JSON.stringify(user)}; document.getElementById('password').value=${JSON.stringify(pass)}; document.getElementById('loginForm').requestSubmit(); true`);
  await sleep(6000);
};

// --- Dashboard login (8090) ---
await go("http://localhost:8090/login.html", 1500); await shot("04-dashboard-login");
await js(`document.getElementById('username').value='admin'; document.getElementById('password').value='wrong'; document.getElementById('loginForm').requestSubmit(); true`);
await sleep(1200); await shot("05-dashboard-login-failed");

// --- Admin console ---
await login("admin", env.DASHBOARD_ADMIN_PASSWORD);
await shot("06-admin-dashboard");
await js("setView('logs'); true"); await sleep(1000); await shot("07-admin-logs", "#view-logs .panel");
await js("setView('threats'); true"); await sleep(1000); await shot("08-admin-threats", "#view-threats .panel");
await js("document.querySelector('#threat-list button[data-ip=\"192.168.1.50\"]').click(); true"); await sleep(600);
await shot("09-admin-mitigation-modal", "#modal .panel", 24);
await js("takeAction('block-ip'); true"); await sleep(500); await shot("10-admin-coming-soon", "#soon-modal .panel", 24);
await js("closeComingSoon(); true");

// --- Viewer ---
await login("viewer", env.DASHBOARD_VIEWER_PASSWORD);
await shot("11-viewer-dashboard");

// --- API docs + OpenSearch Dashboards ---
await go("http://localhost:8000/docs", 3500); await shot("12-swagger-api-docs", ".opblock-tag-section", 6, true);
await go("http://localhost:5601/app/data-explorer/discover#?_g=(time:(from:now-2h,to:now))&_a=(discover:(columns:!(log_type,event,username,source_ip),sort:!()),metadata:(indexPattern:'logs-pattern',view:discover))", 14000);
await shot("13-opensearch-discover");

// --- Demo attack-target site (8080) ---
await go("http://localhost:8080/", 2500); await shot("01-demo-home");
await go("http://localhost:8080/login.html", 2000);
await js(`document.getElementById('username').value='admin'; document.getElementById('password').value='9999'; document.getElementById('loginForm').requestSubmit(); true`);
await sleep(1500); await shot("02-demo-login-failed");
await js(`sessionStorage.clear(); document.getElementById('username').value='guest'; document.getElementById('password').value='0000'; document.getElementById('loginForm').requestSubmit(); true`);
await sleep(3000);
await go("http://localhost:8080/search.html?q=" + encodeURIComponent("<img src=x onerror=alert('XSS')>"), 2500);
await shot("03-demo-search-xss");

console.log("JS errors:", errors.length ? errors.slice(0, 5) : "none");
ws.close(); chrome.kill();
