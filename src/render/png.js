// SVG -> PNG with zero npm dependencies: uses a Chromium-family browser already on the machine
// (Chrome, Edge, Chromium, Brave) in headless mode with a throwaway profile and a local file:// page.
// If none is found, the caller falls back to writing the SVG.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function candidates(env = process.env, platform = process.platform) {
  const list = [];
  if (env.AGENT_XRAY_BROWSER) list.push(env.AGENT_XRAY_BROWSER);
  if (env.CHROME_PATH) list.push(env.CHROME_PATH);
  // Playwright's chrome-headless-shell (fast, reliable screenshots) if the user already has it cached.
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const pwCache = env.PLAYWRIGHT_BROWSERS_PATH || (platform === 'win32' ? path.join(env.LOCALAPPDATA || '', 'ms-playwright') : platform === 'darwin' ? path.join(home, 'Library', 'Caches', 'ms-playwright') : path.join(home, '.cache', 'ms-playwright'));
  try {
    for (const d of fs.readdirSync(pwCache).filter((n) => n.startsWith('chromium_headless_shell-')).sort().reverse()) {
      for (const sub of fs.readdirSync(path.join(pwCache, d))) {
        list.push(path.join(pwCache, d, sub, platform === 'win32' ? 'chrome-headless-shell.exe' : 'chrome-headless-shell'));
      }
    }
  } catch { /* no playwright cache */ }
  if (platform === 'darwin') {
    for (const app of ['Google Chrome', 'Microsoft Edge', 'Chromium', 'Brave Browser']) list.push(`/Applications/${app}.app/Contents/MacOS/${app}`);
  } else if (platform === 'win32') {
    const roots = [env.PROGRAMFILES, env['PROGRAMFILES(X86)'], env.LOCALAPPDATA].filter(Boolean);
    for (const r of roots) {
      list.push(path.join(r, 'Google', 'Chrome', 'Application', 'chrome.exe'));
      list.push(path.join(r, 'Microsoft', 'Edge', 'Application', 'msedge.exe'));
      list.push(path.join(r, 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'));
    }
  } else {
    const dirs = (env.PATH || '').split(':').filter(Boolean);
    for (const b of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge', 'microsoft-edge-stable', 'brave-browser']) for (const d of dirs) list.push(path.join(d, b));
  }
  return list;
}

export function findBrowser(env, platform) {
  return candidates(env, platform).find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
}

export function svgToPng(svg, outPath, { width = 1200, height = 630, env = process.env } = {}) {
  const browsers = candidates(env).filter((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } });
  if (!browsers.length) return { ok: false, reason: 'No Chrome/Edge/Chromium/Brave found for PNG rendering.' };
  let last = 'unknown error';
  for (const browser of browsers.slice(0, 3)) {
    const r = tryRender(browser, svg, outPath, width, height);
    if (r.ok) return r;
    last = r.reason;
  }
  return { ok: false, reason: last };
}

function tryRender(browser, svg, outPath, width, height) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-xray-'));
  try {
    const html = path.join(tmp, 'card.html');
    fs.writeFileSync(html, `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:#060a16;overflow:hidden}svg{display:block}</style></head><body>${svg}</body></html>`);
    const shot = path.join(tmp, 'card.png');
    const headlessShell = /headless[-_]shell/.test(path.basename(browser));
    const args = [...(headlessShell ? [] : ['--headless=new']), '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-pings', '--disable-domain-reliability', '--force-device-scale-factor=1', `--user-data-dir=${path.join(tmp, 'profile')}`, `--window-size=${width},${height}`, `--screenshot=${shot}`, 'file://' + html.replace(/\\/g, '/').replace(/^([A-Za-z]):/, '/$1:')];
    if (process.getuid && process.getuid() === 0) args.unshift('--no-sandbox');
    const res = spawnSync(browser, args, { timeout: 20000, stdio: 'ignore' });
    if (!fs.existsSync(shot)) return { ok: false, reason: `${path.basename(browser)} could not render the card${res.error ? ` (${res.error.code})` : ''}.` };
    fs.copyFileSync(shot, outPath);
    return { ok: true, browser: path.basename(browser) };
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}
