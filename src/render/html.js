// Interactive, self-contained HTML report. One file: inline CSS + JS, no CDN, no network calls
// (a Content-Security-Policy meta tag forbids any fetch). All report data is embedded as JSON in a
// non-executing <script type="application/json"> with < > & U+2028/2029 escaped, and the client builds
// the DOM with textContent only, so config content can never inject markup. Secret values never reach
// this module: findings carry only redacted previews.
import { renderCardSvg, statTiles } from './card.js';
import { badgeSvg } from '../badge.js';
import { fixPromptParts } from './fixprompt.js';
import { annotateFixes, verifyCommand } from '../fixes.js';
import { RISK_POINTS, BANDS, INFECTED_CAP } from '../grade.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
export const safeJson = (v) => JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

/** Client-side mirror of grade.js (kept as source so the browser can project the score as items are marked fixed). */
export const CLIENT_GRADE = `function gradeClient(agents, findings, fixed) {
  var P = ${JSON.stringify(RISK_POINTS)}, B = ${JSON.stringify(BANDS)};
  var letter = function (s) { for (var i = 0; i < B.length; i++) if (s >= B[i][1]) return B[i][0]; return 'F'; };
  var open = findings.filter(function (f, i) { return !fixed[i]; });
  var score = function (fs) {
    var pts = fs.reduce(function (n, f) { return n + (P[f.severity] || 0); }, 0);
    var s = Math.round(100 * Math.exp(-pts / 120));
    var c = fs.filter(function (f) { return f.severity === 'critical'; }).length;
    if (c >= 2) s = Math.min(s, 49); else if (c === 1) s = Math.min(s, 64);
    return s;
  };
  var graded = [], per = {};
  agents.forEach(function (a) {
    var fs = open.filter(function (f) { return f.agents.indexOf(a.id) >= 0; });
    var s = score(fs);
    per[a.id] = { score: s, grade: letter(s) };
    if (a.id !== 'shared' || fs.some(function (f) { return f.severity !== 'info'; })) graded.push(s);
  });
  if (!graded.length) return { score: null, grade: null, per: per };
  var min = Math.min.apply(null, graded), mean = graded.reduce(function (x, y) { return x + y; }, 0) / graded.length;
  var sc = Math.round(0.6 * min + 0.4 * mean);
  var nc = open.filter(function (f) { return f.severity === 'critical'; }).length;
  if (nc >= 2) sc = Math.min(sc, 49); else if (nc === 1) sc = Math.min(sc, 64);
  if (open.some(function (f) { return f.category === 'infected' && f.severity === 'critical'; })) sc = Math.min(sc, ${INFECTED_CAP});
  return { score: sc, grade: letter(sc), per: per };
}`;

const WHY = {
  secret: 'Anything that can read this file can use this key: every agent, editor extension, MCP server and script running as you. If a prompt injection or a bad package ever reads it, the attacker gets whatever access the key gives you.',
  yolo: 'Your agent runs commands and edits files without asking. If it reads a poisoned web page, issue or README (prompt injection), those instructions run with your full access and nobody gets a chance to say no.',
  'dangerous-allow': 'These commands are pre-approved, so the agent runs them silently, even when it has been tricked. Broad rules like rm, curl or Bash(*) are enough to delete files or send data out.',
  'auto-trust': 'Tools on this server run without a confirmation, so a tricked agent can use them without you ever seeing it.',
  sandbox: 'Without a sandbox, every command the agent runs can read and write anywhere on disk and reach the network.',
  'broad-root': 'The agent can read far more than the project it is working on: SSH keys, cloud credentials, browser data and every other project.',
  'insecure-remote': 'Traffic to this server is unencrypted, so anyone on the network path can read or change tool calls and any tokens sent with them.',
  unpinned: 'Every launch downloads whatever version is newest. If the package is hijacked or typosquatted, the malicious release runs right away with your agent\'s access.',
  'stale-server': 'The configured program is missing. If something later appears at that name or path, your agent will run it.',
  'env-exposure': 'The secrets in this file can be pulled into an agent\'s context, sent to the model provider, kept in logs, or committed to git by accident.',
  'parse-error': 'This config could not be read, so Agent X-ray could not check it, and your agent may be ignoring it too.',
  'host-exposure': 'This weakens the server itself: an agent (or attacker) that gets a foothold can reach further than it should.',
  'secret-custody': 'The key that unlocks your stored secrets sits right next to them, so anyone who can read one can read both.',
  infected: 'This matches a published indicator of compromise from a real attack campaign. Some of these campaigns install a service that watches your tokens and wipes your home folder when you revoke them, so the ORDER of the cleanup matters: remove the persistence first, rotate second. Agent X-ray never removes anything itself.',
  autorun: 'This runs automatically (on session start, before a tool call, when a folder opens, or to draw your status line) without asking you. Whoever can edit this file decides what code runs on your machine, every time.',
  'hidden-unicode': 'Invisible characters can hide instructions that you cannot see in an editor or a diff, but the model reads them. This is how "rules file backdoor" attacks smuggle commands into AGENTS.md, .cursorrules and skills.',
  injection: 'This file is loaded into the agent\'s instructions automatically. Text that tells it to hide what it does, ignore your rules or run downloaded code is a prompt-injection pattern, whoever wrote it.',
  planted: 'Agents read AGENTS.md / CLAUDE.md / GEMINI.md from the folder they start in and its parents. A file dropped in Downloads, the Desktop, /tmp or your home root steers every agent you open there: a known attack path.',
  'lock-drift': 'Something your agents load or auto-run changed since agent-xray.lock was written. If nobody on your team made this change, treat it as an incident.',
  inventory: 'For your information: what your agent is able to do, so you can decide whether it should.',
};

const CSS = `
:root{--bg:#060a16;--panel:#0b1222;--tile:#0f172a;--line:#1e293b;--line2:#273449;--txt:#e2e8f0;--mut:#94a3b8;--dim:#64748b;--acc:#38bdf8;
--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#84cc16;--info:#64748b;--agent:#38bdf8;--human:#f59e0b;--both:#a78bfa;
--font:Inter,'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;--mono:'JetBrains Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 var(--font)}
body{background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.018) 0 1px,transparent 1px 4px)}
a{color:var(--acc)}code,pre,.mono{font-family:var(--mono)}
.wrap{max-width:1180px;margin:0 auto;padding:28px 24px 60px}
.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-weight:900;letter-spacing:.32em;color:var(--acc);font-size:20px}
.sub{color:var(--dim);font-size:14px}.spacer{flex:1}
.badge-sample{background:#a21caf;color:#fff;font-weight:800;letter-spacing:.18em;padding:6px 12px;border-radius:8px;font-size:12px}
.samplebar{margin:16px 0 0;padding:10px 14px;border:1px solid #a21caf;background:rgba(162,28,175,.12);border-radius:10px;color:#f5d0fe;font-size:14px}
.hero{display:grid;grid-template-columns:300px 1fr;gap:28px;margin-top:22px;align-items:center}
.ringbox{position:relative;width:280px;height:280px;margin:0 auto}
.ringbox svg{position:absolute;inset:0}
.ringlabel{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ringlabel .g{font-size:118px;font-weight:900;line-height:1}
.ringlabel .s{color:var(--mut);font-size:15px;margin-top:4px}
.ringlabel .p{font-size:12px;letter-spacing:.14em;color:var(--dim);text-transform:uppercase;margin-top:2px;min-height:18px}
.glow{position:absolute;inset:-40px;border-radius:50%;filter:blur(10px);opacity:.35}
h1{font-size:34px;line-height:1.15;margin:0 0 6px;font-weight:850}
.summary{color:var(--mut);margin:0 0 14px}
.proj{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.bar{flex:1;min-width:200px;height:10px;background:var(--tile);border:1px solid var(--line);border-radius:6px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,#22c55e,#84cc16);transition:width .4s}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.tile{background:var(--tile);border:2px solid var(--line);border-radius:16px;padding:14px 16px 12px 20px;position:relative}
.tile:before{content:"";position:absolute;left:0;top:16px;bottom:16px;width:4px;border-radius:3px;background:var(--c)}
.tile b{display:block;font-size:34px;font-weight:850;color:var(--c);line-height:1.1}
.tile span{display:block;font-weight:700;font-size:14px}.tile small{color:var(--dim);font-size:12px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{display:inline-flex;align-items:center;gap:8px;background:var(--tile);border:2px solid var(--line);border-radius:999px;padding:4px 12px 4px 4px;font-weight:600;font-size:13px;color:#cbd5e1}
.chip .dot{width:26px;height:26px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:#0b1020;font-weight:850;font-size:13px}
.section{margin-top:34px}.h2{font-size:13px;letter-spacing:.2em;color:var(--dim);font-weight:800;text-transform:uppercase;margin:0 0 12px}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.step{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.step .n{display:inline-flex;width:26px;height:26px;border-radius:50%;background:var(--acc);color:#04111f;font-weight:900;align-items:center;justify-content:center;margin-right:8px;font-size:13px}
.step b{font-size:15px}.step p{margin:8px 0 0;color:var(--mut);font-size:13.5px}
.actions{display:flex;gap:12px;flex-wrap:wrap;align-items:stretch;margin-top:14px}
.btn{appearance:none;border:1px solid var(--line2);background:var(--tile);color:var(--txt);border-radius:10px;padding:9px 14px;font:600 14px var(--font);cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.btn:hover{border-color:var(--acc)}.btn.primary{background:var(--acc);color:#04111f;border-color:var(--acc);font-weight:800}
.btn.small{padding:5px 10px;font-size:12.5px;border-radius:8px}
.btn.ok{border-color:#22c55e;color:#86efac}.btn.primary.ok{background:#22c55e;border-color:#22c55e;color:#04111f}
.cmd{display:inline-flex;align-items:center;gap:10px;background:#050914;border:1px solid var(--line2);border-radius:10px;padding:6px 6px 6px 14px;font-family:var(--mono);color:var(--acc);font-size:13.5px}
.toolbar{position:sticky;top:0;z-index:5;background:rgba(6,10,22,.94);backdrop-filter:blur(6px);border-bottom:1px solid var(--line);padding:12px 0;margin:0 -2px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.sev{border:1px solid var(--line2);background:var(--tile);color:var(--mut);border-radius:999px;padding:5px 11px;font:700 12.5px var(--font);cursor:pointer;display:inline-flex;gap:6px;align-items:center}
.sev i{width:9px;height:9px;border-radius:50%;background:var(--c)}.sev.on{color:var(--txt);border-color:var(--c);background:color-mix(in srgb,var(--c) 14%,var(--tile))}
select,input[type=search]{background:var(--tile);color:var(--txt);border:1px solid var(--line2);border-radius:9px;padding:7px 10px;font:14px var(--font)}
input[type=search]{min-width:180px;flex:1}
.count{color:var(--dim);font-size:13px;margin-left:auto}
.list{display:flex;flex-direction:column;gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:14px;overflow:hidden}
.card.fixed{opacity:.55}.card.fixed .title{text-decoration:line-through;text-decoration-color:#22c55e}
.head{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;cursor:pointer}
.head:hover{background:rgba(56,189,248,.03)}
.fixbox{display:flex;flex-direction:column;align-items:center;gap:2px;font-size:10.5px;color:var(--dim);min-width:46px;user-select:none;cursor:pointer}
.fixbox input{width:20px;height:20px;accent-color:#22c55e;cursor:pointer;margin:2px 0 0}
.hmain{flex:1;min-width:0}
.title{font-weight:750;font-size:16px;margin:0 0 6px;word-break:break-word}
.meta{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font-size:12.5px;color:var(--mut)}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:2px 9px;font-weight:800;font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.pill.sevp{background:color-mix(in srgb,var(--c) 18%,transparent);color:var(--c);border:1px solid color-mix(in srgb,var(--c) 45%,transparent)}
.pill.ag{background:var(--tile);border:1px solid var(--line2);color:#cbd5e1;text-transform:none;letter-spacing:0;font-weight:600}
.who{border-radius:8px;padding:3px 9px;font-weight:750;font-size:12px;white-space:nowrap;border:1px solid}
.who.agent{color:var(--agent);border-color:rgba(56,189,248,.45);background:rgba(56,189,248,.08)}
.who.human{color:var(--human);border-color:rgba(245,158,11,.45);background:rgba(245,158,11,.08)}
.who.both{color:var(--both);border-color:rgba(167,139,250,.45);background:rgba(167,139,250,.08)}
.pts{color:var(--dim);font-size:12px;white-space:nowrap}
.loc{font-family:var(--mono);color:#cbd5e1;font-size:12px;word-break:break-all}
.ev{font-family:var(--mono);font-size:12px;background:#050914;border:1px solid var(--line);border-radius:6px;padding:1px 7px;color:#fca5a5;word-break:break-all}
.chev{color:var(--dim);transition:transform .2s;font-size:14px;padding-top:2px}.card.open .chev{transform:rotate(90deg)}
.body{display:none;padding:0 16px 16px 74px}.card.open .body{display:block}
.why{margin:0 0 10px;color:#cbd5e1}.why b{color:var(--txt)}.detail{color:var(--mut);margin:0 0 10px;font-size:14px}
.fixline{margin:0 0 12px;font-size:14px}.fixline b{color:#86efac}
.lane{border:1px solid var(--line);border-radius:12px;margin-top:10px;overflow:hidden}
.lane .lh{display:flex;align-items:center;gap:10px;padding:9px 12px;background:var(--tile);border-bottom:1px solid var(--line);font-weight:750;font-size:13.5px;flex-wrap:wrap}
.lane.agent .lh{color:var(--agent)}.lane.human .lh{color:var(--human)}
.lane .lb{padding:10px 12px}
.lane ol{margin:0;padding-left:22px}.lane li{margin:4px 0;color:#cbd5e1;font-size:14px}
.prompt{margin:0;max-height:170px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12.3px;line-height:1.5;color:#cbd5e1;background:#050914;border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.prompt.full{max-height:none}
.docs{margin-top:8px;font-size:13px;display:flex;flex-wrap:wrap;gap:6px 14px}
.docs a{text-decoration:none;border-bottom:1px dotted var(--acc)}
.empty{padding:30px;text-align:center;color:var(--dim);border:1px dashed var(--line2);border-radius:14px}
.share{display:grid;grid-template-columns:minmax(0,600px) 1fr;gap:20px;align-items:start}
.share img{width:100%;border-radius:14px;border:1px solid var(--line);display:block}
.share p{color:var(--mut);margin:0 0 12px}
.foot{margin-top:40px;color:var(--dim);font-size:12.5px;border-top:1px solid var(--line);padding-top:14px;display:flex;flex-wrap:wrap;gap:8px 18px}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(30px);opacity:0;background:#22c55e;color:#04111f;font-weight:800;padding:9px 16px;border-radius:10px;transition:.25s;pointer-events:none;z-index:9}
.toast.show{opacity:1;transform:translateX(-50%)}
noscript div{margin:20px 0;padding:14px;border:1px solid var(--high);border-radius:10px}
.infected{border:2px solid #ef4444;border-radius:16px;padding:18px 20px;background:#1a0b0f}.infected .hsteps li{margin:6px 0;line-height:1.5}.clean p{color:#94a3b8}
.sevtag.critical{background:#ef4444;color:#fff;border-radius:8px;padding:2px 8px;font-size:13px;margin-left:8px}
.arwrap{overflow-x:auto}.ar{width:100%;border-collapse:collapse;font-size:13px}.ar th,.ar td{text-align:left;padding:7px 8px;border-bottom:1px solid #1e293b;vertical-align:top}.ar th{color:#64748b;font-weight:700}.ar tr.risky td{background:#1a1208}.ar code{word-break:break-all}
.flag{display:inline-block;background:#3b1d0a;color:#fdba74;border-radius:6px;padding:1px 6px;margin:1px;font-size:12px}.flag.ioc{background:#7f1d1d;color:#fecaca}.uni{margin:10px 0}.uni b{display:block;margin-bottom:4px}
@media (max-width:860px){.hero,.share{grid-template-columns:1fr}.tiles{grid-template-columns:repeat(2,1fr)}.steps{grid-template-columns:1fr}.body{padding-left:16px}}
@media print{.toolbar,.btn,.fixbox{display:none}.card .body{display:block}body{background:#fff;color:#000}}
`;

const CLIENT = `
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('axr-data').textContent);
  var R = D.report, F = R.findings;
  var SEVC = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#84cc16', info: '#64748b' };
  var GC = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' };
  var SEVR = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var PTS = ${JSON.stringify(RISK_POINTS)};
  var WHO = { agent: 'Your agent can fix this', human: 'Only you can do this', both: 'You + your agent' };
  var TAILOR = {
    any: '',
    claude: '(Claude Code) Stay in the default permission mode so every edit and command asks me first. Start by explaining your plan.',
    cursor: '(Cursor) Use Agent mode with auto-run turned off, so every terminal command waits for my approval. Start by explaining your plan.',
    codex: '(Codex) Keep approvals on (for example codex --ask-for-approval on-request) and explain your plan before running anything.',
    gemini: '(Gemini CLI) Stay in the default approval mode (not --yolo) and explain your plan before running anything.'
  };
  ${CLIENT_GRADE}
  // ---- state (localStorage, keyed to this report) ----
  var KEY = D.storageKey, st = { fixed: {}, tailor: 'any' };
  try { var s = JSON.parse(localStorage.getItem(KEY) || 'null'); if (s && typeof s === 'object') { st.fixed = s.fixed || {}; st.tailor = TAILOR.hasOwnProperty(s.tailor) ? s.tailor : 'any'; } } catch (e) {}
  var save = function () { try { localStorage.setItem(KEY, JSON.stringify(st)); } catch (e) {} };
  var isFixed = function (i) { return !!st.fixed[F[i].key]; };
  // ---- tiny DOM helper: text only, never innerHTML ----
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k]; if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'style') el.setAttribute('style', v);
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else if (k === 'href') { if (/^https:\\/\\//.test(v)) { el.setAttribute('href', v); el.setAttribute('target', '_blank'); el.setAttribute('rel', 'noopener noreferrer'); } }
      else el.setAttribute(k, v);
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i]; if (c == null || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x != null && x !== false) el.appendChild(typeof x === 'string' ? document.createTextNode(x) : x); });
      else el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return el;
  }
  var $ = function (id) { return document.getElementById(id); };
  var toastT;
  function toast(msg) { var t = $('toast'); t.textContent = msg; t.className = 'toast show'; clearTimeout(toastT); toastT = setTimeout(function () { t.className = 'toast'; }, 1600); }
  function copy(text, btn, label) {
    var done = function () { if (btn) { var o = btn.textContent; btn.textContent = 'Copied'; btn.classList.add('ok'); setTimeout(function () { btn.textContent = label || o; btn.classList.remove('ok'); }, 1500); } toast('Copied to clipboard'); };
    var fallback = function () { var ta = h('textarea', { style: 'position:fixed;left:-9999px;top:0' }); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Select the text and copy it manually'); } ta.remove(); };
    if (navigator.clipboard && window.isSecureContext !== false) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
  }
  var agentName = function (id) { for (var i = 0; i < R.agents.length; i++) if (R.agents[i].id === id) return R.agents[i].name; return id; };
  var tailored = function (p) { var t = TAILOR[st.tailor]; return t ? t + '\\n\\n' + p : p; };
  // ---- header: ring + projection ----
  function ringSvg(score, color) {
    var NS = 'http://www.w3.org/2000/svg', r = 122, C = 2 * Math.PI * r;
    var svg = document.createElementNS(NS, 'svg'); svg.setAttribute('viewBox', '0 0 280 280'); svg.setAttribute('width', '280'); svg.setAttribute('height', '280');
    var mk = function (attrs) { var c = document.createElementNS(NS, 'circle'); for (var k in attrs) c.setAttribute(k, attrs[k]); svg.appendChild(c); return c; };
    mk({ cx: 140, cy: 140, r: 132, fill: '#0b1020' });
    mk({ cx: 140, cy: 140, r: r, fill: 'none', stroke: '#1e293b', 'stroke-width': 14 });
    var arc = mk({ cx: 140, cy: 140, r: r, fill: 'none', stroke: color, 'stroke-width': 14, 'stroke-linecap': 'round', 'stroke-dasharray': C, 'stroke-dashoffset': C * (1 - (score || 0) / 100), transform: 'rotate(-90 140 140)' });
    arc.style.transition = 'stroke-dashoffset .6s, stroke .3s';
    return svg;
  }
  function renderHeader() {
    var fixedArr = F.map(function (f, i) { return isFixed(i); });
    var nFixed = fixedArr.filter(Boolean).length, actionable = F.filter(function (f) { return f.severity !== 'info'; }).length;
    var proj = gradeClient(R.agents, F, fixedArr);
    var g = proj.grade || '?', col = GC[g] || '#94a3b8';
    var box = $('ring'); box.textContent = '';
    box.appendChild(h('div', { class: 'glow', style: 'background:radial-gradient(circle,' + col + ' 0%,transparent 65%)' }));
    box.appendChild(ringSvg(proj.score, col));
    box.appendChild(h('div', { class: 'ringlabel' }, h('div', { class: 'g', style: 'color:' + col, text: g }), h('div', { class: 's', text: proj.score == null ? 'no agents found' : proj.score + ' / 100' }), h('div', { class: 'p', text: nFixed ? 'projected' : '' })));
    var o = R.overall;
    $('headline').textContent = o.grade ? (nFixed ? 'Projected: ' + g + ' (' + proj.score + '), up from ' + o.grade + ' (' + o.score + ')' : (R.mode === 'server' ? 'The AI agents on this server got ' : 'Your AI agents got ') + (/^[AEF]/.test(o.grade) ? 'an ' : 'a ') + o.grade) : 'No AI coding agents found';
    var pr = $('progress'); pr.textContent = '';
    pr.appendChild(h('span', { class: 'pts', text: nFixed + ' of ' + actionable + ' issues marked fixed' }));
    var bar = h('div', { class: 'bar' }, h('i', { style: 'width:' + (actionable ? Math.round(100 * nFixed / actionable) : 100) + '%' }));
    pr.appendChild(bar);
    if (nFixed) pr.appendChild(h('span', { class: 'pts', text: 'Marks are a plan, not proof: re-run the scan to verify.' }));
    var chips = $('chips'); chips.textContent = '';
    R.agents.filter(function (a) { return a.id !== 'shared'; }).forEach(function (a) {
      var p = proj.per[a.id] || a, gg = p.grade || a.grade;
      chips.appendChild(h('span', { class: 'chip' }, h('span', { class: 'dot', style: 'background:' + (GC[gg] || '#64748b'), text: gg }), a.name));
    });
  }
  // ---- toolbar ----
  var filt = { sev: { critical: 1, high: 1, medium: 1, low: 1, info: 0 }, agent: '', who: '', status: 'all', q: '', sort: 'severity' };
  function buildToolbar() {
    var tb = $('toolbar'); tb.textContent = '';
    ['critical', 'high', 'medium', 'low', 'info'].forEach(function (s) {
      var n = F.filter(function (f) { return f.severity === s; }).length;
      var b = h('button', { class: 'sev' + (filt.sev[s] ? ' on' : ''), style: '--c:' + SEVC[s], type: 'button', 'aria-pressed': String(!!filt.sev[s]), onclick: function () { filt.sev[s] = filt.sev[s] ? 0 : 1; buildToolbar(); renderList(); } }, h('i'), s + ' ' + n);
      tb.appendChild(b);
    });
    var ag = h('select', { 'aria-label': 'Agent or target', onchange: function () { filt.agent = this.value; renderList(); } }, h('option', { value: '', text: 'All agents / targets' }));
    R.agents.forEach(function (a) { var n = F.filter(function (f) { return f.agents.indexOf(a.id) >= 0; }).length; if (n) ag.appendChild(h('option', { value: a.id, text: a.name + ' (' + n + ')' })); });
    ag.value = filt.agent; tb.appendChild(ag);
    var who = h('select', { 'aria-label': 'Who fixes it', onchange: function () { filt.who = this.value; renderList(); } }, h('option', { value: '', text: 'Anyone can fix' }), h('option', { value: 'agent', text: WHO.agent }), h('option', { value: 'human', text: WHO.human }), h('option', { value: 'both', text: WHO.both }));
    who.value = filt.who; tb.appendChild(who);
    var stt = h('select', { 'aria-label': 'Status', onchange: function () { filt.status = this.value; renderList(); } }, h('option', { value: 'all', text: 'Open + fixed' }), h('option', { value: 'open', text: 'Open only' }), h('option', { value: 'fixed', text: 'Marked fixed' }));
    stt.value = filt.status; tb.appendChild(stt);
    var srt = h('select', { 'aria-label': 'Sort', onchange: function () { filt.sort = this.value; renderList(); } }, h('option', { value: 'severity', text: 'Sort: severity' }), h('option', { value: 'agent', text: 'Sort: agent' }), h('option', { value: 'file', text: 'Sort: location' }), h('option', { value: 'who', text: 'Sort: who fixes' }));
    srt.value = filt.sort; tb.appendChild(srt);
    var q = h('input', { type: 'search', placeholder: 'Search findings…', 'aria-label': 'Search', oninput: function () { filt.q = this.value.toLowerCase(); renderList(); } }); q.value = filt.q; tb.appendChild(q);
    tb.appendChild(h('span', { class: 'count', id: 'count' }));
  }
  // ---- findings ----
  function card(f, i) {
    var fixed = isFixed(i), c = SEVC[f.severity];
    var el = h('article', { class: 'card' + (fixed ? ' fixed' : '') + (f._open ? ' open' : ''), style: '--c:' + c, id: 'f-' + i });
    var cb = h('input', { type: 'checkbox', 'aria-label': 'Mark fixed' }); cb.checked = fixed;
    cb.addEventListener('change', function () { if (cb.checked) st.fixed[f.key] = 1; else delete st.fixed[f.key]; save(); renderHeader(); renderList(); updateFixAll(); });
    var fb = h('label', { class: 'fixbox', title: 'Mark fixed (projects your new score)', onclick: function (e) { e.stopPropagation(); } }, cb, fixed ? 'fixed' : 'mark fixed');
    var meta = h('div', { class: 'meta' }, h('span', { class: 'pill sevp', text: f.severity }), f.agents.map(function (a) { return h('span', { class: 'pill ag', text: agentName(a) }); }),
      f.file ? h('span', { class: 'loc', text: f.file + (f.line ? ':' + f.line : '') }) : null,
      f.evidence ? h('span', { class: 'ev', title: 'Redacted on purpose', text: f.evidence }) : null);
    var head = h('div', { class: 'head', onclick: function () { f._open = !f._open; el.classList.toggle('open', !!f._open); } },
      fb, h('div', { class: 'hmain' }, h('div', { class: 'title', text: f.title }), meta),
      h('div', { style: 'display:flex;flex-direction:column;align-items:flex-end;gap:6px' }, h('span', { class: 'who ' + f.fixer, text: WHO[f.fixer] }), h('span', { class: 'pts', text: PTS[f.severity] ? '−' + PTS[f.severity] + ' risk pts' : 'info' })),
      h('span', { class: 'chev', text: '›' }));
    var body = h('div', { class: 'body' });
    body.appendChild(h('p', { class: 'why' }, h('b', { text: 'Why it matters: ' }), D.why[f.category] || ''));
    if (f.detail) body.appendChild(h('p', { class: 'detail', text: f.detail }));
    if (f.unicode && (f.unicode.lines.length || f.unicode.decoded.length)) {
      body.appendChild(h('div', { class: 'uni' }, h('b', { text: 'Hidden characters made visible:' }),
        f.unicode.lines.map(function (l) { return h('pre', { class: 'prompt full', text: 'line ' + l.line + ': ' + l.visible }); }),
        f.unicode.decoded.length ? h('div', null, h('b', { text: 'Decoded hidden text (do not follow it): ' }), f.unicode.decoded.join(' / ')) : null));
    }
    if (f.fix) body.appendChild(h('p', { class: 'fixline' }, h('b', { text: 'The fix: ' }), f.fix));
    var humanLane = null, agentLane = null;
    if (f.human_steps && f.human_steps.length) {
      humanLane = h('div', { class: 'lane human' }, h('div', { class: 'lh', text: (f.fixer === 'both' ? 'Step 1 · You do this' : 'Only you can do this') + (f.fixer === 'both' ? ' (needs your account or console)' : '') }),
        h('div', { class: 'lb' }, h('ol', null, f.human_steps.map(function (s) { return h('li', { text: s }); })),
          f.docs && f.docs.length ? h('div', { class: 'docs' }, h('span', { class: 'pts', text: 'Official docs:' }), f.docs.map(function (d) { return h('a', { href: d.url, text: d.label }); })) : null));
    }
    if (f.agent_prompt) {
      var pre = h('pre', { class: 'prompt', text: tailored(f.agent_prompt) });
      var cpy = h('button', { class: 'btn small primary', type: 'button', text: 'Copy prompt', onclick: function (e) { e.stopPropagation(); copy(tailored(f.agent_prompt), cpy, 'Copy prompt'); } });
      var more = h('button', { class: 'btn small', type: 'button', text: 'Expand', onclick: function () { pre.classList.toggle('full'); more.textContent = pre.classList.contains('full') ? 'Collapse' : 'Expand'; } });
      agentLane = h('div', { class: 'lane agent' }, h('div', { class: 'lh' }, h('span', { text: (f.fixer === 'both' ? 'Step 2 · Your agent updates the config' : 'Your agent can fix this') + ' · paste into Claude Code, Cursor, Codex, Gemini CLI…' }), h('span', { class: 'spacer' }), more, cpy),
        h('div', { class: 'lb' }, pre, h('div', { class: 'pts', style: 'margin-top:6px', text: 'The prompt tells the agent to back up first, show you the diff, wait for your OK, and never print secrets.' })));
    }
    if (humanLane) body.appendChild(humanLane);
    if (agentLane) body.appendChild(agentLane);
    el.appendChild(head); el.appendChild(body);
    return el;
  }
  function renderList() {
    var list = $('list'); list.textContent = '';
    var idx = F.map(function (f, i) { return i; }).filter(function (i) {
      var f = F[i];
      if (!filt.sev[f.severity]) return false;
      if (filt.agent && f.agents.indexOf(filt.agent) < 0) return false;
      if (filt.who && f.fixer !== filt.who) return false;
      if (filt.status === 'open' && isFixed(i)) return false;
      if (filt.status === 'fixed' && !isFixed(i)) return false;
      if (filt.q && (f.title + ' ' + (f.file || '') + ' ' + (f.detail || '') + ' ' + f.id).toLowerCase().indexOf(filt.q) < 0) return false;
      return true;
    });
    var whoR = { agent: 0, both: 1, human: 2 };
    var key = { severity: function (i) { return [SEVR[F[i].severity], i]; }, agent: function (i) { return [agentName(F[i].agents[0] || '').toLowerCase(), SEVR[F[i].severity], i]; }, file: function (i) { return [(F[i].file || '~').toLowerCase(), F[i].line || 0, i]; }, who: function (i) { return [whoR[F[i].fixer], SEVR[F[i].severity], i]; } }[filt.sort];
    idx.sort(function (a, b) { var x = key(a), y = key(b); for (var k = 0; k < x.length; k++) { if (x[k] < y[k]) return -1; if (x[k] > y[k]) return 1; } return 0; });
    idx.forEach(function (i) { list.appendChild(card(F[i], i)); });
    if (!idx.length) list.appendChild(h('div', { class: 'empty', text: F.length ? 'Nothing matches these filters.' : 'No findings. Nothing to fix.' }));
    $('count').textContent = idx.length + ' of ' + F.length + ' shown';
  }
  // ---- fix-all ----
  function fixAllText() {
    var P = D.fixAll, forAgent = [], forMe = [];
    F.forEach(function (f, i) { if (isFixed(i)) return; if (P.humanItems[i]) forMe.push(P.humanItems[i]); else if (P.items[i]) forAgent.push(P.items[i]); });
    var L = []; var t = TAILOR[st.tailor]; if (t) L.push(t, '');
    L.push(P.preamble, '');
    if (!forAgent.length && !forMe.length) L.push('Findings: none left to fix. Just double-check nothing above applies, then stop.');
    if (forAgent.length) { L.push('Findings (' + forAgent.length + ', most severe first):'); forAgent.forEach(function (s, n) { L.push((n + 1) + '. ' + s); }); }
    if (forMe.length) { L.push('', 'Leave these to me (they need my accounts or console access). Do not attempt them, but remind me at the end:'); forMe.forEach(function (s) { L.push(s); }); }
    L.push('', P.footer);
    return { text: L.join('\\n'), nAgent: forAgent.length, nMe: forMe.length };
  }
  function updateFixAll() {
    var n = { agent: 0, both: 0, human: 0 };
    F.forEach(function (f, i) { if (!isFixed(i) && f.severity !== 'info') n[f.fixer] = (n[f.fixer] || 0) + 1; });
    $('fixall-note').textContent = 'Open: ' + n.agent + ' your agent can fix · ' + n.both + ' you + your agent · ' + n.human + ' only you' + (Object.keys(st.fixed).length ? ' · the fix-all prompt leaves out items you marked fixed' : '');
  }
  // ---- boot ----
  var sel = $('tailor'); for (var k in TAILOR) sel.appendChild(h('option', { value: k, text: { any: 'Any coding agent', claude: 'Claude Code', cursor: 'Cursor', codex: 'Codex', gemini: 'Gemini CLI' }[k] }));
  sel.value = st.tailor; sel.addEventListener('change', function () { st.tailor = sel.value; save(); renderList(); });
  $('fixall').addEventListener('click', function () { copy(fixAllText().text, $('fixall'), 'Copy fix-all prompt'); });
  $('verify').addEventListener('click', function () { copy(D.verify, $('verify'), 'Copy'); });
  $('reset').addEventListener('click', function () { st.fixed = {}; save(); renderHeader(); renderList(); updateFixAll(); });
  var gen = $('gen'); try { gen.textContent = new Date(R.generatedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZoneName: 'short' }); } catch (e) { gen.textContent = R.generatedAt; }
  F.forEach(function (f, i) { f._open = i < 3 && (f.severity === 'critical' || f.severity === 'high'); });
  renderHeader(); buildToolbar(); renderList(); updateFixAll();
  document.documentElement.classList.add('ready');
})();
`;

function hash(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0; return h.toString(36); }

/** Render the interactive report. Accepts a scan report (or one loaded from --json). */
export function renderHtml(report) {
  const r = annotateFixes(report);
  const keyed = r.findings.map((f) => ({ ...f, key: hash(`${f.id}|${f.file || ''}|${f.line ?? ''}|${f.title}`) }));
  const payload = {
    report: {
      version: r.version, generatedAt: r.generatedAt, sample: !!r.sample, mode: r.mode || null, label: r.label || null, platform: r.platform,
      overall: r.overall, counts: r.counts,
      agents: r.agents.map((a) => ({ id: a.id, name: a.name, grade: a.grade, score: a.score })),
      findings: keyed.map((f) => ({ key: f.key, id: f.id, severity: f.severity, category: f.category, agents: f.agents, title: f.title, detail: f.detail, file: f.file, line: f.line, evidence: f.evidence, fix: f.fix, fixer: f.fixer, agent_prompt: f.agent_prompt, human_steps: f.human_steps, docs: (f.docs || []).filter((d) => /^https:\/\//.test(d.url)), unicode: f.unicode ? { lines: (f.unicode.lines || []).slice(0, 8), decoded: (f.unicode.decoded || []).slice(0, 4) } : null })),
      infected: r.infected || null, badge: r.badge || null,
    },
    fixAll: fixPromptParts(r),
    verify: verifyCommand(r) + ' --open',
    why: WHY,
    storageKey: `agent-xray:${hash(r.generatedAt + '|' + keyed.map((f) => f.key).join(','))}`,
  };
  const card = Buffer.from(renderCardSvg(r), 'utf8').toString('base64');
  const c = r.counts;
  const tiles = statTiles(r).map(([n, l, s, col]) => `<div class="tile" style="--c:${col}"><b>${esc(n)}</b><span>${esc(l)}</span><small>${esc(s)}</small></div>`).join('');
  const inf = r.infected;
  const infectedHtml = !inf ? '' : inf.status === 'indicators'
    ? `<section class="section infected" id="infected"><div class="h2">Am I infected? <span class="sevtag critical">${esc(inf.hits)} indicator${inf.hits === 1 ? '' : 's'}</span></div>
      <p><b>Agent X-ray matched published indicators of compromise${inf.persistence?.length ? ` (${esc(inf.persistence.join('; '))})` : ''}.</b> Follow these steps in order. <b>Remove the persistence service BEFORE rotating any token</b>: the Cloud Security Alliance warns the Mini Shai-Hulud monitor wipes your home folder when it sees its token revoked. Agent X-ray never removes or fixes anything itself.</p>
      <ol class="hsteps">${(inf.steps || []).map((st) => `<li>${esc(st)}</li>`).join('')}</ol>
      <p class="pts">IOC list dated ${esc(inf.iocListUpdated)} · ${esc(inf.indicatorsChecked)} indicators checked offline · see the matching findings below.</p></section>`
    : `<section class="section clean" id="infected"><div class="h2">Am I infected?</div><p>No known indicators found: ${esc(inf.indicatorsChecked)} offline indicators checked (IOC list dated ${esc(inf.iocListUpdated)}). A clean result only covers the campaigns on the list; it is not proof of a clean machine.</p></section>`;
  const ar = (r.autorun || []);
  const autorunHtml = !ar.length ? '' : `<section class="section"><div class="h2">Auto-run inventory <span class="pts">${esc(ar.length)} entr${ar.length === 1 ? 'y' : 'ies'} · ${esc(c.riskyAutorun || 0)} risky · listed, never executed</span></div>
    <div class="arwrap"><table class="ar"><thead><tr><th>What</th><th>When</th><th>Runs</th><th>Where</th><th>Flags</th></tr></thead><tbody>${ar.slice(0, 60).map((e) => `<tr class="${e.flags.length ? 'risky' : ''}"><td>${esc(e.kind)}${e.disabled ? ' <small>(disabled)</small>' : ''}</td><td>${esc([e.event, e.matcher].filter(Boolean).join(' · ') || '')}</td><td><code>${esc(String(e.command || e.url || '').slice(0, 140))}</code></td><td><code>${esc(e.file || '')}${e.line ? ':' + esc(e.line) : ''}</code> <small>${esc(e.scope || '')}</small></td><td>${e.flags.map((f) => `<span class="flag${f === 'ioc' ? ' ioc' : ''}">${esc(f)}</span>`).join(' ')}</td></tr>`).join('')}</tbody></table>${ar.length > 60 ? `<p class="pts">+${ar.length - 60} more in the JSON report (--json).</p>` : ''}</div></section>`;
  const badge = r.badge ? Buffer.from(badgeSvg(r.overall.grade, { infected: inf?.status === 'indicators' }), 'utf8').toString('base64') : null;
  const target = r.mode === 'server' ? 'this server' : 'this machine';
  const title = `Agent X-ray${r.label ? ' · ' + r.label : ''} · ${r.overall.grade || '?'}${r.sample ? ' (SAMPLE)' : ''}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <span class="brand">AGENT X-RAY</span>
    <span class="sub">What can the AI agents on ${esc(target)} actually reach?${r.label ? ' · ' + esc(r.label) : ''}</span>
    <span class="spacer"></span>
    ${r.sample ? '<span class="badge-sample">SAMPLE DATA</span>' : ''}
  </div>
  ${r.sample ? '<div class="samplebar"><b>SAMPLE report.</b> Generated by <code>npx agent-xray demo</code> from bundled fake data: no real machine was scanned and none of these keys are real.</div>' : ''}
  <noscript><div>This report needs JavaScript for the interactive list. For a text version run <code>npx agent-xray --verbose</code> or <code>npx agent-xray --fix-prompt</code>.</div></noscript>
  ${infectedHtml.startsWith('<section class="section infected"') ? infectedHtml : ''}
  <section class="hero">
    <div class="ringbox" id="ring"></div>
    <div>
      <h1 id="headline">${esc(r.overall.grade ? `Grade ${r.overall.grade}` : 'No AI coding agents found')}</h1>
      <p class="summary">${esc(r.overall.summary || '')}${r.overall.score != null ? ` · ${esc(r.overall.score)}/100 · ${esc(c.agents)} ${r.mode ? 'target' : 'agent'}${c.agents === 1 ? '' : 's'} scanned` : ''}</p>
      <div class="proj" id="progress"></div>
      <div class="tiles">${tiles}</div>
      <div class="chips" id="chips"></div>
    </div>
  </section>

  <section class="section">
    <div class="h2">How to fix this</div>
    <div class="steps">
      <div class="step"><span class="n">1</span><b>Hand the easy ones to your agent</b><p>Items marked <span class="who agent">Your agent can fix this</span> come with a prompt scoped to that one issue. Paste it into Claude Code, Cursor, Codex or similar. It backs up first, shows you the diff and waits for your OK.</p></div>
      <div class="step"><span class="n">2</span><b>Do the parts only you can do</b><p><span class="who human">Only you can do this</span> means it needs your accounts or console: rotating a key, revoking a token, changing SSH access. Follow the numbered steps.</p></div>
      <div class="step"><span class="n">3</span><b>Mark fixed, then verify</b><p>Tick <i>mark fixed</i> to see your projected grade (saved in this browser only). Then re-run the scan; only a new scan proves it.</p></div>
    </div>
    <div class="actions">
      <button class="btn primary" id="fixall" type="button">Copy fix-all prompt</button>
      <label class="btn" style="cursor:default">Prompts for <select id="tailor" aria-label="Tailor prompts for"></select></label>
      <span class="cmd">${esc(payload.verify)} <button class="btn small" id="verify" type="button">Copy</button></span>
      <button class="btn" id="reset" type="button">Clear marks</button>
    </div>
    <p class="pts" id="fixall-note" style="margin:8px 0 0"></p>
  </section>

  <section class="section">
    <div class="h2">Findings</div>
    <div class="toolbar" id="toolbar"></div>
    <div class="list" id="list"></div>
  </section>

  ${infectedHtml.startsWith('<section class="section clean"') ? infectedHtml : ''}
  ${autorunHtml}

  <section class="section">
    <div class="h2">Share card</div>
    <div class="share">
      <img alt="Agent X-ray share card: grade and counts only" src="data:image/svg+xml;base64,${card}">
      <div><p>The card holds only the grade, counts and agent names: no paths, no keys. Safe to post.</p>
      <p>Save it as PNG with <code>npx agent-xray${r.mode === 'server' ? ' --server' : ''} --card xray.png</code>, or download the SVG:</p>
      <a class="btn" download="agent-xray-card.svg" href="data:image/svg+xml;base64,${card}">Download card (SVG)</a>
      ${badge ? `<p style="margin-top:14px"><b>README badge</b> <img alt="Harness Hygiene badge" src="data:image/svg+xml;base64,${badge}" style="vertical-align:middle;width:auto;border:0"></p><pre class="prompt full">${esc(r.badge.markdown)}</pre><p class="pts">Or commit a local SVG: <code>npx agent-xray --badge harness-hygiene.svg</code>. Grade only, no paths or counts. What the grade means: docs/HARNESS-HYGIENE.md.</p>` : ''}</div>
    </div>
  </section>

  <div class="foot">
    <span>Agent X-ray ${esc(r.version)}</span><span>Scanned <span id="gen">${esc(r.generatedAt)}</span></span>
    <span>Read-only scan · this file works offline and makes no network requests · secret values are redacted</span>
  </div>
</div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script type="application/json" id="axr-data">${safeJson(payload)}</script>
<script>${CLIENT}</script>
</body>
</html>
`;
}
