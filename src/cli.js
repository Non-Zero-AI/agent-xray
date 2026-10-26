import fs from 'node:fs';
import path from 'node:path';
import { scan, VERSION } from './scan.js';
import { renderTerminal } from './render/terminal.js';
import { renderCardSvg } from './render/card.js';
import { svgToPng } from './render/png.js';
import { renderFixPrompt } from './render/fixprompt.js';
import { renderHtml } from './render/html.js';
import { annotateFixes } from './fixes.js';
import { spawn } from 'node:child_process';
import { buildDemoHome } from './demo.js';
import { BANDS, grade } from './grade.js';
import { buildLock, serializeLock, readLock, diffLock, driftFindings, LOCK_NAME } from './lock.js';
import { badgeFor, badgeSvg } from './badge.js';
import { tildify } from './paths.js';
import os from 'node:os';
const T = (p) => tildify(p, os.homedir());

const HELP = `agent-xray ${VERSION} — see what your AI coding agents can reach.

Usage
  npx @non-zero_ai/agent-xray                 scan this machine (+ the current folder as a project)
  npx @non-zero_ai/agent-xray demo            run on bundled SAMPLE data (no real files read)
  npx @non-zero_ai/agent-xray lock            write agent-xray.lock: hashes of harness files, hooks and MCP
                                 server definitions in this project (no secret values)
  npx @non-zero_ai/agent-xray verify          re-scan and fail if anything changed or appeared since the lock
  npx @non-zero_ai/agent-xray --ci            CI mode: GitHub annotations, exit 1 on lock drift, any critical
                                 finding or any infection indicator (verifies the lock if present)

Options
  --html [file]          write the interactive report: one offline HTML file with every finding,
                         who can fix it (your agent / only you), copy-paste fix prompts, step-by-
                         step guides and a live projected score (default: agent-xray-report.html)
  --open                 open the HTML report in your browser (implies --html)
  --from-json <file>     render from a saved --json report instead of scanning
  --json                 print the report as JSON (schema/report.schema.json)
  --card <file.png|svg>  write a shareable card (PNG needs Chrome/Edge/Chromium; else SVG)
  --fix-prompt           print a prompt you can paste into your agent to fix the findings
  --deep                 also check .env files in the project (gitignored? hidden from agents?)
  --project <dir>        project folder to scan (default: current folder)
  --no-project           only scan user-level config
  --path <dir>           also scan a self-hosted / custom agent stack folder (repeatable):
                         .env files, docker-compose, generic MCP configs, service configs,
                         loose token files, encrypted credential stores, agent tool lists
  --server               Linux host checks for a box that runs agents (VPS, homelab):
                         systemd units, public listeners + ufw, docker.sock, sshd,
                         root SSH keys held by agents, CLI credential stores in every home.
                         Without --path it also walks /opt, /srv, /etc and the home dirs.
  --label <name>         display name for the stack on the report and card (e.g. "prod-agent")
  --min-grade <A-F>      exit 1 if the overall grade is worse (for CI)
  --lock-file <file>     lockfile to write/verify (default: <project>/agent-xray.lock)
  --user                 lock/verify user-level files too (default: project files only)
  --badge <file.svg>     write a Harness Hygiene badge SVG for the grade
  --iocs <file.json>     extra IOC list merged over the bundled one (same format as src/iocs.json)
  --verbose              show details for every finding
  --no-color             disable colors (also honors NO_COLOR)
  -v, --version          print version
  -h, --help             show this help

Read-only and offline: nothing is written (except --html / --card / --badge / lock), nothing is uploaded,
nothing found is ever executed (hooks, MCP servers, packages),
secret values are never printed (only redacted previews like sk-...abcd).`;

export function parseArgs(argv) {
  const o = { cmd: 'scan', json: false, card: null, fixPrompt: false, deep: false, project: undefined, minGrade: null, verbose: false, color: undefined, help: false, version: false, home: undefined, paths: [], server: false, label: null, html: null, open: false, fromJson: null, ci: false, lockFile: null, user: false, badge: null, iocs: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === 'demo' || a === 'scan' || a === 'lock' || a === 'verify') o.cmd = a;
    else if (a === '--ci') o.ci = true;
    else if (a === '--lock-file') o.lockFile = path.resolve(val());
    else if (a === '--user') o.user = true;
    else if (a === '--badge') o.badge = val();
    else if (a === '--iocs') o.iocs = path.resolve(val());
    else if (a === '--json') o.json = true;
    else if (a === '--card') o.card = val();
    else if (a.startsWith('--card=')) o.card = a.slice(7);
    else if (a === '--fix-prompt') o.fixPrompt = true;
    else if (a === '--html') { const n = argv[i + 1]; o.html = n !== undefined && !n.startsWith('-') && !['demo', 'scan', 'lock', 'verify'].includes(n) ? (i++, n) : true; }
    else if (a.startsWith('--html=')) o.html = a.slice(7) || true;
    else if (a === '--open') o.open = true;
    else if (a === '--from-json') o.fromJson = path.resolve(val());
    else if (a.startsWith('--from-json=')) o.fromJson = path.resolve(a.slice(12));
    else if (a === '--deep') o.deep = true;
    else if (a === '--project') o.project = path.resolve(val());
    else if (a === '--no-project') o.project = null;
    else if (a === '--home') o.home = path.resolve(val()); // testing / auditing a mounted home
    else if (a === '--path') o.paths.push(path.resolve(val()));
    else if (a.startsWith('--path=')) o.paths.push(path.resolve(a.slice(7)));
    else if (a === '--server' || a === '--host') o.server = true;
    else if (a === '--label') o.label = val();
    else if (a === '--sys-root') o.sysRoot = path.resolve(val()); // testing: treat this folder as /
    else if (a === '--min-grade') o.minGrade = val().toUpperCase();
    else if (a === '--verbose') o.verbose = true;
    else if (a === '--no-color') o.color = false;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else throw new Error(`Unknown option: ${a}`);
  }
  return o;
}

/** Launch the OS default browser, detached. Never throws. Tests set AGENT_XRAY_NO_OPEN=1. */
export function openInBrowser(file, env = process.env, platform = process.platform) {
  if (env.AGENT_XRAY_NO_OPEN) return { ok: false, reason: 'disabled by AGENT_XRAY_NO_OPEN' };
  if (platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) return { ok: false, reason: 'no desktop session' };
  const [cmd, args] = platform === 'darwin' ? ['open', [file]] : platform === 'win32' ? ['cmd', ['/c', 'start', '""', file]] : ['xdg-open', [file]];
  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => {});
    child.unref();
    return { ok: true };
  } catch (e) { return { ok: false, reason: e.message }; }
}

export async function main(argv = process.argv.slice(2), io = { out: process.stdout, err: process.stderr, env: process.env }) {
  let o;
  try { o = parseArgs(argv); } catch (e) { io.err.write(`${e.message}\n\n${HELP}\n`); return 2; }
  if (o.help) { io.out.write(HELP + '\n'); return 0; }
  if (o.version) { io.out.write(VERSION + '\n'); return 0; }

  let report, demo;
  if (o.open && !o.html) o.html = true;
  if (o.fromJson) {
    try { report = JSON.parse(fs.readFileSync(o.fromJson, 'utf8')); } catch (e) { io.err.write(`Could not read ${o.fromJson}: ${e.message}\n`); return 2; }
    if (report?.tool !== 'agent-xray' || !Array.isArray(report.findings)) { io.err.write(`${o.fromJson} is not an agent-xray --json report\n`); return 2; }
    annotateFixes(report);
  } else if (o.cmd === 'demo') {
    demo = buildDemoHome();
    try {
      report = scan({ home: demo.home, env: demo.env, project: demo.project, platform: 'linux', deep: true, sample: true, ...demo.opts });
    } finally { demo.cleanup(); }
  } else {
    report = scan({ home: o.home, project: o.project, deep: o.deep, env: io.env, paths: o.paths, server: o.server, label: o.label, sysRoot: o.sysRoot, iocs: o.iocs });
  }

  // ---- lockfile: write / verify ----
  const home = o.home || io.env.HOME || io.env.USERPROFILE || os.homedir();
  const project = o.project === undefined ? process.cwd() : o.project;
  const lockFile = o.lockFile || (project ? path.join(project, LOCK_NAME) : null);
  if (o.cmd === 'lock') {
    if (!lockFile) { io.err.write('lock needs a project folder (or --lock-file).\n'); return 2; }
    const lock = buildLock(report, { home, project, user: o.user });
    fs.writeFileSync(lockFile, serializeLock(lock));
    io.out.write(`Lock written: ${T(lockFile)} (${Object.keys(lock.files).length} files, ${lock.autorun.length} auto-run entries, ${Object.keys(lock.mcpServers).length} MCP servers; scope: ${lock.scope})\n`);
    io.out.write('Commit it, then run `npx @non-zero_ai/agent-xray verify` (or --ci) to catch anything that changes or appears.\n');
    return 0;
  }
  if ((o.cmd === 'verify' || o.ci) && !report.sample && !o.fromJson) {
    let old = null;
    if (lockFile && fs.existsSync(lockFile)) {
      try { old = readLock(lockFile); } catch (e) { io.err.write(`${e.message}\n`); return 2; }
    }
    if (!old) {
      report.lock = { file: lockFile ? T(lockFile) : null, status: 'missing', changes: 0 };
      if (o.cmd === 'verify') { io.err.write(`No lock found at ${lockFile ? T(lockFile) : '(no project)'}. Run \`npx @non-zero_ai/agent-xray lock\` first.\n`); return 2; }
    } else {
      const cur = buildLock(report, { home, project, user: old.scope === 'project+user' || o.user });
      const drift = diffLock(old, cur);
      report.lock = { file: T(lockFile), status: drift.length ? 'drift' : 'ok', changes: drift.length };
      if (drift.length) {
        report.findings.push(...driftFindings(drift, T(lockFile)));
        if (!report.agents.some((a) => a.id === 'shared')) report.agents.push({ id: 'shared', name: 'Shared / project files', files: [], servers: 0 });
        report.counts.lockDrift = drift.length;
        const R = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        report.findings.sort((a, b) => R[a.severity] - R[b.severity]);
        report.counts.bySeverity = Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, report.findings.filter((f) => f.severity === s).length]));
        grade(report);
        report.badge = badgeFor(report.overall.grade, { infected: report.infected?.status === 'indicators' });
        annotateFixes(report);
      }
    }
  }

  if (o.ci) io.out.write(renderCi(report) + '\n');
  else if (o.json) io.out.write(JSON.stringify(report, null, 2) + '\n');
  else if (o.fixPrompt) io.out.write(renderFixPrompt(report) + '\n');
  else {
    const color = o.color ?? (!!io.out.isTTY && !io.env.NO_COLOR && io.env.TERM !== 'dumb');
    io.out.write(renderTerminal(report, { color, verbose: o.verbose, html: !!o.html }) + '\n');
  }

  if (o.html) {
    const target = path.resolve(o.html === true ? (report.sample ? 'agent-xray-sample-report.html' : 'agent-xray-report.html') : /\.html?$/i.test(o.html) ? o.html : o.html + '.html');
    fs.writeFileSync(target, renderHtml(report));
    io.err.write(`HTML report written: ${T(target)}\n`);
    if (o.open) {
      const r = openInBrowser(target, io.env);
      io.err.write(r.ok ? 'Opened it in your browser.\n' : `Could not open a browser (${r.reason}). Open the file above manually.\n`);
    }
  }

  if (o.card) {
    const svg = renderCardSvg(report);
    let target = path.resolve(o.card);
    if (/\.svg$/i.test(target)) { fs.writeFileSync(target, svg); io.err.write(`Card written: ${T(target)}\n`); }
    else {
      if (!/\.png$/i.test(target)) target += '.png';
      const r = svgToPng(svg, target, { env: io.env });
      if (r.ok) io.err.write(`Card written: ${T(target)}\n`);
      else {
        const svgPath = target.replace(/\.png$/i, '.svg');
        fs.writeFileSync(svgPath, svg);
        io.err.write(`${r.reason} Wrote SVG instead: ${T(svgPath)}\n`);
      }
    }
  }

  if (o.badge) {
    const target = path.resolve(/\.svg$/i.test(o.badge) ? o.badge : o.badge + '.svg');
    fs.writeFileSync(target, badgeSvg(report.overall.grade, { infected: report.infected?.status === 'indicators' }));
    io.err.write(`Badge written: ${T(target)}\n`);
  }

  if (o.cmd === 'verify' && report.lock?.status === 'drift') {
    if (!o.ci && !o.json) io.err.write(`agent-xray.lock: ${report.lock.changes} change(s) since the lock. Review them above; if intended, run \`npx @non-zero_ai/agent-xray lock\`.\n`);
    return 1;
  }
  if (o.ci) {
    if (report.lock?.status === 'drift' || report.counts.bySeverity.critical || report.infected?.status === 'indicators') return 1;
  }
  if (o.minGrade) {
    const order = BANDS.map(([g]) => g);
    if (!order.includes(o.minGrade)) { io.err.write(`--min-grade must be one of ${order.join(', ')}\n`); return 2; }
    if (report.overall.grade && order.indexOf(report.overall.grade) > order.indexOf(o.minGrade)) return 1;
  }
  return 0;
}

/** CI output: GitHub Actions workflow commands (::error/::warning) plus a short summary. No secret values. */
export function renderCi(report) {
  const esc = (s) => String(s ?? '').replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  const escP = (s) => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
  const L = [];
  for (const f of report.findings) {
    if (f.severity === 'info' || f.severity === 'low') continue;
    const level = f.severity === 'critical' || f.category === 'infected' || f.category === 'lock-drift' ? 'error' : 'warning';
    const proj = report.project && !String(report.project).startsWith('~') ? String(report.project).replace(/[\\/]+$/, '') + '/' : null;
    let file = f.file && !String(f.file).startsWith('~') ? String(f.file).replace(/^\.\//, '') : null;
    if (file && proj && file.startsWith(proj)) file = file.slice(proj.length);
    const props = [file && `file=${escP(file)}`, file && f.line && `line=${f.line}`, `title=${escP(`agent-xray ${f.severity}: ${f.id}`)}`].filter(Boolean).join(',');
    L.push(`::${level} ${props}::${esc(f.title + (f.evidence ? ` (${f.evidence})` : ''))}`);
  }
  const c = report.counts;
  L.push(`agent-xray ${report.version}: Harness Hygiene ${report.overall.grade || 'n/a'}${report.overall.score != null ? ` (${report.overall.score}/100)` : ''}`);
  L.push(`  infected: ${report.infected?.status || 'n/a'} · critical ${c.bySeverity.critical} · high ${c.bySeverity.high} · auto-run ${c.autorunEntries ?? 0} (${c.riskyAutorun ?? 0} risky) · lock: ${report.lock?.status || 'not checked'}${report.lock?.changes ? ` (${report.lock.changes} changes)` : ''}`);
  if (report.infected?.status === 'indicators') L.push('  INFECTION INDICATORS: remove the persistence service BEFORE rotating any token. Run `npx @non-zero_ai/agent-xray` locally for the steps.');
  if (report.badge) L.push(`  badge: ${report.badge.markdown}`);
  return L.join('\n');
}
