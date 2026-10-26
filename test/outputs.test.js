import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { scan } from '../src/scan.js';
import { buildDemoHome, FAKE } from '../src/demo.js';
import { renderTerminal } from '../src/render/terminal.js';
import { renderCardSvg } from '../src/render/card.js';
import { renderFixPrompt } from '../src/render/fixprompt.js';
import { main } from '../src/cli.js';
import { renderHtml } from '../src/render/html.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const BIN = path.join(ROOT, 'bin', 'agent-xray.js');

function demoReport() {
  const d = buildDemoHome();
  try { return { r: scan({ home: d.home, env: d.env, project: d.project, platform: 'linux', deep: true, sample: true, ...d.opts }), home: d.home }; } finally { d.cleanup(); }
}

test('demo report: expected headline numbers', () => {
  const { r } = demoReport();
  assert.equal(r.sample, true);
  assert.equal(r.overall.grade, 'F');
  assert.equal(r.counts.yoloAgents, 2);
  assert.equal(r.counts.plaintextSecrets, 7);
  assert.equal(r.counts.mcpServers, 10);
  assert.ok(r.counts.unpinnedPackages >= 5);
});

test('NO raw secret value, home path or username appears in any output', () => {
  const { r, home } = demoReport();
  const outputs = {
    json: JSON.stringify(r),
    terminal: renderTerminal(r, { color: false, verbose: true }),
    card: renderCardSvg(r),
    fixPrompt: renderFixPrompt(r),
    html: renderHtml(r),
  };
  for (const [name, out] of Object.entries(outputs)) {
    for (const [k, secret] of Object.entries(FAKE)) {
      assert.ok(!out.includes(secret), `${name} leaks ${k}`);
      assert.ok(!out.includes(secret.slice(-12)), `${name} leaks the tail of ${k}`);
    }
    assert.ok(!out.includes(home), `${name} leaks home path`);
    assert.ok(!out.includes('/home/demo'), `${name} leaks username path`);
  }
  assert.ok(!/~\/|\/home\/|\/Users\/|\.json|\.toml|\.env\b/.test(outputs.card), 'card contains no file paths');
});

test('report matches schema (required keys + enums)', () => {
  const { r } = demoReport();
  const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'schema', 'report.schema.json'), 'utf8'));
  for (const k of schema.required) assert.ok(k in r, k);
  assert.equal(r.schemaVersion, schema.properties.schemaVersion.const);
  const F = schema.properties.findings.items;
  for (const f of r.findings) {
    for (const k of F.required) assert.ok(k in f, k);
    assert.ok(F.properties.severity.enum.includes(f.severity));
    assert.ok(F.properties.category.enum.includes(f.category), f.category);
    assert.ok(F.properties.fixer.enum.includes(f.fixer), f.fixer);
    assert.ok(f.agent_prompt === null || typeof f.agent_prompt === 'string');
    assert.ok(Array.isArray(f.human_steps));
  }
  for (const a of r.agents) assert.ok(schema.properties.agents.items.properties.id.enum.includes(a.id));
});

test('terminal colors: off for non-TTY / NO_COLOR', () => {
  const { r } = demoReport();
  assert.ok(!renderTerminal(r, { color: false }).includes('\x1b['));
  assert.ok(renderTerminal(r, { color: true }).includes('\x1b['));
});

function capture() {
  let out = '', err = '';
  return { io: { out: { write: (s) => { out += s; }, isTTY: false }, err: { write: (s) => { err += s; } }, env: { PATH: '' } }, get out() { return out; }, get err() { return err; } };
}

test('CLI: help, version, bad flag, demo --json, --min-grade, --card svg', async () => {
  let c = capture();
  assert.equal(await main(['--help'], c.io), 0);
  assert.match(c.out, /Usage/);
  c = capture();
  assert.equal(await main(['--version'], c.io), 0);
  assert.match(c.out, /^\d+\.\d+\.\d+/);
  c = capture();
  assert.equal(await main(['--nope'], c.io), 2);
  c = capture();
  assert.equal(await main(['demo', '--json'], c.io), 0);
  assert.equal(JSON.parse(c.out).sample, true);
  c = capture();
  assert.equal(await main(['demo', '--json', '--min-grade', 'C'], c.io), 1);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-card-'));
  try {
    c = capture();
    assert.equal(await main(['demo', '--card', path.join(tmp, 'c.svg')], c.io), 0);
    const svg = fs.readFileSync(path.join(tmp, 'c.svg'), 'utf8');
    assert.match(svg, /SAMPLE DATA/);
    assert.match(svg, /npx @non-zero_ai\/agent-xray/);
    c = capture(); // PATH empty and no browser override -> PNG falls back to SVG (unless a Playwright cache exists)
    assert.equal(await main(['demo', '--card', path.join(tmp, 'c.png')], { ...c.io, env: { PATH: '', HOME: tmp } }), 0);
    assert.ok(fs.existsSync(path.join(tmp, 'c.svg')));
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('CLI: fix prompt is redacted and actionable', async () => {
  const c = capture();
  assert.equal(await main(['demo', '--fix-prompt'], c.io), 0);
  assert.match(c.out, /NEVER print/);
  assert.match(c.out, /\[CRITICAL\]/);
  assert.match(c.out, /rotate|ROTATE/);
  for (const s of Object.values(FAKE)) assert.ok(!c.out.includes(s));
});

test('bin runs as a real process and never writes into the cwd', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-cwd-'));
  try {
    const res = spawnSync(process.execPath, [BIN, 'demo'], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /AGENT X-RAY/);
    assert.match(res.stdout, /SAMPLE/);
    assert.deepEqual(fs.readdirSync(cwd), []);
  } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
});

test('scanner is read-only: fixture files are byte-identical after a scan', () => {
  const d = buildDemoHome();
  try {
    const snap = (dir) => fs.readdirSync(dir, { recursive: true, withFileTypes: false }).sort().map((f) => {
      const p = path.join(dir, f);
      return fs.statSync(p).isFile() ? `${f}:${fs.readFileSync(p, 'utf8').length}:${fs.statSync(p).mtimeMs}` : f;
    }).join('\n');
    const before = snap(d.home);
    scan({ home: d.home, env: d.env, project: d.project, platform: 'linux', deep: true, ...d.opts });
    assert.equal(snap(d.home), before);
  } finally { d.cleanup(); }
});
