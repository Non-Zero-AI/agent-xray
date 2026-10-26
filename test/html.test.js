import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fixtureHome } from './helpers.js';
import { buildDemoHome, FAKE } from '../src/demo.js';
import { scan } from '../src/scan.js';
import { grade } from '../src/grade.js';
import { renderHtml, CLIENT_GRADE, safeJson } from '../src/render/html.js';
import { renderTerminal } from '../src/render/terminal.js';
import { fixFor, annotateFixes } from '../src/fixes.js';
import { findBrowser } from '../src/render/png.js';
import { main } from '../src/cli.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const BIN = path.join(ROOT, 'bin', 'agent-xray.js');
// assembled at runtime so no secret-shaped literal is committed
const SECRET = 'gh' + 'p_' + 'HTMLTESTnotreal0123456789abcdefABCDEF';
const XSS1 = '</script><script>document.title="PWNED"</script>';
const XSS2 = '<img src=x onerror="document.title=\'PWNED\'">';

function demoReport() {
  const d = buildDemoHome();
  try { return scan({ home: d.home, env: d.env, project: d.project, platform: 'linux', deep: true, sample: true, ...d.opts }); } finally { d.cleanup(); }
}
function hostileFixture() {
  return fixtureHome({
    '.claude.json': { mcpServers: {
      [XSS1]: { command: 'npx', args: ['-y', '@evil/pkg', XSS2], env: { GITHUB_PERSONAL_ACCESS_TOKEN: SECRET } },
      [XSS2]: { url: 'http://mcp.example.invalid/sse' },
    } },
    '.claude/settings.json': { permissions: { defaultMode: 'bypassPermissions', allow: ['Bash(*)'] } },
  });
}

test('every finding carries fixer, agent_prompt and human_steps', () => {
  const r = demoReport();
  assert.ok(r.findings.length > 20);
  for (const f of r.findings) {
    assert.ok(['agent', 'human', 'both'].includes(f.fixer), f.id);
    assert.ok(Array.isArray(f.human_steps), f.id);
    if (f.fixer === 'human') assert.equal(f.agent_prompt, null, f.id);
    else {
      assert.equal(typeof f.agent_prompt, 'string', f.id);
      assert.match(f.agent_prompt, /ONE issue/);
      assert.match(f.agent_prompt, /NEVER print/);
      assert.match(f.agent_prompt, /Back up every file/);
      assert.match(f.agent_prompt, /npx agent-xray/);
    }
    if (f.fixer !== 'agent') assert.ok(f.human_steps.length > 0, f.id);
    for (const d of f.docs || []) assert.match(d.url, /^https:\/\//);
  }
  const yolo = r.findings.find((f) => f.id === 'claude.bypass');
  assert.equal(yolo.fixer, 'agent');
  const gh = r.findings.find((f) => f.id === 'secret.plaintext' && f.credential === 'github');
  assert.equal(gh.fixer, 'both');
  assert.ok(gh.docs.some((d) => d.url.includes('github.com/settings/tokens')));
});

test('human-only and server guidance: root SSH keys, CLI logins, live-server rule', () => {
  const ssh = fixFor({ id: 'host.agentRootSsh', severity: 'medium', category: 'host-exposure', agents: ['shared'], title: '4 automated agent keys have full root SSH', file: '~/.ssh/authorized_keys' }, { server: true });
  assert.equal(ssh.fixer, 'human');
  assert.ok(ssh.human_steps.some((s) => /second SSH session/.test(s)));
  const gh = fixFor({ id: 'secret.plaintext', severity: 'medium', category: 'secret', agents: ['shared'], title: 'GitHub CLI login token stored in plain text', credential: 'cli-store', file: '~/.config/gh/hosts.yml' }, { server: true });
  assert.equal(gh.fixer, 'human');
  assert.ok(gh.docs.some((d) => d.url === 'https://cli.github.com/manual/gh_auth_logout'));
  const sr = fixFor({ id: 'secret.plaintext', severity: 'high', category: 'secret', agents: ['shared'], title: 'Plaintext Supabase service_role key (in a .env file)', file: '~/app/.env', line: 3, evidence: 'eyJ...abcd' }, { server: true, verify: 'npx agent-xray --server' });
  assert.equal(sr.fixer, 'both');
  assert.match(sr.human_steps.join(' '), /Supabase/);
  assert.match(sr.agent_prompt, /live server/);
  assert.match(sr.agent_prompt, /npx agent-xray --server/);
});

test('HTML: no secret values, no raw injected markup, no external resources', () => {
  const fx = hostileFixture();
  try {
    const r = fx.scan();
    assert.ok(r.findings.some((f) => f.title.includes(XSS1)), 'fixture puts the payload in a finding title');
    const html = renderHtml(r);
    assert.ok(!html.includes(SECRET), 'leaks the secret');
    assert.ok(!html.includes(SECRET.slice(-12)), 'leaks the secret tail');
    assert.ok(!html.includes(XSS1), 'raw </script> payload');
    assert.ok(!html.includes(XSS2), 'raw <img onerror> payload');
    assert.ok(!/<img[^>]*onerror/i.test(html));
    assert.equal((html.match(/<\/script>/g) || []).length, 2, 'only the two real script blocks close');
    assert.ok(!/<script[^>]+src=/i.test(html), 'no external scripts');
    assert.ok(!/<link\b/i.test(html), 'no <link>');
    assert.ok(!/@import/i.test(html), 'no @import');
    assert.ok(!/url\((?!#)/i.test(html.replace(/data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+/g, '')), 'no external url()');
    assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
    assert.ok(!html.includes(fx.home), 'leaks home path');
    // the embedded data round-trips to exactly the original strings
    const json = /<script type="application\/json" id="axr-data">([\s\S]*?)<\/script>/.exec(html)[1];
    const data = JSON.parse(json);
    assert.ok(data.report.findings.some((f) => f.title.includes(XSS1)));
  } finally { fx.cleanup(); }
});

test('HTML demo report: no FAKE secret, labelled SAMPLE, all sections present', () => {
  const html = renderHtml(demoReport());
  for (const [k, v] of Object.entries(FAKE)) {
    assert.ok(!html.includes(v), `leaks ${k}`);
    assert.ok(!html.includes(v.slice(-12)), `leaks tail of ${k}`);
  }
  assert.match(html, /SAMPLE DATA/);
  for (const id of ['fixall', 'verify', 'tailor', 'toolbar', 'list', 'ring']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /data:image\/svg\+xml;base64,/);
});

test('safeJson escapes characters that could end a script block', () => {
  const s = safeJson({ a: '</script><!-- & \u2028\u2029 >' });
  assert.ok(!/[<>&\u2028\u2029]/.test(s));
  assert.deepEqual(JSON.parse(s), { a: '</script><!-- & \u2028\u2029 >' });
});

test('client-side projected score matches grade() for any set of fixed findings', () => {
  const r = demoReport();
  const gradeClient = new Function(`${CLIENT_GRADE}; return gradeClient;`)();
  const subsets = [[], r.findings.map(() => true), r.findings.map((f) => f.severity === 'critical'), r.findings.map((_, i) => i % 2 === 0), r.findings.map((f) => f.severity !== 'low')];
  for (const fixed of subsets) {
    const copy = JSON.parse(JSON.stringify(r));
    copy.findings = copy.findings.filter((_, i) => !fixed[i]);
    grade(copy);
    const c = gradeClient(r.agents, r.findings, fixed);
    assert.equal(c.score, copy.overall.score);
    assert.equal(c.grade, copy.overall.grade);
  }
});

function capture(env = { PATH: '' }) {
  let out = '', err = '';
  return { io: { out: { write: (s) => { out += s; }, isTTY: false }, err: { write: (s) => { err += s; } }, env }, get out() { return out; }, get err() { return err; } };
}

test('CLI: --html writes a file, --from-json re-renders, terminal advertises --html', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-html-'));
  try {
    let c = capture();
    const out = path.join(dir, 'r.html');
    assert.equal(await main(['demo', '--html', out], c.io), 0);
    assert.ok(fs.existsSync(out));
    assert.match(c.err, /HTML report written: .*r\.html/);
    assert.match(c.out, /--html --open/);
    // --html with no value right before another flag
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      c = capture();
      assert.equal(await main(['demo', '--html', '--no-color'], c.io), 0);
      assert.ok(fs.existsSync(path.join(dir, 'agent-xray-sample-report.html')));
    } finally { process.chdir(cwd); }
    // --json -> --from-json, and annotateFixes fills in fields missing from older reports
    c = capture();
    assert.equal(await main(['demo', '--json'], c.io), 0);
    const r = JSON.parse(c.out);
    for (const f of r.findings) { delete f.fixer; delete f.agent_prompt; delete f.human_steps; delete f.docs; }
    const jf = path.join(dir, 'r.json');
    fs.writeFileSync(jf, JSON.stringify(r));
    c = capture({ PATH: '', AGENT_XRAY_NO_OPEN: '1' });
    const out2 = path.join(dir, 'from.html');
    assert.equal(await main(['--from-json', jf, '--html', out2, '--open'], c.io), 0);
    assert.match(c.err, /Could not open a browser/);
    const html = fs.readFileSync(out2, 'utf8');
    assert.match(html, /Your agent can fix this/);
    assert.ok(!html.includes(FAKE.github));
    // bad --from-json
    fs.writeFileSync(path.join(dir, 'bad.json'), '{"hello":1}');
    c = capture();
    assert.equal(await main(['--from-json', path.join(dir, 'bad.json')], c.io), 2);
    // help mentions it
    c = capture();
    await main(['--help'], c.io);
    assert.match(c.out, /--html \[file\]/);
    assert.match(c.out, /--from-json/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('annotateFixes is idempotent', () => {
  const r = demoReport();
  const before = JSON.stringify(r.findings);
  annotateFixes(r);
  assert.equal(JSON.stringify(r.findings), before);
  assert.match(renderTerminal(r, { color: false }), /Interactive report/);
});

const browser = findBrowser(process.env, process.platform);
test('HTML renders in a real browser and injected markup stays inert', { skip: !browser && 'no Chrome/Chromium found' }, () => {
  const fx = hostileFixture();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-dom-'));
  try {
    const file = path.join(dir, 'x.html');
    fs.writeFileSync(file, renderHtml(fx.scan()));
    const res = spawnSync(browser, ['--headless', '--no-sandbox', '--disable-gpu', '--virtual-time-budget=2000', '--dump-dom', 'file://' + file], { encoding: 'utf8', timeout: 30000 });
    const dom = res.stdout || '';
    assert.match(dom, /<article class="card/, 'findings rendered');
    assert.ok(!/<title>PWNED/.test(dom), 'payload executed');
    assert.ok(!/<img[^>]*onerror/i.test(dom.replace(/<script type="application\/json"[\s\S]*?<\/script>/, '')), 'payload became markup');
    assert.ok(dom.includes('&lt;/script&gt;&lt;script&gt;'), 'payload shown as text');
  } finally { fx.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});
