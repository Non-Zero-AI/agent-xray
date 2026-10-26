import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { classify, parseEnv, isBackup } from '../src/stack.js';
import { parseProcNet, parseAuthorizedKeys, parseUnit } from '../src/host.js';
import { classifyCredential } from '../src/secrets.js';
import { renderTerminal } from '../src/render/terminal.js';
import { renderCardSvg } from '../src/render/card.js';
import { renderFixPrompt } from '../src/render/fixprompt.js';
import { byId, agent } from './helpers.js';

// All credentials below are FAKE, built at runtime so no secret-looking literal lives in the repo.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'fakefakefake', ...claims })}.${'s'.repeat(10)}FAKEsig${'x'.repeat(20)}`;
const SERVICE = jwt({ role: 'service_role' });
const ANON = jwt({ role: 'anon' });
const HF = 'hf_' + 'F'.repeat(30) + 'AKE1';
const GHO = 'gho_' + 'Q'.repeat(32) + 'FAKE';
const OPENAI = 'sk-proj-' + 'Z'.repeat(30) + 'FAKE';

function sysFixture(files, modes = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-sys-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    fs.chmodSync(p, modes[rel] ?? 0o600);
  }
  const home = path.join(root, 'root');
  fs.mkdirSync(home, { recursive: true });
  return {
    root, home,
    scan: (o = {}) => scan({ home, env: { HOME: home, PATH: '' }, platform: 'linux', project: null, now: '2026-01-01T00:00:00.000Z', sysRoot: root, ...o }),
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

const hex = (p) => p.toString(16).toUpperCase().padStart(4, '0');
const tcp = (rows) => '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n' + rows.map(([a, p], i) => `   ${i}: ${a}:${hex(p)} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 ${1000 + i} 1 0000000000000000 100 0 0 10 0`).join('\n') + '\n';

const SELF_HOSTED = {
  'root/myapp/.env': `NEXT_PUBLIC_SUPABASE_URL=https://fakefakefake.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=${SERVICE}\nFEATURE_FLAG=true\n`,
  'root/quarantine/old/.env': `SUPABASE_SERVICE_ROLE_KEY=${SERVICE}\n`,
  'root/.hf_token': HF + '\n',
  'root/.config/gh/hosts.yml': `github.com:\n    oauth_token: ${GHO}\n    user: someone\n`,
  'etc/agent-svc/config.json': { public_api_key: ANON, default_model: 'google/gemini-fake', fallback_models: ['anthropic/claude-fake'], enabled_operations: ['mail.messages.read', 'mail.messages.send', 'calendar.events.create', 'calendar.events.delete', 'ledger.read'] },
  'etc/agent-svc/config.json.prev-1': { public_api_key: ANON },
  'etc/agent-svc/credentials/openai.secret.fernet': 'gAAAAAfake',
  'etc/agent-svc/credentials/service.key': 'k'.repeat(43) + '=',
  'etc/systemd/system/agent.service': '[Service]\nUser=agent\nNoNewPrivileges=yes\nProtectSystem=strict\nExecStart=/opt/agent/run\n',
  'etc/systemd/system/old-worker.service': '[Service]\nWorkingDirectory=/root/myapp\nEnvironmentFile=/root/myapp/.env\nExecStart=/usr/bin/node worker.js\n',
  'etc/systemd/system/multi-user.target.wants/agent.service': '',
  'etc/ssh/sshd_config': 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n',
  'etc/ufw/ufw.conf': 'ENABLED=yes\n',
  'etc/default/ufw': 'DEFAULT_INPUT_POLICY="DROP"\n',
  'etc/ufw/user.rules': '### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n',
  'etc/fail2ban/jail.local': '[sshd]\nenabled = true\n',
  'root/.ssh/authorized_keys': ['ssh-ed25519 AAAAC3NzaFAKE1 admin@example.com', 'ssh-ed25519 AAAAC3NzaFAKE2', 'ssh-ed25519 AAAAC3NzaFAKE3 deploy-agent@ci', 'ssh-ed25519 AAAAC3NzaFAKE4 claude-runner', 'command="/bin/true" ssh-ed25519 AAAAC3NzaFAKE5 backup-bot'].join('\n') + '\n',
  'proc/net/tcp': tcp([['00000000', 22], ['0100007F', 3000], ['0100007F', 2019], ['00000000', 443], ['00000000', 5678]]),
  'proc/net/tcp6': tcp([['00000000000000000000000000000000', 80]]),
};

test('server mode: self-hosted stack gets a real grade, secrets redacted', () => {
  const fx = sysFixture(SELF_HOSTED);
  try {
    const r = fx.scan({ server: true, label: 'Demo Stack' });
    assert.equal(r.mode, 'server');
    assert.equal(agent(r, 'stack').name, 'Demo Stack');
    assert.ok(agent(r, 'host'));
    const titles = r.findings.map((f) => f.title).join('\n');
    // service_role recognized, anon ignored, duplicate counted once
    const sr = byId(r, 'secret.plaintext').filter((f) => /service_role/.test(f.title));
    assert.equal(sr.length, 1, titles);
    assert.match(sr[0].detail, /Row Level Security/);
    assert.ok(/myapp[\/]\.env/.test(sr[0].file) && !/quarantine/.test(sr[0].file), 'main finding points at the live copy, not the quarantine backup');
    assert.ok(byId(r, 'secret.duplicate').some((f) => /service_role/.test(f.title)));
    assert.ok(!titles.includes('public_api_key'), 'anon key must not be flagged');
    // CLI token stores and loose token files
    assert.ok(r.findings.some((f) => /GitHub CLI login token/.test(f.title) && f.severity === 'medium'));
    assert.ok(r.findings.some((f) => /Hugging Face token in a loose token file/.test(f.title)));
    // host checks
    const rootSvc = byId(r, 'host.rootService');
    assert.equal(rootSvc.length, 1);
    assert.equal(rootSvc[0].severity, 'low'); // disabled unit
    assert.ok(/old-worker/.test(rootSvc[0].title));
    const agentSsh = byId(r, 'host.agentRootSsh')[0];
    assert.ok(agentSsh && /2 automated agent keys/.test(agentSsh.title), titles);
    assert.equal(byId(r, 'host.unlabeledKey')[0].severity, 'low');
    const port = byId(r, 'host.publicListener');
    assert.equal(port.length, 1);
    assert.equal(port[0].severity, 'low'); // n8n port, but ufw blocks it
    assert.ok(/5678/.test(port[0].title));
    assert.ok(byId(r, 'stack.keyNextToVault').length === 1);
    // inventory + strengths
    assert.equal(r.stack.tools.length, 1, 'backup configs are not listed as live tools');
    assert.equal(r.stack.backupConfigs, 1);
    assert.equal(r.stack.tools[0].total, 5);
    assert.deepEqual(r.stack.tools[0].write.sort(), ['calendar.events.create', 'calendar.events.delete', 'mail.messages.send']);
    assert.deepEqual(r.stack.models, ['anthropic/claude-fake', 'google/gemini-fake']);
    const good = r.strengths.join('\n');
    assert.match(good, /encrypted at rest/);
    assert.match(good, /password login off/);
    assert.match(good, /fail2ban/);
    assert.match(good, /default-deny/);
    assert.ok(['B', 'C', 'D'].includes(r.overall.grade), `${r.overall.grade} ${r.overall.score}`);
    // nothing secret anywhere
    const outs = [JSON.stringify(r), renderTerminal(r, { color: false, verbose: true }), renderCardSvg(r), renderFixPrompt(r)];
    for (const o of outs) for (const s of [SERVICE, ANON, HF, GHO, 'k'.repeat(43)]) assert.ok(!o.includes(s), 'secret leaked');
    const card = renderCardSvg(r);
    assert.ok(!card.includes(fx.root) && !card.includes('/etc/') && !card.includes('~/'), 'card must not contain paths');
    assert.match(card, /Demo Stack/);
    assert.match(renderFixPrompt(r), /live server/);
  } finally { fx.cleanup(); }
});

test('server mode: enabled root service loading a .env is high; public agent port without firewall is high', () => {
  const files = { ...SELF_HOSTED, 'etc/systemd/system/multi-user.target.wants/old-worker.service': '', 'etc/ufw/ufw.conf': 'ENABLED=no\n',
    'proc/net/tcp': tcp([['00000000', 22], ['00000000', 443], ['00000000', 5678], ['00000000', 6001], ['00000000', 6002], ['00000000', 6003]]) };
  const fx = sysFixture(files);
  try {
    const r = fx.scan({ server: true });
    assert.equal(byId(r, 'host.rootService')[0].severity, 'high');
    assert.equal(byId(r, 'host.publicListener')[0].severity, 'high');
    assert.ok(byId(r, 'host.noFirewall').length === 1);
    const other = byId(r, 'host.publicListeners'); // unknown ports grouped into one finding, not one per port
    assert.equal(other.length, 1);
    assert.match(other[0].title, /^3 other ports/);
    assert.equal(other[0].severity, 'medium');
    assert.equal(agent(r, 'stack').name, 'Self-hosted agent stack');
  } finally { fx.cleanup(); }
});

test('--path: docker-compose with docker.sock, privileged, public n8n port and literal secrets', () => {
  const fx = sysFixture({
    'srv/n8n/docker-compose.yml': `services:\n  n8n:\n    image: n8nio/n8n:1.0\n    privileged: true\n    ports:\n      - "5678:5678"\n      - "127.0.0.1:9000:9000"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    environment:\n      - OPENAI_API_KEY=${OPENAI}\n      - N8N_HOST=\${HOST}\n    env_file: ./n8n.env\n`,
    'srv/n8n/n8n.env': `N8N_ENCRYPTION_KEY=${'e'.repeat(24)}FAKE\n`,
  }, { 'srv/n8n/n8n.env': 0o644 });
  try {
    const r = fx.scan({ paths: [path.join(fx.root, 'srv')] });
    assert.equal(r.mode, 'paths');
    assert.equal(byId(r, 'compose.dockerSock')[0].severity, 'critical');
    assert.equal(byId(r, 'compose.privileged').length, 1);
    const pub = byId(r, 'compose.publicPort');
    assert.equal(pub.length, 1, 'loopback-bound port must not be flagged');
    assert.equal(pub[0].severity, 'high');
    assert.ok(r.findings.some((f) => /OpenAI API key/.test(f.title)));
    const envSecret = r.findings.find((f) => /N8N_ENCRYPTION_KEY/.test(f.title));
    assert.ok(envSecret, r.findings.map((f) => f.title).join('\n'));
    assert.equal(envSecret.severity, 'critical'); // world-readable
    assert.equal(r.overall.grade, 'F');
    assert.ok(!JSON.stringify(r).includes(OPENAI));
  } finally { fx.cleanup(); }
});

test('--path: generic MCP config is picked up and analyzed like any agent config', () => {
  const fx = sysFixture({ 'opt/bot/mcp.json': { mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] }, api: { url: 'http://10.0.0.5/mcp', headers: { Authorization: `Bearer ${OPENAI}` } } } } });
  try {
    const r = fx.scan({ paths: [path.join(fx.root, 'opt')], label: 'MyBot' });
    assert.equal(r.counts.mcpServers, 2);
    assert.ok(r.servers.every((s) => s.agents.includes('stack')));
    assert.ok(r.findings.some((f) => f.category === 'broad-root'));
    assert.ok(r.findings.some((f) => f.category === 'insecure-remote'));
    assert.ok(r.findings.some((f) => f.category === 'secret'));
    assert.equal(agent(r, 'stack').name, 'MyBot');
  } finally { fx.cleanup(); }
});

test('without --path/--server nothing new is scanned (desktop behavior unchanged)', () => {
  const fx = sysFixture(SELF_HOSTED);
  try {
    const r = fx.scan();
    assert.equal(r.mode, undefined);
    assert.equal(r.stack, undefined);
    assert.equal(r.overall.grade, null);
  } finally { fx.cleanup(); }
});

test('stack unit helpers', () => {
  for (const p of ['/etc/x/config.json.prev-20261001T00Z', '/etc/x/config.json.pre-huddle-1', '/root/quarantine/a/.env', '/srv/app/.env.bak', '/srv/app/settings.yaml~']) assert.equal(isBackup(p), 1, p);
  for (const p of ['/etc/x/config.json', '/root/myapp_os/.env', '/srv/app/.env.production', '/opt/prevail/config.json', '/srv/app/.env.preview', '/srv/app/.env.oldschool']) assert.equal(isBackup(p), 0, p);
  assert.equal(classify('.env'), 'env');
  assert.equal(classify('.env.example'), null);
  assert.equal(classify('docker-compose.prod.yml'), 'compose');
  assert.equal(classify('compose.yaml'), 'compose');
  assert.equal(classify('.mcp.json'), 'mcp');
  assert.equal(classify('config.json.prev-20260101'), 'config');
  assert.equal(classify('.gh_deploy_pat'), 'token');
  assert.equal(classify('telegram-token'), 'token');
  assert.equal(classify('token.js'), null);
  assert.equal(classify('a.secret.fernet'), 'encrypted');
  assert.deepEqual(parseEnv('export A="x y"\nB=z # c\n# no\nC=\'q\''), { A: 'x y', B: 'z', C: 'q' });
  assert.equal(classifyCredential(ANON).publishable, true);
  assert.equal(classifyCredential(SERVICE).label, 'Supabase service_role key');
  assert.equal(classifyCredential(OPENAI).publishable, false);
});

test('host unit helpers: /proc/net/tcp, authorized_keys, systemd units', () => {
  const l = parseProcNet(tcp([['00000000', 5678], ['0100007F', 3000]]), false);
  assert.deepEqual(l.map((x) => [x.port, x.any, x.loopback]), [[5678, true, false], [3000, false, true]]);
  const v6 = parseProcNet(tcp([['00000000000000000000000001000000', 2019]]), true);
  assert.equal(v6[0].loopback, true);
  const k = parseAuthorizedKeys('# c\nssh-ed25519 AAAA a@b\nfrom="1.2.3.4" ssh-rsa BBBB ci-bot\nssh-ed25519 CCCC\n');
  assert.deepEqual(k.map((x) => [x.comment, x.restricted]), [['a@b', false], ['ci-bot', true], ['', false]]);
  const u = parseUnit('[Service]\nUser=x\nEnvironmentFile=-/etc/a\nEnvironmentFile=/etc/b\n');
  assert.deepEqual(u['Service.EnvironmentFile'], ['-/etc/a', '/etc/b']);
});
