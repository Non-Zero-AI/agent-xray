import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanText, redact, isPlaceholder, looksLikeSecretKey } from '../src/secrets.js';
import { allowRuleRisk, packageSpec, unwrapCommand, isBroadRoot, insecureUrl, terminalAllowRisk } from '../src/rules.js';
import { tildify } from '../src/paths.js';
import { locations } from '../src/agents.js';
import { scoreFindings, letter } from '../src/grade.js';
import { FAKE } from '../src/demo.js';

test('secret patterns detect common providers and report line numbers', () => {
  const text = `a\nkey=${FAKE.anthropic}\ngh: ${FAKE.github}\nurl: postgres://u:${FAKE.dbPassword}@h/db\n`;
  const hits = scanText(text);
  assert.deepEqual(hits.map((h) => h.kind).sort(), ['anthropic', 'github', 'url-password']);
  assert.equal(hits.find((h) => h.kind === 'anthropic').line, 2);
});

test('redact never reveals more than prefix + last 4', () => {
  const r = redact(FAKE.openai);
  assert.match(r, /^sk-proj-\.\.\..{4}$/);
  assert.ok(!r.includes(FAKE.openai.slice(8, -4)));
  assert.equal(redact('short'), '****');
  assert.match(redact('-----BEGIN PRIVATE KEY-----abc'), /\[redacted\]/);
});

test('placeholders and env references are not secrets', () => {
  for (const v of ['${env:GITHUB_TOKEN}', '$OPENAI_API_KEY', '%API_KEY%', '<your-key>', 'your_api_key_here', 'xxxxxxxxxxxx', '{{TOKEN}}', 'https://api.example.dev']) assert.ok(isPlaceholder(v), v);
  assert.ok(!isPlaceholder('a8f3k2l9q0w8e7r6'));
  assert.ok(looksLikeSecretKey('BRAVE_API_KEY'));
  assert.ok(!looksLikeSecretKey('authMethod'));
  assert.ok(!looksLikeSecretKey('max_tokens'));
});

test('allow-rule risk classification', () => {
  assert.equal(allowRuleRisk('Bash').severity, 'critical');
  assert.equal(allowRuleRisk('Bash(*)').severity, 'critical');
  assert.equal(allowRuleRisk('Bash(rm:*)').severity, 'high');
  assert.equal(allowRuleRisk('Shell(sudo)').severity, 'high');
  assert.equal(allowRuleRisk('run_shell_command(curl)').severity, 'high');
  assert.equal(allowRuleRisk('Bash(python:*)').severity, 'medium');
  assert.equal(allowRuleRisk('mcp__*').severity, 'medium');
  assert.equal(allowRuleRisk('Bash(npm run test:*)'), null);
  assert.equal(allowRuleRisk('Bash(git status)'), null);
  assert.equal(allowRuleRisk('Read(./src/**)'), null);
  assert.equal(terminalAllowRisk('*').severity, 'critical');
});

test('package pinning for npx / uvx / docker, incl. Windows cmd /c wrappers', () => {
  assert.equal(packageSpec('npx', ['-y', '@scope/pkg']).pinned, false);
  assert.equal(packageSpec('npx', ['-y', '@scope/pkg@latest']).pinned, false);
  assert.equal(packageSpec('npx', ['-y', '@scope/pkg@1.2.3']).pinned, true);
  assert.equal(packageSpec('npx', ['pkg@^1.0.0']).pinned, false);
  assert.equal(packageSpec('uvx', ['mcp-server-git']).pinned, false);
  assert.equal(packageSpec('uvx', ['mcp-server-git==0.6.2']).pinned, true);
  assert.equal(packageSpec('docker', ['run', '-i', '--rm', '-e', 'X', 'ghcr.io/a/b']).pinned, false);
  assert.equal(packageSpec('docker', ['run', '-i', 'ghcr.io/a/b@sha256:abc']).pinned, true);
  const u = unwrapCommand('cmd', ['/c', 'npx', '-y', 'pkg']);
  assert.equal(u.base, 'npx');
  assert.deepEqual(u.args, ['-y', 'pkg']);
  assert.equal(unwrapCommand('C:\\Program Files\\nodejs\\npx.cmd', ['-y', 'x']).base, 'npx');
});

test('broad roots and insecure urls (posix + Windows)', () => {
  for (const p of ['/', '~', '/Users/alice', '/home/alice/', 'C:\\', 'C:\\Users\\alice', 'C:\\Users\\alice\\', '%USERPROFILE%']) assert.ok(isBroadRoot(p, '/home/alice'), p);
  for (const p of ['/home/alice/code/app', 'C:\\Users\\alice\\code', './src']) assert.ok(!isBroadRoot(p, '/home/alice'), p);
  assert.ok(insecureUrl('http://mcp.example.dev/sse'));
  assert.ok(!insecureUrl('http://localhost:3000/mcp'));
  assert.ok(!insecureUrl('http://127.0.0.1:8080'));
  assert.ok(!insecureUrl('https://x.dev'));
});

test('tildify hides usernames on every OS', () => {
  assert.equal(tildify('/home/alice/.claude/settings.json', '/home/alice'), '~/.claude/settings.json');
  assert.equal(tildify('C:\\Users\\alice\\AppData\\Roaming\\Claude\\x.json', 'C:\\Users\\alice'), '~\\AppData\\Roaming\\Claude\\x.json');
  assert.equal(tildify('/Users/someone/x', '/home/alice'), '~/x');
  assert.equal(tildify('c:\\users\\Alice\\a', 'C:\\Users\\alice'), '~\\a');
});

test('Windows config locations (path.win32, APPDATA)', () => {
  const home = 'C:\\Users\\alice';
  const env = { APPDATA: 'C:\\Users\\alice\\AppData\\Roaming' };
  const L = locations({ platform: 'win32', home, env, project: 'C:\\code\\app', P: path.win32 }).map((l) => l.path);
  for (const p of [
    'C:\\Users\\alice\\.claude\\settings.json',
    'C:\\Users\\alice\\.claude.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Claude\\claude_desktop_config.json',
    'C:\\Users\\alice\\.cursor\\mcp.json',
    'C:\\Users\\alice\\.codex\\config.toml',
    'C:\\Users\\alice\\.gemini\\settings.json',
    'C:\\Users\\alice\\.codeium\\windsurf\\mcp_config.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Code\\User\\mcp.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Code\\User\\settings.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Zed\\settings.json',
    'C:\\Users\\alice\\AppData\\Roaming\\Block\\goose\\config\\config.yaml',
    'C:\\code\\app\\.mcp.json',
    'C:\\code\\app\\.vscode\\mcp.json',
  ]) assert.ok(L.includes(p), p);
});

test('macOS config locations', () => {
  const L = locations({ platform: 'darwin', home: '/Users/alice', env: {}, project: null, P: path.posix }).map((l) => l.path);
  assert.ok(L.includes('/Users/alice/Library/Application Support/Claude/claude_desktop_config.json'));
  assert.ok(L.includes('/Users/alice/Library/Application Support/Code/User/mcp.json'));
  assert.ok(L.includes('/Users/alice/.config/zed/settings.json'));
});

test('CODEX_HOME and XDG_CONFIG_HOME are honored', () => {
  const L = locations({ platform: 'linux', home: '/h', env: { CODEX_HOME: '/opt/codex', XDG_CONFIG_HOME: '/x' }, project: null, P: path.posix }).map((l) => l.path);
  assert.ok(L.includes('/opt/codex/config.toml'));
  assert.ok(L.includes('/x/zed/settings.json'));
  assert.ok(L.includes('/x/goose/config.yaml'));
});

test('grading rubric', () => {
  assert.equal(scoreFindings([]), 100);
  assert.equal(letter(scoreFindings([{ severity: 'low' }])), 'A');
  assert.equal(letter(scoreFindings([{ severity: 'high' }])), 'B');
  assert.equal(letter(scoreFindings([{ severity: 'critical' }])), 'D');
  assert.equal(letter(scoreFindings([{ severity: 'critical' }, { severity: 'critical' }])), 'F');
  assert.ok(scoreFindings(Array(10).fill({ severity: 'medium' })) < 65);
});
