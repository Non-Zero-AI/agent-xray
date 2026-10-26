import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fixtureHome, byId, agent } from './helpers.js';
import { FAKE } from '../src/demo.js';

test('empty home: no agents, no grade', () => {
  const h = fixtureHome();
  try {
    const r = h.scan();
    assert.equal(r.agents.length, 0);
    assert.equal(r.overall.grade, null);
  } finally { h.cleanup(); }
});

test('clean, pinned setup gets an A', () => {
  const h = fixtureHome({
    '.claude/settings.json': { permissions: { defaultMode: 'default', allow: ['Bash(npm run test:*)'] } },
    '.cursor/mcp.json': { mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${env:GITHUB_TOKEN}' } } } },
  });
  try {
    const r = h.scan();
    assert.equal(r.overall.grade, 'A');
    assert.equal(r.findings.length, 0);
    assert.equal(r.counts.mcpServers, 1);
    assert.deepEqual(r.servers[0].envKeys, ['GITHUB_PERSONAL_ACCESS_TOKEN']);
  } finally { h.cleanup(); }
});

test('Claude Code: bypassPermissions, allow rules, auto-trust, env secret, ~/.claude.json servers', () => {
  const h = fixtureHome({
    '.claude/settings.json': { permissions: { defaultMode: 'bypassPermissions', allow: ['Bash(*)', 'Bash(rm -rf:*)'], additionalDirectories: ['~'] }, env: { ANTHROPIC_API_KEY: FAKE.anthropic }, enableAllProjectMcpServers: true, sandbox: { enabled: false } },
    '.claude.json': { mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] } }, projects: { '/home/tester/code/x': { mcpServers: { remote: { type: 'http', url: 'http://mcp.corp.dev/mcp' } }, allowedTools: ['Bash(sudo:*)'] } } },
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'claude.bypass')[0].severity, 'critical');
    assert.equal(byId(r, 'claude.allow').length, 2);
    assert.equal(byId(r, 'claude.enableAllProjectMcpServers').length, 1);
    assert.equal(byId(r, 'claude.additionalDirectories').length, 1);
    assert.equal(byId(r, 'claude.sandbox.off').length, 1);
    assert.equal(byId(r, 'claude.allowedTools')[0].severity, 'high');
    assert.equal(byId(r, 'mcp.fs.broad').length, 1);
    assert.equal(byId(r, 'mcp.http').length, 1);
    const sec = byId(r, 'secret.plaintext')[0];
    assert.equal(sec.file, '~/.claude/settings.json');
    assert.match(sec.evidence, /^sk-ant-\.\.\./);
    assert.ok(['D', 'F'].includes(agent(r, 'claude-code').grade));
    assert.equal(r.counts.yoloAgents, 1);
  } finally { h.cleanup(); }
});

test('Claude Code: bypassPermissions in project settings is only medium', () => {
  const h = fixtureHome({ 'proj/.claude/settings.json': { permissions: { defaultMode: 'bypassPermissions' } } });
  try {
    const r = h.scan({ project: path.join(h.home, 'proj') });
    assert.equal(byId(r, 'claude.bypass.project')[0].severity, 'medium');
    assert.equal(r.findings[0].file, '~/proj/.claude/settings.json');
  } finally { h.cleanup(); }
});

test('Codex: YOLO, profiles, writable_roots, mcp servers, stale binary', () => {
  const h = fixtureHome({
    '.codex/config.toml': `approval_policy = "never"\nsandbox_mode = "danger-full-access"\n[sandbox_workspace_write]\nwritable_roots = ["~"]\n[profiles.fast]\nsandbox_mode = "danger-full-access"\n[mcp_servers.ctx]\ncommand = "npx"\nargs = ["-y", "@upstash/context7-mcp"]\n[mcp_servers.gone]\ncommand = "/nope/bin/server"\n[mcp_servers.notonpath]\ncommand = "definitely-not-installed-mcp"\n`,
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'codex.yolo').length, 1);
    assert.equal(byId(r, 'codex.sandbox.off').length, 1);
    assert.equal(byId(r, 'codex.writable_roots').length, 1);
    assert.equal(byId(r, 'mcp.unpinned').length, 1);
    assert.equal(byId(r, 'mcp.stale').length, 2);
    assert.equal(r.servers.length, 3);
  } finally { h.cleanup(); }
});

test('Gemini CLI: yolo mode, trust:true, allowed tools, httpUrl', () => {
  const h = fixtureHome({
    '.gemini/settings.json': `{
      // jsonc
      "general": { "defaultApprovalMode": "yolo" },
      "tools": { "allowed": ["run_shell_command(rm)"] },
      "mcpServers": { "remote": { "httpUrl": "http://10.0.0.5/mcp", "trust": true, "headers": { "Authorization": "Bearer ${FAKE.openai}" } } }
    }`,
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'gemini.yolo').length, 1);
    assert.equal(byId(r, 'mcp.trust').length, 1);
    assert.equal(byId(r, 'gemini.allowed')[0].severity, 'high');
    assert.equal(byId(r, 'mcp.http').length, 1);
    assert.equal(byId(r, 'secret.plaintext').length, 1);
  } finally { h.cleanup(); }
});

test('Cursor: mcp.json + permissions.json + cli-config.json', () => {
  const h = fixtureHome({
    '.cursor/mcp.json': { mcpServers: { s: { command: 'npx', args: ['-y', 'x-mcp', '--access-token', FAKE.supabase] }, r: { url: `https://mcp.x.dev/mcp?api_key=a8f3k2l9q0w8e7r6t5` } } },
    '.cursor/permissions.json': { terminalAllowlist: ['*'], mcpAllowlist: ['*:*'] },
    '.cursor/cli-config.json': { permissions: { allow: ['Shell(curl)'], deny: [] } },
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'cursor.terminalAllowlist')[0].severity, 'critical');
    assert.equal(byId(r, 'cursor.mcpAllowlist').length, 1);
    assert.equal(byId(r, 'cursor.cli.allow')[0].severity, 'high');
    assert.equal(byId(r, 'secret.plaintext').length, 2, 'token in args + api_key in URL');
    assert.ok(r.servers.every((s) => !String(s.url).includes('a8f3')), 'query string stripped from inventory');
  } finally { h.cleanup(); }
});

test('VS Code: auto-approve settings + user mcp.json servers key', () => {
  const h = fixtureHome({
    '.config/Code/User/settings.json': `{ "chat.tools.global.autoApprove": true, "chat.tools.terminal.autoApprove": { "/.*/": true, "rm": true, "git status": true }, "chat.tools.terminal.ignoreDefaultAutoApproveRules": true, }`,
    '.config/Code/User/mcp.json': { servers: { pw: { type: 'stdio', command: 'npx', args: ['@playwright/mcp@latest'] } } },
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'vscode.globalAutoApprove')[0].severity, 'critical');
    const t = byId(r, 'vscode.terminalAutoApprove').map((f) => f.severity).sort();
    assert.deepEqual(t, ['critical', 'high']);
    assert.equal(byId(r, 'vscode.ignoreDefaultRules').length, 1);
    assert.equal(byId(r, 'mcp.unpinned').length, 1);
  } finally { h.cleanup(); }
});

test('Zed, Goose, Continue, Windsurf, Cline, Roo', () => {
  const h = fixtureHome({
    '.config/zed/settings.json': '{ "agent": { "always_allow_tool_actions": true }, "context_servers": { "z": { "command": { "path": "npx", "args": ["-y", "zed-mcp"] } } } }',
    '.config/goose/config.yaml': 'GOOSE_MODE: auto\nextensions:\n  developer:\n    type: builtin\n    enabled: true\n  gh:\n    type: stdio\n    enabled: true\n    cmd: npx\n    args: [-y, "@modelcontextprotocol/server-github"]\n    envs: { GITHUB_TOKEN: "' + FAKE.github + '" }\n',
    '.continue/config.yaml': 'mcpServers:\n  - name: sqlite\n    command: uvx\n    args:\n      - mcp-server-sqlite\n',
    '.codeium/windsurf/mcp_config.json': { mcpServers: { w: { serverUrl: 'http://example.org/mcp' } } },
    '.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json': { mcpServers: { c: { command: 'node', args: ['/x/missing.js'], autoApprove: ['run_command'], disabled: false } } },
    '.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json': { mcpServers: { r: { command: 'node', args: ['/x/also-missing.js'], alwaysAllow: ['read'], disabled: true } } },
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'zed.allowAll').length, 1);
    assert.equal(byId(r, 'goose.auto').length, 1);
    assert.ok(r.servers.some((s) => s.name === 'z' && s.agents.includes('zed')));
    assert.ok(!r.servers.some((s) => s.name === 'developer'), 'goose builtins are not MCP servers');
    assert.ok(r.servers.some((s) => s.name === 'sqlite' && s.pinned === false));
    assert.ok(byId(r, 'mcp.http').some((f) => f.agents.includes('windsurf')));
    assert.ok(byId(r, 'mcp.autoApprove').some((f) => f.agents.includes('cline') && f.severity === 'medium'));
    assert.ok(byId(r, 'mcp.stale').some((f) => f.agents.includes('cline')));
    assert.ok(!byId(r, 'mcp.stale').some((f) => f.agents.includes('roo')), 'disabled servers are not flagged');
    assert.equal(byId(r, 'secret.plaintext').length, 1);
    for (const id of ['zed', 'goose', 'continue', 'windsurf', 'cline', 'roo']) assert.ok(agent(r, id), id);
  } finally { h.cleanup(); }
});

test('instruction files: secrets in AGENTS.md / CLAUDE.md are flagged', () => {
  const h = fixtureHome({ '.claude/CLAUDE.md': `use ${FAKE.stripe} for tests`, 'p/AGENTS.md': `token ${FAKE.github}` });
  try {
    const r = h.scan({ project: path.join(h.home, 'p') });
    const s = byId(r, 'secret.plaintext');
    assert.equal(s.length, 2);
    assert.ok(s.every((f) => /sent to the model/.test(f.title)));
  } finally { h.cleanup(); }
});

test('duplicate servers with conflicting definitions', () => {
  const h = fixtureHome({
    '.cursor/mcp.json': { mcpServers: { gh: { command: 'npx', args: ['-y', 'gh-mcp@1.0.0'] } } },
    '.gemini/settings.json': { mcpServers: { gh: { command: 'npx', args: ['-y', 'gh-mcp@2.0.0'] } } },
    '.codeium/windsurf/mcp_config.json': { mcpServers: { gh: { command: 'npx', args: ['-y', 'gh-mcp@2.0.0'] } } },
  });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'mcp.duplicate').length, 1);
    assert.equal(r.counts.mcpServers, 1);
    assert.equal(r.servers.length, 2);
    assert.deepEqual(r.servers.find((s) => s.package === 'gh-mcp@2.0.0').agents.sort(), ['gemini', 'windsurf']);
  } finally { h.cleanup(); }
});

test('unparseable config becomes an info finding, raw secret scan still runs', () => {
  const h = fixtureHome({ '.cursor/mcp.json': `{ "mcpServers": { "x": { "env": { "K": "${FAKE.anthropic}" } } ` });
  try {
    const r = h.scan();
    assert.equal(byId(r, 'config.unparseable').length, 1);
    assert.equal(byId(r, 'secret.plaintext').length, 1);
  } finally { h.cleanup(); }
});

test('--deep: .env not gitignored and readable by agents', () => {
  const h = fixtureHome({
    '.claude/settings.json': {},
    'p/.env': `OPENAI_API_KEY=${FAKE.openai}\n`, 'p/.env.example': 'OPENAI_API_KEY=\n', 'p/.gitignore': 'node_modules\n',
    'q/.env.local': `SECRET_TOKEN=a8f3k2l9q0w8e7r6t5\n`, 'q/.gitignore': '.env*\n', 'q/.cursorignore': '.env*\n',
  });
  try {
    const p = h.scan({ project: path.join(h.home, 'p'), deep: true });
    assert.equal(byId(p, 'env.notGitignored')[0].severity, 'high');
    assert.equal(byId(p, 'env.readableByAgents').length, 1);
    assert.ok(!p.findings.some((f) => /example/.test(f.title)));
    const q = h.scan({ project: path.join(h.home, 'q'), deep: true });
    assert.equal(q.findings.filter((f) => f.category === 'env-exposure').length, 0);
    const noDeep = h.scan({ project: path.join(h.home, 'p') });
    assert.equal(noDeep.findings.filter((f) => f.category === 'env-exposure').length, 0);
  } finally { h.cleanup(); }
});

test('win32 platform: APPDATA-based configs are found and paths are tildified', () => {
  const h = fixtureHome({
    'AppData/Roaming/Claude/claude_desktop_config.json': { mcpServers: { fs: { command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem', 'C:\\Users\\tester'] } } },
    'AppData/Roaming/Code/User/settings.json': '{ "chat.permissions.default": "autopilot" }',
  });
  try {
    const r = h.scan({ platform: 'win32', env: { ...h.env, APPDATA: path.join(h.home, 'AppData', 'Roaming') }, checkBinaries: false });
    assert.ok(agent(r, 'claude-desktop'));
    assert.equal(byId(r, 'mcp.fs.broad').length, 1, 'cmd /c wrapper unwrapped');
    assert.equal(byId(r, 'mcp.unpinned').length, 1);
    assert.equal(byId(r, 'vscode.permissionsDefault').length, 1);
    assert.ok(r.findings.every((f) => !f.file || f.file.startsWith('~')));
    assert.ok(!JSON.stringify(r).includes('tester'), 'no username anywhere in output');
  } finally { h.cleanup(); }
});
