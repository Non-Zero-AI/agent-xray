// Where each agent keeps its config. Every path here is documented in docs/CONFIG-SOURCES.md.
// kind -> handler in scan.js / harness.js. scope: 'user' | 'project' | 'managed'.
// A path containing * or ** is expanded by scan.js (depth-capped). Entries marked UNVERIFIED in
// CONFIG-SOURCES.md are best-effort and only ever produce inventory or generic checks.

export const AGENTS = {
  'claude-code': { name: 'Claude Code' },
  'claude-desktop': { name: 'Claude Desktop' },
  cursor: { name: 'Cursor' },
  codex: { name: 'Codex CLI' },
  gemini: { name: 'Gemini CLI' },
  windsurf: { name: 'Windsurf' },
  vscode: { name: 'VS Code / Copilot' },
  'copilot-cli': { name: 'Copilot CLI' },
  opencode: { name: 'OpenCode' },
  openclaw: { name: 'OpenClaw' },
  aider: { name: 'Aider' },
  qwen: { name: 'Qwen Code' },
  continue: { name: 'Continue' },
  cline: { name: 'Cline' },
  roo: { name: 'Roo Code' },
  zed: { name: 'Zed' },
  goose: { name: 'Goose' },
  stack: { name: 'Self-hosted agent stack' },
  host: { name: 'Server host' },
  shared: { name: 'Shared project files' },
};

const EDITOR_HOSTS = ['Code', 'Code - Insiders', 'Cursor', 'Windsurf', 'VSCodium'];

/**
 * @param {{platform:string, home:string, env:object, project?:string|null, P:typeof import('node:path')}} ctx
 */
export function locations(ctx) {
  const { platform, home: H, env, P } = ctx;
  const j = (...a) => P.join(...a);
  const win = platform === 'win32';
  const mac = platform === 'darwin';
  const xdg = (!win && env.XDG_CONFIG_HOME) || j(H, '.config');
  // OS "application data" root used by Electron apps (VS Code, Claude Desktop, Cline/Roo globalStorage).
  const appData = win ? (env.APPDATA || j(H, 'AppData', 'Roaming')) : mac ? j(H, 'Library', 'Application Support') : xdg;
  const codexHome = env.CODEX_HOME || j(H, '.codex');
  const copilotHome = env.COPILOT_HOME || j(H, '.copilot');
  const cursorCfgDir = env.CURSOR_CONFIG_DIR || j(H, '.cursor');
  const zedDir = win ? j(appData, 'Zed') : j(mac ? j(H, '.config') : xdg, 'zed');
  const gooseDir = win ? j(appData, 'Block', 'goose', 'config') : j(mac ? j(H, '.config') : xdg, 'goose');

  const L = [];
  const add = (agents, path, kind, format, scope = 'user') => L.push({ agents: [].concat(agents), path, kind, format, scope });
  const opencodeDir = j(xdg, 'opencode');
  const openclawCfg = env.OPENCLAW_CONFIG_PATH || j(H, '.openclaw', 'openclaw.json');
  const claudeDir = env.CLAUDE_CONFIG_DIR || j(H, '.claude');

  // Claude Code
  add('claude-code', j(H, '.claude', 'settings.json'), 'claude-settings', 'json');
  add('claude-code', j(H, '.claude.json'), 'claude-global', 'json');
  add('claude-code', j(H, '.claude', 'CLAUDE.md'), 'instructions', 'text');
  if (claudeDir !== j(H, '.claude')) add('claude-code', j(claudeDir, 'settings.json'), 'claude-settings', 'json');
  add('claude-code', j(claudeDir, 'skills', '*', 'SKILL.md'), 'skill', 'text');
  add('claude-code', j(claudeDir, 'agents', '**', '*.md'), 'subagent', 'text');
  add('claude-code', j(claudeDir, 'commands', '**', '*.md'), 'command', 'text');
  add('claude-code', j(claudeDir, 'rules', '**', '*.md'), 'rule', 'text');
  add('claude-code', j(claudeDir, 'plugins', '**', 'hooks', 'hooks.json'), 'hooks-file', 'json');
  add('claude-code', j(claudeDir, 'plugins', '**', '.mcp.json'), 'mcp-standard', 'json');
  add('claude-code', j(claudeDir, 'plugins', '**', 'skills', '*', 'SKILL.md'), 'skill', 'text');
  add(['claude-code', 'codex', 'opencode', 'copilot-cli'], j(H, '.agents', 'skills', '*', 'SKILL.md'), 'skill', 'text');
  // Claude Desktop (Linux path is used by community builds; official builds are macOS/Windows)
  add('claude-desktop', j(appData, 'Claude', 'claude_desktop_config.json'), 'mcp-standard', 'json');
  // Cursor
  add('cursor', j(H, '.cursor', 'mcp.json'), 'mcp-standard', 'jsonc');
  add('cursor', j(cursorCfgDir, 'cli-config.json'), 'cursor-cli', 'jsonc');
  add('cursor', j(H, '.cursor', 'permissions.json'), 'cursor-permissions', 'jsonc');
  add('cursor', j(H, '.cursor', 'hooks.json'), 'hooks-file', 'jsonc');
  add('cursor', j(H, '.cursor', 'rules', '*.mdc'), 'rule', 'text');
  add('cursor', j(H, '.cursor', 'skills', '*', 'SKILL.md'), 'skill', 'text');
  // Codex CLI
  add('codex', j(codexHome, 'config.toml'), 'codex-config', 'toml');
  add('codex', j(codexHome, 'AGENTS.md'), 'instructions', 'text');
  add('codex', j(codexHome, 'AGENTS.override.md'), 'instructions', 'text');
  add('codex', j(codexHome, 'hooks.json'), 'hooks-file', 'json');
  add('codex', j(codexHome, 'prompts', '*.md'), 'command', 'text');
  add('codex', j(codexHome, 'skills', '*', 'SKILL.md'), 'skill', 'text');
  // Gemini CLI
  add('gemini', j(H, '.gemini', 'settings.json'), 'gemini-settings', 'jsonc');
  add('gemini', j(H, '.gemini', 'GEMINI.md'), 'instructions', 'text');
  add('gemini', j(H, '.gemini', 'extensions', '*', 'gemini-extension.json'), 'mcp-standard', 'json');
  add('gemini', j(H, '.gemini', 'commands', '**', '*.toml'), 'command', 'text');
  // Windsurf
  add('windsurf', j(H, '.codeium', 'windsurf', 'mcp_config.json'), 'mcp-standard', 'jsonc');
  add('windsurf', j(H, '.codeium', 'windsurf', 'memories', 'global_rules.md'), 'instructions', 'text');
  // VS Code / GitHub Copilot
  for (const host of ['Code', 'Code - Insiders']) {
    add('vscode', j(appData, host, 'User', 'mcp.json'), 'vscode-mcp', 'jsonc');
    add('vscode', j(appData, host, 'User', 'settings.json'), 'vscode-settings', 'jsonc');
  }
  for (const host of ['Code', 'Code - Insiders']) add('vscode', j(appData, host, 'User', 'tasks.json'), 'vscode-tasks', 'jsonc');
  // Copilot CLI (~/.copilot/config.json holds auth and is NEVER read)
  add('copilot-cli', j(copilotHome, 'mcp-config.json'), 'mcp-standard', 'jsonc');
  add('copilot-cli', j(copilotHome, 'settings.json'), 'copilot-settings', 'jsonc');
  add('copilot-cli', j(copilotHome, 'permissions-config.json'), 'copilot-permissions', 'jsonc');
  add('copilot-cli', j(copilotHome, 'copilot-instructions.md'), 'instructions', 'text');
  add('copilot-cli', j(copilotHome, 'instructions', '**', '*.md'), 'instructions', 'text');
  add('copilot-cli', j(copilotHome, 'agents', '*.md'), 'subagent', 'text');
  add('copilot-cli', j(copilotHome, 'skills', '*', 'SKILL.md'), 'skill', 'text');
  add('copilot-cli', j(copilotHome, 'hooks', '*.json'), 'hooks-file', 'json');
  // OpenCode
  for (const f of ['opencode.json', 'opencode.jsonc', 'config.json']) add('opencode', j(opencodeDir, f), 'opencode-config', 'jsonc');
  add('opencode', j(opencodeDir, 'AGENTS.md'), 'instructions', 'text');
  for (const d of ['agent', 'agents']) add('opencode', j(opencodeDir, d, '**', '*.md'), 'subagent', 'text');
  for (const d of ['command', 'commands']) add('opencode', j(opencodeDir, d, '**', '*.md'), 'command', 'text');
  for (const d of ['skill', 'skills']) add('opencode', j(opencodeDir, d, '*', 'SKILL.md'), 'skill', 'text');
  for (const d of ['plugin', 'plugins', 'tool', 'tools']) add('opencode', j(opencodeDir, d, '*.{js,ts,mjs,cjs}'), 'plugin-code', 'text');
  // OpenClaw (JSON5 config; key semantics UNVERIFIED -> generic checks only)
  add('openclaw', openclawCfg, 'openclaw-config', 'json5');
  add('openclaw', j(H, '.openclaw', 'skills', '*', 'SKILL.md'), 'skill', 'text');
  for (const f of ['AGENTS.md', 'SOUL.md', 'TOOLS.md']) add('openclaw', j(H, '.openclaw', 'workspace', f), 'instructions', 'text');
  // Aider
  add('aider', j(H, '.aider.conf.yml'), 'aider-config', 'yaml');
  // Qwen Code
  add('qwen', j(H, '.qwen', 'settings.json'), 'qwen-settings', 'jsonc');
  add('qwen', j(H, '.qwen', 'QWEN.md'), 'instructions', 'text');
  add('qwen', j(H, '.qwen', 'skills', '*', 'SKILL.md'), 'skill', 'text');
  // Continue
  add('continue', j(H, '.continue', 'config.yaml'), 'continue-config', 'yaml');
  add('continue', j(H, '.continue', 'config.json'), 'continue-config', 'jsonc');
  // Cline / Roo Code (VS Code-family extension globalStorage)
  for (const host of EDITOR_HOSTS) {
    add('cline', j(appData, host, 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), 'mcp-standard', 'json');
    add('roo', j(appData, host, 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), 'mcp-standard', 'json');
  }
  // Zed
  add('zed', j(zedDir, 'settings.json'), 'zed-settings', 'jsonc');
  // Goose
  add('goose', j(gooseDir, 'config.yaml'), 'goose-config', 'yaml');
  add('goose', j(gooseDir, 'secrets.yaml'), 'secrets-file', 'text');

  // Managed / enterprise policy files (admins push these; an attacker with root can too)
  const sys = (p) => (ctx.sysRoot && ctx.sysRoot !== '/' && !win ? P.join(ctx.sysRoot, p) : p);
  const m = (agents, path, kind, format) => add(agents, path, kind, format, 'managed');
  if (win) {
    const pf = env.ProgramFiles || 'C:\\Program Files', pd = env.ProgramData || 'C:\\ProgramData';
    m('claude-code', j(pf, 'ClaudeCode', 'managed-settings.json'), 'claude-settings', 'json');
    m('claude-code', j(pf, 'ClaudeCode', 'managed-mcp.json'), 'mcp-standard', 'json');
    m('cursor', j(pd, 'Cursor', 'hooks.json'), 'hooks-file', 'jsonc');
    m('gemini', j(pd, 'gemini-cli', 'settings.json'), 'gemini-settings', 'jsonc');
    m('qwen', j(pd, 'qwen-code', 'settings.json'), 'qwen-settings', 'jsonc');
    m('qwen', j(pd, 'qwen-code', 'system-defaults.json'), 'qwen-settings', 'jsonc');
    m('copilot-cli', j(pf, 'GitHubCopilot', 'managed-settings.json'), 'copilot-settings', 'jsonc');
  } else if (mac) {
    const lib = sys('/Library/Application Support');
    m('claude-code', j(lib, 'ClaudeCode', 'managed-settings.json'), 'claude-settings', 'json');
    m('claude-code', j(lib, 'ClaudeCode', 'managed-settings.d', '*.json'), 'claude-settings', 'json');
    m('claude-code', j(lib, 'ClaudeCode', 'managed-mcp.json'), 'mcp-standard', 'json');
    m('cursor', j(lib, 'Cursor', 'hooks.json'), 'hooks-file', 'jsonc');
    m('gemini', j(lib, 'GeminiCli', 'settings.json'), 'gemini-settings', 'jsonc');
    m('qwen', j(lib, 'QwenCode', 'settings.json'), 'qwen-settings', 'jsonc');
    m('qwen', j(lib, 'QwenCode', 'system-defaults.json'), 'qwen-settings', 'jsonc');
    m('copilot-cli', j(lib, 'GitHubCopilot', 'managed-settings.json'), 'copilot-settings', 'jsonc');
  } else {
    m('claude-code', sys('/etc/claude-code/managed-settings.json'), 'claude-settings', 'json');
    m('claude-code', j(sys('/etc/claude-code/managed-settings.d'), '*.json'), 'claude-settings', 'json');
    m('claude-code', sys('/etc/claude-code/managed-mcp.json'), 'mcp-standard', 'json');
    m('cursor', sys('/etc/cursor/hooks.json'), 'hooks-file', 'jsonc');
    m('gemini', sys('/etc/gemini-cli/settings.json'), 'gemini-settings', 'jsonc');
    m('qwen', sys('/etc/qwen-code/settings.json'), 'qwen-settings', 'jsonc');
    m('qwen', sys('/etc/qwen-code/system-defaults.json'), 'qwen-settings', 'jsonc');
    m('copilot-cli', sys('/etc/github-copilot/managed-settings.json'), 'copilot-settings', 'jsonc');
  }

  if (ctx.project) {
    const R = ctx.project;
    const p = (agents, rel, kind, format) => add(agents, j(R, ...rel.split('/')), kind, format, 'project');
    p('claude-code', '.claude/settings.json', 'claude-settings', 'json');
    p('claude-code', '.claude/settings.local.json', 'claude-settings', 'json');
    p(['claude-code', 'vscode'], '.mcp.json', 'mcp-standard', 'json');
    p('claude-code', 'CLAUDE.md', 'instructions', 'text');
    p('claude-code', 'CLAUDE.local.md', 'instructions', 'text');
    p('cursor', '.cursor/mcp.json', 'mcp-standard', 'jsonc');
    p('cursor', '.cursor/cli.json', 'cursor-cli', 'jsonc');
    p('cursor', '.cursor/permissions.json', 'cursor-permissions', 'jsonc');
    p('cursor', '.cursorrules', 'instructions', 'text');
    p('cursor', '.cursor/rules', 'instructions-dir', 'text');
    p('codex', '.codex/config.toml', 'codex-config', 'toml');
    p('gemini', '.gemini/settings.json', 'gemini-settings', 'jsonc');
    p('gemini', 'GEMINI.md', 'instructions', 'text');
    p('windsurf', '.windsurfrules', 'instructions', 'text');
    p('vscode', '.vscode/mcp.json', 'vscode-mcp', 'jsonc');
    p('vscode', '.vscode/settings.json', 'vscode-settings', 'jsonc');
    p('vscode', '.github/copilot-instructions.md', 'instructions', 'text');
    p('continue', '.continue/mcpServers', 'continue-dir', 'yaml');
    p('roo', '.roo/mcp.json', 'mcp-standard', 'json');
    p('zed', '.zed/settings.json', 'zed-settings', 'jsonc');
    p('goose', '.goosehints', 'instructions', 'text');
    p('shared', 'AGENTS.md', 'instructions', 'text');
    p('shared', 'AGENTS.override.md', 'instructions', 'text');
    // hooks, skills, subagents, commands, rules, plugins (auto-loaded from the repo)
    p('claude-code', '.claude/skills/*/SKILL.md', 'skill', 'text');
    p('claude-code', '.claude/agents/**/*.md', 'subagent', 'text');
    p('claude-code', '.claude/commands/**/*.md', 'command', 'text');
    p('claude-code', '.claude/rules/**/*.md', 'rule', 'text');
    p(['claude-code', 'codex', 'opencode', 'copilot-cli'], '.agents/skills/*/SKILL.md', 'skill', 'text');
    p('codex', '.codex/hooks.json', 'hooks-file', 'json');
    p('cursor', '.cursor/hooks.json', 'hooks-file', 'jsonc');
    p('cursor', '.cursor/skills/*/SKILL.md', 'skill', 'text');
    p('gemini', '.gemini/commands/**/*.toml', 'command', 'text');
    p(['copilot-cli', 'vscode'], '.github/hooks/*.json', 'hooks-file', 'json');
    p('copilot-cli', '.github/copilot/settings.json', 'copilot-settings', 'jsonc');
    p('copilot-cli', '.github/copilot/settings.local.json', 'copilot-settings', 'jsonc');
    p('copilot-cli', '.github/mcp.json', 'mcp-standard', 'jsonc');
    p(['copilot-cli', 'vscode'], '.github/instructions/**/*.md', 'instructions', 'text');
    p(['copilot-cli', 'vscode'], '.github/agents/*.md', 'subagent', 'text');
    p(['copilot-cli', 'vscode'], '.github/skills/*/SKILL.md', 'skill', 'text');
    p(['copilot-cli', 'vscode'], '.github/prompts/*.prompt.md', 'command', 'text');
    p('vscode', '.vscode/tasks.json', 'vscode-tasks', 'jsonc');
    p('opencode', 'opencode.json', 'opencode-config', 'jsonc');
    p('opencode', 'opencode.jsonc', 'opencode-config', 'jsonc');
    for (const d of ['agent', 'agents']) p('opencode', `.opencode/${d}/**/*.md`, 'subagent', 'text');
    for (const d of ['command', 'commands']) p('opencode', `.opencode/${d}/**/*.md`, 'command', 'text');
    for (const d of ['skill', 'skills']) p('opencode', `.opencode/${d}/*/SKILL.md`, 'skill', 'text');
    for (const d of ['plugin', 'plugins', 'tool', 'tools']) p('opencode', `.opencode/${d}/*.{js,ts,mjs,cjs}`, 'plugin-code', 'text');
    p('qwen', '.qwen/settings.json', 'qwen-settings', 'jsonc');
    p('qwen', 'QWEN.md', 'instructions', 'text');
    p('qwen', '.qwen/skills/*/SKILL.md', 'skill', 'text');
    p('aider', '.aider.conf.yml', 'aider-config', 'yaml');
    p('cline', '.clinerules', 'instructions', 'text');
    p('windsurf', '.windsurf/rules/*.md', 'rule', 'text');
    p('shared', 'skills/*/SKILL.md', 'skill', 'text');
  }
  return L;
}

/** Directories whose existence alone means an agent is installed/used (graded even with no config issues). */
export function presenceDirs(ctx) {
  const { platform, home: H, env, P } = ctx;
  const j = (...a) => P.join(...a);
  const win = platform === 'win32';
  const mac = platform === 'darwin';
  const xdg = (!win && env.XDG_CONFIG_HOME) || j(H, '.config');
  const appData = win ? (env.APPDATA || j(H, 'AppData', 'Roaming')) : mac ? j(H, 'Library', 'Application Support') : xdg;
  const out = [
    ['claude-code', j(H, '.claude')],
    ['claude-desktop', j(appData, 'Claude')],
    ['cursor', j(H, '.cursor')],
    ['codex', env.CODEX_HOME || j(H, '.codex')],
    ['gemini', j(H, '.gemini')],
    ['windsurf', j(H, '.codeium', 'windsurf')],
    ['continue', j(H, '.continue')],
    ['zed', win ? j(appData, 'Zed') : j(mac ? j(H, '.config') : xdg, 'zed')],
    ['goose', win ? j(appData, 'Block', 'goose') : j(mac ? j(H, '.config') : xdg, 'goose')],
    ['copilot-cli', env.COPILOT_HOME || j(H, '.copilot')],
    ['opencode', j(xdg, 'opencode')],
    ['openclaw', j(H, '.openclaw')],
    ['qwen', j(H, '.qwen')],
  ];
  for (const host of EDITOR_HOSTS) {
    out.push(['cline', j(appData, host, 'User', 'globalStorage', 'saoudrizwan.claude-dev')]);
    out.push(['roo', j(appData, host, 'User', 'globalStorage', 'rooveterinaryinc.roo-cline')]);
  }
  out.push(['vscode', j(appData, 'Code', 'User')]);
  return out;
}
