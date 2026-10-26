// Auto-run inventory: hooks, status lines, key helpers, folder-open tasks, auto-loaded plugins.
// Everything here is static text analysis. agent-xray NEVER runs a hook, command or plugin it finds.
import { scanText, redact } from './secrets.js';
import { tildify } from './paths.js';
import { packageSpec, unwrapCommand } from './rules.js';

const SH = '(?:sudo\\s+(?:-\\S+\\s+)*)?(?:ba|z|da|k|fi|a)?sh\\b';
const FETCH = '\\b(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c)\\b';
const RUNTIMES = '(?:python[23]?|node|perl|ruby|bun|deno|php|iex|invoke-expression|pwsh|powershell)\\b';

/** [id, severity, label, regex]. Order matters only for display. */
export const COMMAND_FLAGS = [
  ['pipe-to-shell', 'critical', 'downloads a script and pipes it straight into a shell', new RegExp(`${FETCH}[^|;&\\n]*\\|\\s*(?:${SH}|${RUNTIMES})`, 'i')],
  ['eval-remote', 'critical', 'evaluates code it just downloaded', new RegExp(`\\b(?:eval|source|exec)\\s+["'(]*\\$\\(\\s*(?:curl|wget)|\\b(?:ba|z)?sh\\s+-c\\s+["']?\\$\\(\\s*(?:curl|wget)|<\\(\\s*(?:curl|wget)|\\biex\\s*\\(?\\s*\\(?\\s*(?:new-object|iwr|irm|invoke-webrequest|invoke-restmethod)`, 'i')],
  ['base64-exec', 'critical', 'decodes a hidden (base64) payload and runs it', /base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|python[23]?|node|perl)\b|\beval\b[^\n]*base64|frombase64string[^\n]*(?:iex|invoke-expression)|\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|\beval\s*\(\s*(?:atob|Buffer\.from)\(/i],
  ['reverse-shell', 'critical', 'opens a remote shell to another machine', /\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\b[^\n]*\s-[ec]\s|\bbash\s+-i\b[^\n]*>&|\bmkfifo\b[^\n]*\b(?:nc|ncat)\b|\bsocat\b[^\n]*exec:/i],
  ['exfil', 'high', 'sends secrets, env vars or credential files to a remote host', new RegExp(`${FETCH}[^\\n]*(?:\\s-d\\b|\\s--data(?:-binary|-raw|-urlencode)?\\b|\\s-F\\b|\\s--form\\b|\\s-T\\b|--upload-file|--post-(?:data|file)|-Method\\s+Post|-Body\\b|\\s-X\\s*POST)[^\\n]*(?:\\$\\{?\\w*(?:TOKEN|KEY|SECRET|PASS|CRED|AUTH)\\w*|\\$\\(\\s*(?:env|printenv|cat)\\b|\\.(?:ssh|aws|npmrc|netrc|git-credentials)\\b|\\.config/gh|id_(?:rsa|ed25519)|\\.env\\b|/etc/passwd)|\\$\\{?\\w*(?:TOKEN|KEY|SECRET|PASS|CRED|AUTH)\\w*\\}?[^\\n;&]*\\|[^\\n;&]*\\b(?:curl|wget|nc|ncat)\\b|\\b(?:env|printenv)\\s*\\|\\s*(?:curl|wget|nc)\\b|\\bcat\\b[^\\n|]*(?:\\.ssh/|\\.aws/|\\.npmrc|\\.netrc|\\.git-credentials|\\.env\\b)[^\\n]*\\|\\s*(?:curl|wget|nc|base64)`, 'i')],
  ['shell-rc-write', 'high', 'writes to a shell startup file, crontab or login item (persistence)', /(?:>>?|\btee\b(?:\s+-a)?)\s*["']?[^\s"']*\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv|bash_login)\b|config\/fish\/config\.fish|\bcrontab\s+(?:-\s|-e|\S+\.\w+)|\|\s*crontab\b|\/etc\/cron|launchctl\s+(?:load|bootstrap|submit)|systemctl\s+(?:--user\s+)?(?:enable|link)|Library\/LaunchAgents|\.config\/systemd\/user|\.config\/autostart|\bschtasks\b|CurrentVersion\\\\?Run\b/i],
  ['hidden-script', 'high', 'runs a script hidden in a dot-folder or temp dir', /\b(?:bun|node|deno|python[23]?|ruby|perl|sh|bash|zsh|tsx|ts-node)\s+(?:run\s+)?["']?(?:(?:~|\$HOME|\$\{HOME\})\/\.(?!claude\/hooks\/|cursor\/hooks\/|codex\/hooks\/|gemini\/hooks\/|copilot\/hooks\/)[\w.-]+\/|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|%TEMP%|\$TMPDIR|\$env:TEMP)\S*/i],
  ['rm-home', 'high', 'can delete your home folder or whole disk', /\brm\s+-[a-z]*(?:rf|fr|r)[a-z]*\s+(?:--no-preserve-root\s+)?["']?(?:~\/?|\$HOME\/?|\$\{HOME\}\/?|\/)(?:\*)?["']?(?:\s|$|;|&)|Remove-Item\s+[^\n]*-Recurse[^\n]*(?:\$HOME|~|\$env:USERPROFILE)/i],
  ['obfuscated', 'medium', 'contains an obfuscated / encoded blob', /[A-Za-z0-9+/]{160,}={0,2}|(?:\\x[0-9a-f]{2}){10,}|(?:\\u00[0-9a-f]{2}){10,}/i],
  ['downloader', 'medium', 'downloads something from the internet', new RegExp(`${FETCH}[^\\n]*https?://`, 'i')],
  ['runtime-fetch', 'medium', 'fetches and runs the newest version of a package every time', /\b(?:npx|bunx|pnpx|uvx|pipx\s+run|pnpm\s+dlx|yarn\s+dlx|bun\s+x)\s/i],
  ['sudo', 'medium', 'runs with sudo (root)', /(?:^|[;&|(]\s*|\s)sudo\s/],
  ['downloads-script', 'medium', 'runs a script from your Downloads / Desktop folder', /\b(?:bun|node|deno|python[23]?|ruby|perl|sh|bash|zsh|tsx)\s+(?:run\s+)?["']?(?:~|\$HOME|\$\{HOME\})\/(?:Downloads|Desktop)\//i],
  ['loose-script', 'low', 'runs a loose script from your home folder (whoever can edit it controls what runs)', /\b(?:bun|node|deno|python[23]?|ruby|perl|sh|bash|zsh|tsx)\s+(?:run\s+)?["']?(?:~|\$HOME|\$\{HOME\})\/[^.\/\s"'][^\/\s"']*\.(?:m?js|cjs|ts|py|sh|rb|pl)\b/i],
  ['reads-key-file', 'medium', 'reads a key from a plaintext file', /^\s*(?:cat|type|get-content|head|tail)\s+["']?(?:~|\$HOME|\$\{HOME\}|\/)[^|;&]*$/i],
  ['remote-url', 'low', 'contacts a remote URL', /https?:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/i],
];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const worstSeverity = (flags) => flags.reduce((w, f) => (SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), 'info');

/** Risk flags for one shell command string. Returns [{id, severity, label}]. */
export function commandFlags(cmd) {
  if (typeof cmd !== 'string' || !cmd.trim()) return [];
  const s = cmd.length > 20000 ? cmd.slice(0, 20000) : cmd;
  let flags = COMMAND_FLAGS.filter(([, , , re]) => re.test(s)).map(([id, severity, label]) => ({ id, severity, label }));
  const has = (id) => flags.some((f) => f.id === id);
  if (has('pipe-to-shell') || has('eval-remote') || has('exfil')) flags = flags.filter((f) => f.id !== 'downloader');
  if (has('downloader') || has('pipe-to-shell') || has('eval-remote') || has('exfil') || has('reverse-shell')) flags = flags.filter((f) => f.id !== 'remote-url');
  if (has('runtime-fetch')) { // only risky when unpinned
    const m = /\b(npx|bunx|pnpx|uvx|pipx|pnpm|yarn|bun)\s+(?:run\s+|dlx\s+|x\s+)?(.*)$/i.exec(s);
    if (m) {
      const { base, args } = unwrapCommand(m[1], m[2].split(/\s+/).filter(Boolean));
      const spec = packageSpec(base === 'pipx' ? 'pipx' : base, args);
      if (spec && spec.pinned) flags = flags.filter((f) => f.id !== 'runtime-fetch');
    }
  }
  return flags;
}

/** Make a command safe to show: secrets redacted, home tildified, hidden chars visible, length capped. */
export function displayCommand(cmd, home, max = 160) {
  if (typeof cmd !== 'string') return null;
  let s = cmd;
  for (const h of scanText(s)) s = s.split(h.value).join(redact(h.value));
  s = s.replace(/((?:api[_-]?key|token|secret|password|passwd|pat)\s*[=:]\s*)["']?[^\s"'&]{8,}/gi, (m0, k) => `${k}****`);
  s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/gu, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase()}>`);
  s = tildify(s.replace(/\s+/g, ' ').trim(), home);
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

const cmdStr = (v) => (typeof v === 'string' ? v : Array.isArray(v) ? v.map(String).join(' ') : null);

/**
 * Normalize any harness's hook block into a flat list.
 * Handles Claude/Codex/Gemini/Qwen `{Event:[{matcher, hooks:[{type,command}]}]}`, Cursor/Copilot
 * `{version, hooks:{event:[{command|bash|powershell|type:'http',url|type:'prompt',prompt}]}}`
 * and Codex TOML `[[hooks.Event]]` tables (same shape after parsing).
 */
export function hookList(block) {
  const out = [];
  if (!block || typeof block !== 'object') return out;
  const H = block.hooks && typeof block.hooks === 'object' && !Array.isArray(block.hooks) ? block.hooks : block;
  for (const [event, arr] of Object.entries(H)) {
    if (!arr || typeof arr !== 'object') continue;
    for (const group of [].concat(arr)) {
      if (!group || typeof group !== 'object') continue;
      const inner = Array.isArray(group.hooks) ? group.hooks : [group];
      for (const h of inner) {
        if (!h || typeof h !== 'object') continue;
        const cmds = [...new Set([cmdStr(h.command), cmdStr(h.bash), cmdStr(h.powershell), cmdStr(h.command_windows), cmdStr(h.windows), h.exec ? [h.exec, ...[].concat(h.args || [])].join(' ') : null].filter(Boolean))];
        const type = String(h.type || (cmds.length ? 'command' : h.url ? 'http' : h.prompt ? 'prompt' : h.server || h.tool ? 'mcp_tool' : 'unknown'));
        const base = { event, matcher: typeof (group.matcher ?? h.matcher) === 'string' ? (group.matcher ?? h.matcher) : null, type, async: h.async === true || h.background === true };
        if (cmds.length) for (const c of cmds) out.push({ ...base, command: c });
        else out.push({ ...base, command: null, url: typeof h.url === 'string' ? h.url : null, prompt: typeof h.prompt === 'string' ? h.prompt : null, tool: h.tool || h.server ? `${h.server || ''}${h.tool ? ':' + h.tool : ''}` : null });
      }
    }
  }
  return out;
}

export const STARTUP_EVENTS = /^(session[-_]?start|sessionstart|setup|workspace[-_]?open|folder[-_]?open|on[-_]?start(up)?|startup|init|beforeagentstart|agentstart)$/i;
