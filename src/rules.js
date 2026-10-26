// Risk rules for permission allow-lists and MCP server definitions.
import path from 'node:path';

const SHELL_TOOLS = /^(bash|shell|run_shell_command|terminal|shellcommand|execute_command)$/i;
const DANGER_CMDS = new Set(['rm', 'rmdir', 'sudo', 'su', 'doas', 'curl', 'wget', 'chmod', 'chown', 'dd', 'mkfs', 'eval', 'exec', 'ssh', 'scp', 'rsync', 'nc', 'ncat', 'netcat', 'kill', 'pkill', 'killall', 'shutdown', 'reboot', 'remove-item', 'del', 'erase', 'rd', 'format', 'iex', 'invoke-expression', 'invoke-webrequest', 'iwr', 'irm', 'invoke-restmethod', 'powershell', 'pwsh', 'sh', 'bash', 'zsh', 'fish', 'cmd', 'xargs', 'find', 'security', 'osascript', 'crontab', 'launchctl', 'systemctl', 'reg']);
const INTERPRETERS = new Set(['python', 'python3', 'node', 'npx', 'bunx', 'bun', 'deno', 'ruby', 'perl', 'php', 'docker', 'uvx', 'uv', 'pipx', 'pip', 'pip3', 'npm', 'pnpm', 'yarn', 'make', 'git']);
const SAFE_INTERPRETER_SUBCMDS = /^(npm|pnpm|yarn)[ :](test|run test|run lint|run build|lint|build|ls|list|view|outdated)\b|^git[ :](status|diff|log|show|branch|fetch|add|commit|checkout|switch|stash|rev-parse|ls-files|blame|grep)\b|^make[ :](test|lint|build)\b/i;
const WILDCARD_ONLY = /^(\*|:\*|\*:\*|\*\*|\s*|\.\*)$/;

/**
 * Classify one allow rule ("Bash(rm:*)", "Shell(curl)", "run_shell_command(git)", "mcp__*", "Mcp(*:*)").
 * Returns null (fine) or {severity, title, why}.
 */
export function allowRuleRisk(rule) {
  if (typeof rule !== 'string') return null;
  const r = rule.trim();
  if (/^mcp__\*$|^mcp__\*__?\*?$/i.test(r)) {
    return { severity: 'medium', title: `Every MCP tool auto-approved: ${r}`, why: 'Any tool from any configured MCP server runs without a prompt.' };
  }
  const m = /^([A-Za-z_][\w.\-]*)(?:\((.*)\))?$/s.exec(r);
  if (!m) return null;
  const tool = m[1];
  const inner = m[2];
  if (SHELL_TOOLS.test(tool)) {
    if (inner === undefined || WILDCARD_ONLY.test(inner)) {
      return { severity: 'critical', title: `Unrestricted shell auto-approved: ${r}`, why: 'The agent can run ANY shell command without asking.' };
    }
    const first = inner.trim().split(/[\s:]+/)[0].toLowerCase().replace(/\.exe$/, '');
    if (DANGER_CMDS.has(first)) {
      return { severity: 'high', title: `Dangerous command auto-approved: ${r}`, why: `\`${first}\` can delete data, escalate privileges or pull code from the internet without a prompt.` };
    }
    if (/\|\s*(ba|z)?sh\b|curl[^)]*\|/.test(inner)) {
      return { severity: 'critical', title: `Pipe-to-shell auto-approved: ${r}`, why: 'Downloads and executes remote code without a prompt.' };
    }
    if (/^git[\s:]+push\b/i.test(inner.trim())) {
      return { severity: 'medium', title: `git push auto-approved: ${r}`, why: 'The agent can publish commits (including any secrets it committed) to remotes without asking.' };
    }
    if (INTERPRETERS.has(first) && /\*|^[\w.\-]+$/.test(inner.trim()) && !SAFE_INTERPRETER_SUBCMDS.test(inner.trim())) {
      return { severity: 'medium', title: `Code runner auto-approved: ${r}`, why: `\`${first}\` with any arguments can run arbitrary code.` };
    }
    return null;
  }
  if (/^mcp__\*?$|^mcp__\*/i.test(r) || (/^mcp$/i.test(tool) && (inner === undefined || /^\*(:\*)?$/.test(inner || '')))) {
    return { severity: 'medium', title: `Every MCP tool auto-approved: ${r}`, why: 'Any tool from any configured MCP server runs without a prompt.' };
  }
  if (/^(write|edit|multiedit)$/i.test(tool) && (inner === undefined || /^(\*\*?|\/\/\*\*|~\/?\*\*|\/\*\*|\/)$/.test(inner))) {
    return { severity: 'medium', title: `Writes anywhere auto-approved: ${r}`, why: 'The agent can modify any file it can reach without asking.' };
  }
  if (/^webfetch$/i.test(tool) && (inner === undefined || /^(\*|domain:\*)$/.test(inner))) {
    return { severity: 'low', title: `Fetching any URL auto-approved: ${r}`, why: 'Prompt-injected pages can be fetched (and data exfiltrated via URLs) without a prompt.' };
  }
  return null;
}

/** Cursor permissions.json terminalAllowlist entry ("git", "npm:install*", "*"). */
export function terminalAllowRisk(entry) {
  if (typeof entry !== 'string') return null;
  const e = entry.trim();
  if (WILDCARD_ONLY.test(e)) return allowRuleRisk('Shell(*)');
  return allowRuleRisk(`Shell(${e})`);
}

/** Cursor mcpAllowlist entry ("server:tool"). */
export function mcpAllowRisk(entry) {
  if (typeof entry !== 'string') return null;
  if (/^\*:\*$/.test(entry.trim())) return { severity: 'medium', title: `Every MCP tool auto-approved: ${entry}`, why: 'Any tool from any configured MCP server runs without a prompt.' };
  return null;
}

/** Unwrap "cmd /c npx ..." and "wsl npx ..." wrappers. */
export function unwrapCommand(command, args = []) {
  let cmd = command || '';
  let a = Array.isArray(args) ? args.map(String) : [];
  if (cmd && !a.length && /\s/.test(cmd) && !/^[A-Za-z]:\\|^\//.test(cmd)) {
    const parts = cmd.split(/\s+/);
    cmd = parts[0];
    a = parts.slice(1);
  }
  const base = path.basename(cmd.replace(/\\/g, '/')).toLowerCase().replace(/\.(exe|cmd|bat)$/, '');
  if (base === 'cmd' && a[0] && /^\/c$/i.test(a[0])) return unwrapCommand(a[1], a.slice(2));
  if (base === 'wsl' && a[0]) return unwrapCommand(a[0], a.slice(1));
  return { cmd, base, args: a };
}

/** Is the package spec for npx/uvx/docker pinned to a version? */
export function packageSpec(base, args) {
  const flagsWithValue = new Set(['-p', '--package', '--from', '--with', '-w', '--python', '--registry', '--cache', '--userconfig', '-c', '--call', '--index', '--index-url', '-e', '--env', '-v', '--volume', '--name', '--network', '--entrypoint', '--mount', '--env-file', '--platform', '-u', '--user', '--workdir']);
  let autoYes = false;
  let pkg = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-y' || a === '--yes') { autoYes = true; continue; }
    if (base === 'docker' && (a === 'run' || a === 'exec')) continue;
    if ((a === '--package' || a === '-p' || a === '--from') && args[i + 1]) { pkg = args[i + 1]; break; }
    if (a.startsWith('--package=') || a.startsWith('--from=')) { pkg = a.split('=')[1]; break; }
    if (flagsWithValue.has(a)) { i++; continue; }
    if (a.startsWith('-')) continue;
    if (base === 'pnpm' && a === 'dlx') continue;
    pkg = a;
    break;
  }
  if (!pkg) return null;
  let pinned;
  if (base === 'docker') {
    pinned = /@sha256:/.test(pkg) || (/:[^/]+$/.test(pkg) && !/:latest$/.test(pkg));
  } else if (base === 'uvx' || base === 'uv' || base === 'pipx') {
    pinned = /==\s*[\w.]+|@\d[\w.]*$/.test(pkg);
  } else {
    const at = pkg.startsWith('@') ? pkg.indexOf('@', 1) : pkg.indexOf('@');
    const ver = at > 0 ? pkg.slice(at + 1) : '';
    pinned = !!ver && !/^(latest|next|canary|beta|\*|x)$/i.test(ver) && !/^[\^~><]/.test(ver);
  }
  if (/^(\.|\/|[A-Za-z]:\\|file:|https?:|git\+)/.test(pkg)) pinned = true; // local path / explicit source, not a registry fetch
  return { pkg, pinned, autoYes };
}

export const RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'docker', 'pnpm']);

export function isBroadRoot(p, home) {
  if (typeof p !== 'string') return false;
  const s = p.trim().replace(/[\\\/]+$/, '');
  const h = (home || '').replace(/[\\\/]+$/, '');
  if (s === '' && p.trim().startsWith('/')) return true; // "/"
  if (['/', '~', '$HOME', '${HOME}', '%USERPROFILE%', '${userHome}', '${env:HOME}', '${env:USERPROFILE}', '/Users', '/home', '/root'].includes(s)) return true;
  if (/^[A-Za-z]:$/.test(s)) return true; // C:\
  if (/^[A-Za-z]:[\\\/]Users$/i.test(s)) return true;
  if (h && s.toLowerCase() === h.toLowerCase()) return true;
  if (/^\/(Users|home)\/[^\/]+$/.test(s) || /^[A-Za-z]:[\\\/]Users[\\\/][^\\\/]+$/i.test(s)) return true;
  return false;
}

export function insecureUrl(url) {
  if (typeof url !== 'string' || !/^http:\/\//i.test(url)) return false;
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    return !(host === 'localhost' || host === '::1' || host === '0.0.0.0' || /^127\./.test(host) || host.endsWith('.localhost'));
  } catch { return true; }
}
