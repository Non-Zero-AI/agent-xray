// v0.3 checks: auto-run inventory (hooks, status lines, key helpers, tasks, plugins), new harnesses
// (Copilot CLI, OpenCode, OpenClaw, Aider, Qwen Code), instruction-file hygiene and the offline
// "Am I infected?" IOC pass. Static analysis only: nothing found here is executed, fetched or changed.
import fs from 'node:fs';
import nodePath from 'node:path';
import { commandFlags, displayCommand, hookList, worstSeverity, STARTUP_EVENTS } from './autorun.js';
import { hiddenUnicode, injectionHits, remoteScriptHits, frontmatter, INSTRUCTION_NAMES } from './instructions.js';
import { commandHits, textHits, packageHit, packagesInCommand, iocDocs, sha256File } from './iocs.js';
import { allowRuleRisk, unwrapCommand, packageSpec, RUNNERS, isBroadRoot } from './rules.js';
import { findLine } from './secrets.js';
import { tildify } from './paths.js';
import { sysPath } from './host.js';

// ---------- glob expansion for agents.js paths (*, **, {a,b}) ----------
const SKIP_DIRS = new Set(['node_modules', '.git', 'cache', 'Cache', '.cache', 'dist', 'build']);
export function globPaths(pattern, { maxDepth = 6, max = 300 } = {}) {
  const parts = pattern.split(/[\\/]/);
  const firstGlob = parts.findIndex((p) => /[*{]/.test(p));
  if (firstGlob < 0) return [pattern];
  let root = parts.slice(0, firstGlob).join(nodePath.sep) || nodePath.sep;
  if (/^[A-Za-z]:$/.test(root)) root += nodePath.sep;
  const segs = parts.slice(firstGlob);
  const toRe = (seg) => new RegExp('^' + seg.replace(/[.+^$()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '.').replace(/\{([^}]*)\}/g, (m, alts) => `(?:${alts.split(',').join('|')})`) + '$');
  const out = [];
  const walk = (dir, i, depth) => {
    if (out.length >= max || depth > maxDepth + segs.length) return;
    const seg = segs[i];
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    if (seg === '**') {
      walk(dir, i + 1, depth); // zero dirs
      if (depth >= maxDepth) return;
      for (const e of ents) if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(nodePath.join(dir, e.name), i, depth + 1);
      return;
    }
    const re = toRe(seg);
    const last = i === segs.length - 1;
    for (const e of ents) {
      if (!re.test(e.name)) continue;
      const p = nodePath.join(dir, e.name);
      if (last) { if (e.isFile() || e.isSymbolicLink()) out.push(p); } else if (e.isDirectory()) walk(p, i + 1, depth + 1);
      if (out.length >= max) return;
    }
  };
  walk(root, 0, 0);
  return [...new Set(out)].sort();
}

/** JSON5-lite: comments, trailing commas, unquoted keys, single-quoted strings. */
export function parseJson5(text, parseJsonc) {
  try { return parseJsonc(text); } catch { /* fall through */ }
  let s = text.replace(/^\uFEFF/, '');
  s = s.replace(/'((?:[^'\\\n]|\\.)*)'/g, (m, inner) => JSON.stringify(inner.replace(/\\'/g, "'")));
  s = s.replace(/([{,]\s*)([A-Za-z_$][\w$-]*)\s*:/g, '$1"$2":');
  return parseJsonc(s);
}

const safeUrl = (u) => { try { const x = new URL(u); x.username = ''; x.password = ''; x.search = x.search ? '?…' : ''; return x.toString(); } catch { return '[invalid url]'; } };
const KIND_LABEL = { hook: 'hook', statusLine: 'status line', apiKeyHelper: 'API key helper', helper: 'credential helper', task: 'folder-open task', plugin: 'plugin', command: 'command', skill: 'skill', subagent: 'subagent', rule: 'rule', tool: 'tool', notify: 'notify command' };
const STARTUPISH = new Set(['statusLine', 'apiKeyHelper', 'helper', 'task', 'plugin']);
const HELPER_KEYS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper'];

export const INFECTED_STEPS = [
  'STOP: do not rotate or revoke tokens yet. The Mini Shai-Hulud "gh-token-monitor" service watches your GitHub token and, per CSA, wipes your home folder when the token is revoked while it runs.',
  "Find the persistence service: Linux `systemctl --user list-units --all | grep -Ei 'gh-token-monitor|kitty-monitor'` (and `sudo systemctl list-units --all | grep -Ei ...`); macOS `launchctl list | grep -Ei 'gh-token-monitor|kitty-monitor'` and look in ~/Library/LaunchAgents and /Library/LaunchDaemons.",
  'Disable and remove it: `systemctl --user disable --now gh-token-monitor.service kitty-monitor.service` (sudo for system units) or `launchctl bootout gui/$(id -u) <plist>`, then delete the unit/plist files plus ~/.local/bin/gh-token-monitor.sh and ~/.local/share/kitty/cat.py.',
  "Confirm nothing is still running: `pgrep -fa 'gh-token-monitor|kitty-monitor|execution\\.js|\\.config/index\\.js'` must print nothing.",
  'Remove the injected files and hooks in every repo and in your home: .claude/setup.mjs, .claude/execution.js, .vscode/setup.mjs, the SessionStart hook / folderOpen task that runs them, ~/.config/index.js, and any unexpected .github/workflows file.',
  'Only now rotate credentials: GitHub tokens and SSH keys, npm tokens, cloud keys (AWS/GCP/Azure), and every AI provider key that was on this machine.',
  'Check GitHub for repos named "A Mini Shai-Hulud has Appeared", unexpected "dependabout/..." branches and commits by claude@users.noreply.github.com with message "chore: update dependencies"; block api.masscan.cloud at your firewall.',
  'Re-run agent-xray. Report confirmed infections to your security team. agent-xray never removes anything itself.',
];

export function makeHarness(ctx, api, iocs) {
  const { addFinding } = api;
  const autorun = [];
  const home = ctx.home;
  const show = (p) => tildify(p, home);
  const iocFinding = (entry, f) => addFinding({ category: 'infected', severity: 'critical', ...f, refs: iocDocs(iocs, entry), iocId: entry.id, persistence: !!(entry.persistence || iocs.campaigns[entry.campaign]?.persistenceService) });

  const checkPackages = (cmdText, loc, line, where) => {
    for (const p of packagesInCommand(cmdText)) {
      const hit = packageHit(p.spec, iocs, p.ecosystem, p.version);
      if (hit) packageFinding(hit, loc.agents, loc.path, line, where);
    }
  };
  const packageFinding = (hit, agents, file, line, where) => {
    const label = `${hit.name}${hit.version ? '@' + hit.version : ''}`;
    if (hit.severity === 'critical') iocFinding(hit.entry, { id: 'ioc.package', agents, title: hit.status === 'malicious' ? `Known-malicious package referenced: ${hit.name}` : `Compromised package version: ${label}`, detail: `${where}. ${hit.entry.what || (hit.status === 'malicious' ? 'Published by attackers.' : 'This exact version was published by the Mini Shai-Hulud worm.')}${hit.entry.verified === false ? ' (IOC not independently verified; treat as suspicious.)' : ''}`, file, line, evidence: label, fix: 'Do not run it. Follow the infected-machine steps before rotating anything.' });
    else addFinding({ id: 'ioc.watch', severity: hit.severity, category: 'unpinned', agents, title: hit.status === 'reported' ? `Package reported as malicious (unconfirmed): ${hit.name}` : hit.status === 'scope-watch' ? `Unpinned package from a scope hit by Mini Shai-Hulud: ${hit.name}` : `Unpinned package with known-bad versions: ${hit.name}`, detail: `${where}. ${hit.status === 'may-resolve' ? `Versions ${hit.entry.versions.join(', ')} were malicious; an unpinned spec can resolve to them from a stale cache or mirror.` : hit.status === 'watch' || hit.status === 'reported' ? (hit.entry.what || 'Named in incident reports; pin a reviewed version.') : `Packages in this scope were trojanized between ${hit.entry.window || 'Apr–May 2026'}.`}`, file, line, evidence: label, fix: hit.status === 'reported' ? 'Remove it unless you have reviewed its source; if it ever ran, check the "Am I infected?" steps.' : 'Pin an exact, reviewed version (and check your lockfile for the bad versions).', refs: iocDocs(iocs, hit.entry) });
  };

  /** Record one auto-run entry and raise findings for it. */
  const record = (loc, e) => {
    const isHelper = e.kind === 'apiKeyHelper' || e.kind === 'helper';
    const flags = commandFlags(e.command).filter((f) => f.id !== 'reads-key-file' || isHelper);
    const hits = commandHits(e.command, iocs);
    const line = e.line ?? (e.command ? findLine(loc.text, e.command.slice(0, 60)) ?? findLine(loc.text, e.command.split(/\s+/)[0]) : null);
    const rec = { agents: loc.agents, kind: e.kind, event: e.event || null, matcher: e.matcher || null, command: e.command ? displayCommand(e.command, home) : null, url: e.url ? safeUrl(e.url) : null, file: show(loc.path), line, scope: loc.scope, flags: flags.map((f) => f.id), disabled: !!e.disabled };
    if (hits.length) rec.flags.unshift('ioc');
    autorun.push(rec);
    if (e.disabled) return;
    const what = `${loc.scope === 'project' ? 'Project ' : loc.scope === 'managed' ? 'Managed ' : ''}${e.event && e.kind === 'hook' ? `${e.event} ` : ''}${KIND_LABEL[e.kind] || e.kind}`;
    const ev = rec.command || rec.url;
    if (hits.length) {
      for (const h of hits) iocFinding(h, { id: 'ioc.command', agents: loc.agents, title: `${what} matches a known malware command (${(iocs.campaigns[h.campaign]?.name || h.campaign).split(' (')[0]})`, detail: `${h.what || 'Matches an indicator of compromise.'} It runs automatically${e.event ? ` on ${e.event}` : ''}.`, file: loc.path, line, evidence: ev, fix: 'Do NOT rotate tokens first. Follow the infected-machine steps in order.' });
    } else if (flags.length) {
      const sev = worstSeverity(flags);
      addFinding({ id: 'autorun.risky', severity: sev, category: 'autorun', agents: loc.agents, title: `${what} ${flags[0].label}`, detail: `This runs automatically${e.event ? ` (${e.event}${e.matcher ? `, matcher ${e.matcher}` : ''})` : ''} with your user's permissions, outside the agent's permission prompts. Flags: ${flags.map((f) => f.id).join(', ')}.${loc.scope === 'project' ? ' It comes from the repo, so anyone who can push to it controls what runs on your machine.' : ''}`, file: loc.path, line, evidence: ev, fix: 'Delete the entry, or replace it with a reviewed local script pinned in the repo. Never pipe downloads into a shell.' });
    } else if (loc.scope === 'project' && (STARTUP_EVENTS.test(e.event || '') || STARTUPISH.has(e.kind))) {
      addFinding({ id: 'autorun.project', severity: 'medium', category: 'autorun', agents: loc.agents, title: `${what} runs code from the repo automatically`, detail: `Opening this project runs \`${ev || e.kind}\`${e.event ? ` on ${e.event}` : ''}. Fine if you wrote it; a cloned or forked repo can use this to run anything.`, file: loc.path, line, evidence: ev, fix: 'Review what it runs; remove it if you did not add it.' });
    } else if (loc.scope === 'project' && e.kind === 'hook' && e.command) {
      addFinding({ id: 'autorun.project', severity: 'low', category: 'autorun', agents: loc.agents, title: `${what} runs a repo command on agent events`, detail: `Runs \`${ev}\`${e.event ? ` on ${e.event}` : ''} for anyone who opens this repo with the agent.`, file: loc.path, line, evidence: ev, fix: 'Keep project hooks small and reviewed.' });
    }
    if (e.type === 'http' && e.url) addFinding({ id: 'autorun.http', severity: 'medium', category: 'autorun', agents: loc.agents, title: `${what} sends agent events to ${safeUrl(e.url).replace(/\?…$/, '')}`, detail: 'HTTP hooks post event payloads (prompts, tool inputs, file paths) to a remote server.', file: loc.path, line, evidence: safeUrl(e.url), fix: 'Remove it unless you run that endpoint.' });
    if (e.prompt) for (const h of injectionHits(e.prompt)) addFinding({ id: 'instructions.injection', severity: h.severity, category: 'injection', agents: loc.agents, title: `Prompt hook ${h.label}`, detail: `"${h.snippet}"`, file: loc.path, line, fix: 'Remove the hook.' });
    if (e.command) checkPackages(e.command, loc, line, `Run by ${what}`);
  };

  /** Pull every auto-run entry out of a parsed settings / hooks file. */
  const fromConfig = (S, { hooksAtRoot = false } = {}) => {
    const { data, loc } = S;
    const disabled = data.disableAllHooks === true;
    const block = hooksAtRoot ? data : data.hooks && typeof data.hooks === 'object' ? { hooks: data.hooks } : null;
    if (block) for (const h of hookList(block)) record({ ...loc, text: S.text }, { kind: 'hook', ...h, disabled });
    const L = { ...loc, text: S.text };
    const sl = data.statusLine ?? data.ui?.statusLine;
    if (sl && typeof sl === 'object' && typeof sl.command === 'string') record(L, { kind: 'statusLine', event: 'status refresh', command: sl.command });
    for (const k of HELPER_KEYS) if (typeof data[k] === 'string') record(L, { kind: k === 'apiKeyHelper' ? 'apiKeyHelper' : 'helper', event: k, command: data[k] });
    for (const k of ['discoveryCommand', 'callCommand']) if (typeof data.tools?.[k] === 'string') record(L, { kind: 'tool', event: `tools.${k}`, command: data.tools[k] });
    if (Array.isArray(data.notify) && data.notify.length) record(L, { kind: 'notify', event: 'after each turn', command: data.notify.map(String).join(' ') });
    for (const [k, v] of Object.entries(data)) if (typeof v === 'string' && /(?:Helper|Command)$/.test(k) && !HELPER_KEYS.includes(k)) record(L, { kind: 'helper', event: k, command: v });
    if (data.enabledPlugins && typeof data.enabledPlugins === 'object') for (const [name, on] of Object.entries(data.enabledPlugins)) if (on) autorun.push({ agents: loc.agents, kind: 'plugin', event: 'enabled', matcher: null, command: name, url: null, file: show(loc.path), line: findLine(S.text, name), scope: loc.scope, flags: [], disabled: false });
  };

  /** Hidden Unicode, injection phrasing, remote-script lines, IOC package installs. */
  const instructionChecks = (loc, text, label = 'Instruction file') => {
    const fm = frontmatter(text);
    const always = fm && fm.alwaysApply ? ' This rule has alwaysApply: true, so it is loaded into every session.' : '';
    const hu = hiddenUnicode(text);
    const nHidden = hu.tags + hu.bidi + hu.zeroWidth + hu.variation;
    if (nHidden) {
      const kinds = [hu.tags && `${hu.tags} Unicode tag char${hu.tags === 1 ? '' : 's'} (invisible text)`, hu.bidi && `${hu.bidi} bidi control${hu.bidi === 1 ? '' : 's'} (reorders text)`, hu.zeroWidth && `${hu.zeroWidth} zero-width char${hu.zeroWidth === 1 ? '' : 's'}`, hu.variation && `${hu.variation} variation selector${hu.variation === 1 ? '' : 's'}`].filter(Boolean);
      const sev = hu.tags || hu.bidi || hu.variation || hu.zeroWidth >= 10 ? 'high' : 'medium';
      const shown = hu.lines.slice(0, 3).map((l) => `line ${l.line}: ${l.visible}`).join(' | ');
      addFinding({ id: 'unicode.hidden', severity: sev, category: 'hidden-unicode', agents: loc.agents, title: `${label} contains hidden characters: ${kinds.join(', ')}`, detail: `The model reads characters you cannot see in your editor.${hu.decoded.length ? ` Hidden tag text decodes to: "${hu.decoded.join(' ').slice(0, 100)}".` : ''} Made visible: ${shown}${hu.lines.length > 3 ? ` (+${hu.lines.length - 3} more lines)` : ''}.${always}`, file: loc.path, line: hu.lines[0]?.line, evidence: hu.lines[0]?.visible.slice(0, 120), fix: 'Delete the hidden characters (or the file if you did not write it) and check git blame for who added them.', unicode: { tags: hu.tags, bidi: hu.bidi, zeroWidth: hu.zeroWidth, variation: hu.variation, lines: hu.lines.slice(0, 10), decoded: hu.decoded.slice(0, 4).map((d) => String(d).slice(0, 200)) } });
    }
    const inj = injectionHits(text);
    if (hu.decoded.length) for (const h of injectionHits(hu.decoded.join('\n'))) if (!inj.some((x) => x.id === h.id)) inj.push({ ...h, label: `${h.label} (inside hidden text)`, severity: 'high' });
    for (const h of inj.slice(0, 4)) addFinding({ id: 'instructions.injection', severity: h.severity, category: 'injection', agents: loc.agents, title: `${label} ${h.label}`, detail: `Prompt-injection phrasing: "${h.snippet}".${always}`, file: loc.path, line: h.line, evidence: h.snippet, fix: 'Remove the instruction. If you did not write it, treat the repo or folder as untrusted.' });
    const rs = remoteScriptHits(text);
    if (hu.decoded.length && !rs.length) for (const r of remoteScriptHits(hu.decoded.join('\n'))) rs.push({ ...r, line: hu.lines[0]?.line, snippet: `(hidden text) ${r.snippet}` });
    for (const r of rs.slice(0, 3)) addFinding({ id: 'instructions.remoteScript', severity: 'high', category: 'injection', agents: loc.agents, title: `${label} tells the agent to ${IMPERATIVE[r.flags[0].id] || 'run a risky command'}`, detail: `An agent following this file will run: ${r.snippet}${always}`, file: loc.path, line: r.line, evidence: r.snippet, fix: 'Replace it with a pinned, reviewed install step, or delete it.' });
    text.split(/\r?\n/).forEach((ln, i) => { if (/\b(?:npm|pnpm|yarn|bun|npx|bunx|pip3?|uvx|pipx)\b/.test(ln)) checkPackages(ln, loc, i + 1, `${label} tells the agent to install it`); });
    if (fm?.hasHooks) for (const m of fm.raw.matchAll(/command\s*:\s*["']?(.+?)["']?\s*$/gm)) record({ ...loc, text }, { kind: 'hook', event: 'frontmatter hook', command: m[1] });
  };

  const IMPERATIVE = { 'pipe-to-shell': 'pipe a downloaded script into a shell', 'eval-remote': 'evaluate code it downloads', 'base64-exec': 'decode and run a hidden payload', 'reverse-shell': 'open a remote shell', exfil: 'send secrets to a remote host' };
  const TEXT_KINDS = { instructions: 'Instruction file', skill: 'Skill', subagent: 'Subagent', command: 'Custom command', rule: 'Rule file', planted: 'Planted instruction file' };
  /** Called for every file read (before parsing). */
  const onText = (loc, text) => {
    for (const h of textHits(text, iocs)) iocFinding(h, { id: 'ioc.text', agents: loc.agents, title: `File contains a known malware marker: "${h.label || h.re}"`, detail: h.what || 'Matches an indicator of compromise.', file: loc.path, line: findLine(text, (h.label || '').slice(0, 30)) ?? null, evidence: h.label || null, fix: 'Do NOT rotate tokens first. Follow the infected-machine steps in order.' });
    if (TEXT_KINDS[loc.kind]) {
      instructionChecks(loc, text, TEXT_KINDS[loc.kind]);
      if (['skill', 'subagent', 'rule', 'command'].includes(loc.kind)) autorun.push({ agents: loc.agents, kind: loc.kind, event: loc.kind === 'command' ? 'on demand' : loc.kind === 'rule' && !/alwaysApply\s*:\s*true/.test(text) && /\.mdc$/.test(loc.path) ? 'when matched' : 'auto-loaded', matcher: null, command: null, url: null, file: show(loc.path), line: null, scope: loc.scope, flags: [], disabled: false });
    }
    if (loc.kind === 'plugin-code') {
      const flags = commandFlags(text).filter((f) => ['critical', 'high'].includes(f.severity));
      const L = { ...loc, text };
      autorun.push({ agents: loc.agents, kind: 'plugin', event: 'startup (auto-loaded)', matcher: null, command: null, url: null, file: show(loc.path), line: null, scope: loc.scope, flags: flags.map((f) => f.id), disabled: false });
      if (flags.length) addFinding({ id: 'autorun.risky', severity: worstSeverity(flags), category: 'autorun', agents: loc.agents, title: `Auto-loaded plugin ${flags[0].label}`, detail: `OpenCode loads every file in this folder at startup. Flags: ${flags.map((f) => f.id).join(', ')}.`, file: loc.path, fix: 'Delete the plugin unless you wrote and reviewed it.' });
      else if (loc.scope === 'project') addFinding({ id: 'autorun.project', severity: 'medium', category: 'autorun', agents: loc.agents, title: 'Project plugin runs code from the repo at startup', detail: 'OpenCode auto-loads plugins in .opencode/plugins when you open this project.', file: loc.path, fix: 'Review the plugin; remove it if you did not add it.' });
      for (const h of commandHits(text, iocs)) iocFinding(h, { id: 'ioc.command', agents: loc.agents, title: 'Auto-loaded plugin contains a known malware command', detail: h.what || '', file: loc.path, fix: 'Do NOT rotate tokens first. Follow the infected-machine steps in order.' });
      void L;
    }
  };

  // ---------- per-kind handlers ----------
  const handlers = {
    'hooks-file'(S) { fromConfig(S, { hooksAtRoot: true }); },
    'vscode-tasks'(S) {
      for (const t of [].concat(S.data.tasks || [])) {
        if (!t || typeof t !== 'object' || t.runOptions?.runOn !== 'folderOpen') continue;
        const parts = [t.command, ...[].concat(t.args || []).map((a) => (typeof a === 'object' ? a?.value : a))].filter((x) => typeof x === 'string');
        const cmds = [parts.join(' '), ...['linux', 'osx', 'windows'].map((os) => t[os]?.command && [t[os].command, ...[].concat(t[os].args || [])].join(' '))].filter(Boolean);
        for (const c of new Set(cmds)) record({ ...S.loc, text: S.text }, { kind: 'task', event: 'folderOpen', matcher: t.label || null, command: c, line: findLine(S.text, 'folderOpen') });
      }
    },
    'copilot-settings'(S) { fromConfig(S); api.addServers(S, S.data.mcpServers); },
    'copilot-permissions'(S) { // documented shape: { locations: { <abs path>: { tool_approvals: [{ kind, commandIdentifiers }], allowed_directories: [] } } }
      const locs = S.data?.locations;
      if (!locs || typeof locs !== 'object') return;
      const seen = new Set();
      for (const [where, v] of Object.entries(locs)) {
        if (!v || typeof v !== 'object') continue;
        for (const ap of [].concat(v.tool_approvals || [])) {
          if (ap?.kind !== 'commands') continue;
          for (const id of [].concat(ap.commandIdentifiers || [])) {
            if (typeof id !== 'string' || seen.has(id)) continue;
            seen.add(id);
            const r = allowRuleRisk(`Bash(${id})`);
            if (r) addFinding({ id: 'copilot.allow', severity: r.severity, category: 'dangerous-allow', agents: S.loc.agents, title: r.title.replace(/Bash\((.*)\)/, 'shell "$1"'), detail: `${r.why} (saved Copilot CLI approval for ${tildify(where, home)})`, file: S.loc.path, line: findLine(S.text, id), fix: 'Remove the saved approval in Copilot CLI (/permissions) or delete it from permissions-config.json.' });
          }
        }
        for (const d of [].concat(v.allowed_directories || [])) if (typeof d === 'string' && isBroadRoot(d, home)) addFinding({ id: 'copilot.allowedDirectory', severity: 'high', category: 'broad-root', agents: S.loc.agents, title: `Copilot CLI may touch ${tildify(d, home)} without a path prompt`, detail: `allowed_directories for ${tildify(where, home)} includes your whole home folder or /.`, file: S.loc.path, line: findLine(S.text, d), fix: 'Remove the entry or narrow it to a project folder.' });
      }
    },
    'opencode-config'(S) {
      const { data, loc, text } = S;
      api.addServers(S, data.mcp);
      const perm = data.permission ?? data.permissions;
      const L = (k) => findLine(text, k);
      if (perm === 'allow' || (perm && typeof perm === 'object' && perm['*'] === 'allow')) addFinding({ id: 'opencode.yolo', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: OpenCode allows every action without asking', detail: 'permission is "allow" (or "*": "allow"): shell, edits and web fetches all run without approval.', file: loc.path, line: L('"allow"'), fix: 'Set "permission": { "*": "ask" } and allow specific commands only.' });
      else if (perm && typeof perm === 'object') {
        const bash = perm.bash;
        if (bash === 'allow' || (bash && typeof bash === 'object' && bash['*'] === 'allow')) addFinding({ id: 'opencode.bash', severity: 'critical', category: 'dangerous-allow', agents: loc.agents, title: 'OpenCode runs any shell command without asking', detail: 'permission.bash is "allow" — equivalent to Bash(*).', file: loc.path, line: L('"bash"'), fix: 'Use "bash": { "*": "ask", "git status": "allow", ... }.' });
        else if (bash && typeof bash === 'object') for (const [pat, act] of Object.entries(bash)) if (act === 'allow' && pat !== '*') { const r = allowRuleRisk(`Bash(${pat.replace(/\s\*$/, ':*')})`); if (r) addFinding({ id: 'opencode.bash', severity: r.severity, category: 'dangerous-allow', agents: loc.agents, title: r.title.replace(/Bash\((.*)\)/, `bash "${pat}"`), detail: r.why, file: loc.path, line: L(pat), fix: `Change "${pat}" to "ask".` }); }
        const ext = perm.external_directory;
        if (ext && typeof ext === 'object') for (const [pat, act] of Object.entries(ext)) if (act === 'allow' && isBroadRoot(pat.replace(/\/\*\*?$/, '').replace(/^\$HOME/, '~'), home)) addFinding({ id: 'opencode.externalDirectory', severity: 'high', category: 'broad-root', agents: loc.agents, title: `OpenCode can reach ${pat} outside the project`, detail: 'permission.external_directory allows your whole home folder or /.', file: loc.path, line: L(pat), fix: 'Allow only specific project folders.' });
      }
      for (const p of [].concat(data.plugin || data.plugins || [])) {
        if (typeof p !== 'string') continue;
        const local = /^(\.|\/|~|file:)/.test(p);
        const rec = { kind: 'plugin', event: 'startup (installed with Bun)', command: p, line: findLine(text, p) };
        record({ ...loc, text }, rec);
        if (!local) {
          const hit = packageHit(p, iocs, 'npm');
          if (hit) packageFinding(hit, loc.agents, loc.path, rec.line, 'OpenCode installs and loads this plugin at startup');
          else if (!/@\d+\.\d+\.\d+/.test(p.replace(/^@/, ''))) addFinding({ id: 'opencode.plugin.unpinned', severity: 'medium', category: 'unpinned', agents: loc.agents, title: `Unpinned OpenCode plugin installs at startup: ${p}`, detail: 'OpenCode installs npm plugins automatically with Bun; without a version a hijacked release runs inside your agent.', file: loc.path, line: rec.line, evidence: p, fix: `Pin it: "${p.replace(/@[^@/]*$/, '')}@<version>".` });
        }
      }
    },
    'qwen-settings'(S) {
      const { data, loc, text } = S;
      fromConfig(S);
      api.addServers(S, data.mcpServers);
      const mode = data.tools?.approvalMode ?? data.general?.defaultApprovalMode ?? data.approvalMode;
      if (mode === 'yolo') addFinding({ id: 'qwen.yolo', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Qwen Code auto-approves every tool', detail: 'tools.approvalMode is "yolo".', file: loc.path, line: findLine(text, 'yolo'), fix: 'Use "default" (or "auto-edit" for trusted repos).' });
      for (const rule of [].concat(data.permissions?.allow || [], data.tools?.allowed || [])) { const r = typeof rule === 'string' && allowRuleRisk(rule); if (r) addFinding({ id: 'qwen.allow', severity: r.severity, category: 'dangerous-allow', agents: loc.agents, title: r.title, detail: r.why, file: loc.path, line: findLine(text, rule), fix: `Remove "${rule}".` }); }
    },
    'aider-config'(S) {
      const { data, loc, text } = S;
      if (data['yes-always'] === true || data.yes === true) addFinding({ id: 'aider.yesAlways', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Aider answers "yes" to every confirmation', detail: 'yes-always: true lets Aider run suggested shell commands and create/edit files without asking.', file: loc.path, line: findLine(text, 'yes-always') ?? findLine(text, 'yes:'), fix: 'Remove yes-always (pass --yes-always only in a sandbox).' });
      for (const k of ['lint-cmd', 'test-cmd', 'notifications-command']) for (const c of [].concat(data[k] || [])) if (typeof c === 'string') record({ ...loc, text }, { kind: 'command', event: k, command: c.replace(/^[\w-]+:\s*/, '') });
    },
    'openclaw-config'(S) { fromConfig(S); api.addServers(S, S.data.mcpServers ?? S.data.mcp?.servers); },
  };

  // ---------- post-pass: planted files, IOC files, services, lockfiles ----------
  const post = (processLoc) => {
    // planted instruction files
    const planted = [];
    const dirs = [[nodePath.join(home, 'Downloads'), 'high', 2], [nodePath.join(home, 'Desktop'), 'high', 1], ...(ctx.tmpDirs || []).map((d) => [d, 'high', 1]), [home, 'medium', 0]];
    const names = new Set(INSTRUCTION_NAMES.filter((n) => n !== 'SKILL.md'));
    for (const [dir, sev, depth] of dirs) {
      const walk = (d, lvl) => {
        let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          const p = nodePath.join(d, e.name);
          if (e.isFile() && names.has(e.name)) planted.push([p, sev, dir]);
          else if (e.isDirectory() && lvl < depth && !e.name.startsWith('.') && e.name !== 'node_modules') walk(p, lvl + 1);
        }
      };
      walk(dir, 0);
    }
    for (const [p, sev, dir] of planted) {
      if (ctx.project && p.startsWith(ctx.project + nodePath.sep)) continue;
      const where = dir === home ? 'your home folder' : show(dir);
      addFinding({ id: 'instructions.planted', severity: sev, category: 'planted', agents: ['shared'], title: `Agent instruction file in ${where}: ${nodePath.basename(p)}`, detail: dir === home ? 'Any agent started from your home folder loads this file into every session. Make sure you wrote it.' : `Agents started in ${where} (or in a downloaded/extracted folder) load this automatically. Attackers plant AGENTS.md files in Downloads to make agents install malware.`, file: p, fix: 'Delete it unless you put it there on purpose.' });
      processLoc({ agents: ['shared'], path: p, kind: 'planted', format: 'text', scope: 'user' });
    }
    // IOC files
    const roots = (scope) => (scope === 'project' ? [ctx.project, home] : [home]).filter(Boolean);
    for (const e of iocs.files || []) {
      for (const r of roots(e.scope)) {
        const p = nodePath.join(r, ...e.path.split('/'));
        let st; try { st = fs.statSync(p); } catch { continue; }
        if (!st.isFile()) continue;
        let confirmed = false, sev = e.confidence === 'medium' ? 'high' : 'critical';
        if (e.sha256?.length) { const h = sha256File(p); confirmed = !!h && e.sha256.includes(h); if (!confirmed) sev = 'high'; }
        if (e.contains) { let t = ''; try { t = fs.readFileSync(p, 'utf8'); } catch { /* */ } if (!t.includes(e.contains)) continue; }
        const f = { id: 'ioc.file', severity: sev, agents: ['shared'], title: `${confirmed ? 'Confirmed malware file' : 'Known malware file name'}: ${show(p)}`, detail: `${e.what || 'Matches an indicator of compromise.'}${confirmed ? ' SHA-256 matches a published sample.' : e.sha256?.length ? ' The hash differs from published samples, so check it by hand.' : ''}`, file: p, evidence: confirmed ? 'sha256 match' : null, fix: 'Do NOT rotate tokens first. Follow the infected-machine steps in order.' };
        if (sev === 'critical') iocFinding(e, f); else { const x = { ...f, category: 'infected' }; addFinding({ ...x, refs: iocDocs(iocs, e), iocId: e.id, persistence: !!e.persistence }); }
      }
    }
    // persistence services
    for (const s of iocs.services || []) {
      const cands = [nodePath.join(home, '.config', 'systemd', 'user', `${s.name}.service`), ...['/etc/systemd/system', '/etc/systemd/user', '/usr/lib/systemd/user', '/lib/systemd/system'].map((d) => nodePath.join(sysPath(ctx, d), `${s.name}.service`))];
      for (const d of [nodePath.join(home, 'Library', 'LaunchAgents'), sysPath(ctx, '/Library/LaunchAgents'), sysPath(ctx, '/Library/LaunchDaemons')]) { try { for (const n of fs.readdirSync(d)) if (n.toLowerCase().includes(s.name.toLowerCase())) cands.push(nodePath.join(d, n)); } catch { /* */ } }
      for (const p of cands) { try { if (!fs.statSync(p).isFile()) continue; } catch { continue; } iocFinding({ ...s, persistence: true }, { id: 'ioc.service', agents: ['shared'], title: `Malware persistence service installed: ${s.name}`, detail: `${s.what || 'Known persistence service.'} Remove it BEFORE rotating any token.`, file: p, fix: 'Disable and delete the service first, then rotate credentials.' }); }
    }
    // MCP servers referencing bad packages
    for (const s of api.servers) {
      if (s.disabled || !s.command) continue;
      const { base, args } = unwrapCommand(s.command, s.args);
      if (!RUNNERS.has(base)) continue;
      const spec = packageSpec(base, args);
      if (!spec) continue;
      const hit = packageHit(spec.pkg, iocs, ['uvx', 'pipx', 'pip', 'uv'].includes(base) ? 'pypi' : 'npm');
      if (hit) packageFinding(hit, s.agents, s.file, s.line, `MCP server "${s.name}" runs it`);
    }
    // project manifests and lockfiles (exact versions only; no scope-watch noise for normal deps)
    if (ctx.project) {
      const read = (rel) => { try { return fs.readFileSync(nodePath.join(ctx.project, rel), 'utf8'); } catch { return null; } };
      const pj = read('package.json');
      if (pj) { try { const d = JSON.parse(pj); for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies']) for (const [n, v] of Object.entries(d[sec] || {})) { const h = packageHit(n, iocs, 'npm', String(v)); if (h && (h.severity === 'critical' || h.status === 'may-resolve')) packageFinding(h, ['shared'], nodePath.join(ctx.project, 'package.json'), findLine(pj, `"${n}"`), `Listed in package.json ${sec}`); } } catch { /* */ } }
      const lock = read('package-lock.json');
      if (lock) { try { const d = JSON.parse(lock); for (const [k, v] of Object.entries(d.packages || {})) { if (!k) continue; const n = k.replace(/^.*node_modules\//, ''); const h = packageHit(n, iocs, 'npm', v?.version || ''); if (h && h.severity === 'critical') packageFinding(h, ['shared'], nodePath.join(ctx.project, 'package-lock.json'), findLine(lock, `"${k}"`), 'Installed per package-lock.json'); } } catch { /* */ } }
      for (const e of iocs.packages || []) if ((e.ecosystem || 'npm') === 'npm') { const t = read(`node_modules/${e.name}/package.json`); if (!t) continue; try { const h = packageHit(e.name, iocs, 'npm', JSON.parse(t).version || ''); if (h && h.severity === 'critical') packageFinding(h, ['shared'], nodePath.join(ctx.project, 'node_modules', e.name, 'package.json'), null, 'Installed in node_modules'); } catch { /* */ } }
    }
  };

  return { autorun, handlers, onText, fromConfig, post };
}
