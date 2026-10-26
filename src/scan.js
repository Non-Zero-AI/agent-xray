import { annotateFixes } from './fixes.js';
import { badgeFor } from './badge.js';
import fs from 'node:fs';
import os from 'node:os';
import nodePath from 'node:path';
import { AGENTS, locations, presenceDirs } from './agents.js';
import { parseJsonc } from './parse/jsonc.js';
import { parseToml } from './parse/toml.js';
import { parseYaml } from './parse/yaml.js';
import { scanText, scanKeyValues, isPlaceholder, looksLikeSecretKey, redact, findLine, classifyCredential } from './secrets.js';
import { allowRuleRisk, terminalAllowRisk, mcpAllowRisk, unwrapCommand, packageSpec, RUNNERS, isBroadRoot, insecureUrl } from './rules.js';
import { tildify, isAbs } from './paths.js';
import { grade } from './grade.js';
import { discover, analyzeStack } from './stack.js';
import { scanHost, hostHomes, sysPath } from './host.js';
import { loadIocs, iocSummary } from './iocs.js';
import { makeHarness, globPaths, parseJson5, INFECTED_STEPS } from './harness.js';

export const VERSION = '0.3.1';
export const SCHEMA_VERSION = 1;
const MAX_FILE = 5 * 1024 * 1024;

export function makeContext(opts = {}) {
  const platform = opts.platform || process.platform;
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  let project = opts.project === undefined ? process.cwd() : opts.project;
  if (project && nodePath.resolve(project) === nodePath.resolve(home)) project = null; // home is not a project
  return {
    platform, home, env, project,
    P: opts.pathImpl || nodePath,
    deep: !!opts.deep,
    checkBinaries: opts.checkBinaries !== false,
    sample: !!opts.sample,
    now: opts.now || new Date().toISOString(),
    paths: (opts.paths || []).map((p) => nodePath.resolve(p)),
    server: !!opts.server,
    label: opts.label ? String(opts.label).slice(0, 40) : null,
    sysRoot: opts.sysRoot || '/',
    tmpDirs: opts.tmpDirs || [...new Set([os.tmpdir(), '/tmp'].filter((d) => process.platform !== 'win32' || d !== '/tmp'))],
    iocsPath: opts.iocs || null,
  };
}

function readFileSafe(p) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > MAX_FILE) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}

function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }

function parse(format, text) {
  if (format === 'json' || format === 'jsonc') return parseJsonc(text);
  if (format === 'toml') return parseToml(text);
  if (format === 'yaml') return parseYaml(text);
  if (format === 'json5') return parseJson5(text, parseJsonc);
  return null;
}

function onPath(cmd, ctx) {
  const PATH = ctx.env.PATH || ctx.env.Path || '';
  if (!PATH) return true; // can't tell; don't flag
  const sep = ctx.platform === 'win32' ? ';' : ':';
  const exts = ctx.platform === 'win32' ? ['', ...(ctx.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').toLowerCase().split(';')] : [''];
  for (const dir of PATH.split(sep)) {
    if (!dir) continue;
    for (const e of exts) if (exists(nodePath.join(dir, cmd + e))) return true;
  }
  return false;
}

export function scan(opts = {}) {
  const ctx = makeContext(opts);
  const show = (p) => tildify(p, ctx.home);
  const files = [];
  const servers = [];
  const findings = [];
  const detected = new Set();
  const secretValues = new Map(); // value -> redacted (internal; never serialized)

  const addFinding = (f) => {
    findings.push({
      id: f.id, severity: f.severity, category: f.category,
      agents: f.agents, title: f.title, detail: f.detail || '',
      file: f.file ? show(f.file) : null, line: f.line ?? null,
      evidence: f.evidence ? show(f.evidence) : null,
      fix: f.fix || '',
      ...(f.credential ? { credential: f.credential } : {}),
      ...(f.refs?.length ? { refs: f.refs } : {}),
      ...(f.persistence ? { persistence: true } : {}),
      ...(f.iocId ? { iocId: f.iocId } : {}),
      ...(f.unicode ? { unicode: f.unicode } : {}),
    });
  };

  const secretFiles = new Map(); // value -> { first: file, label, copies: Set<file>, agents } (internal; never serialized)
  const addSecret = (hit, file, agents, scope, where, o = {}) => {
    const cls = classifyCredential(hit.value);
    if (cls.publishable) return; // e.g. Supabase anon key: public by design
    const known = secretFiles.get(hit.value);
    if (known) { // same secret again: count once, note the extra copy
      if (known.first !== file) known.copies.add(file);
      return;
    }
    secretFiles.set(hit.value, { first: file, label: cls.label || hit.label, copies: new Set(), agents });
    secretValues.set(hit.value, true);
    const label = cls.label || hit.label;
    const projectNote = scope === 'project' ? ' This is a project file, so it may be committed to git and shared.' : '';
    addFinding({
      id: 'secret.plaintext', severity: o.severity || 'high', category: 'secret', agents,
      title: o.title ? (cls.label ? o.title.replace(hit.label, cls.label) : o.title) : `Plaintext ${label}${where ? ` (${where})` : ''}`,
      detail: `${o.detail || 'A live-looking credential is stored in plain text in an agent config. Every agent, extension and MCP server that can read this file can read the key.'}${cls.note ? ' ' + cls.note : ''}${o.extraDetail || ''}${projectNote}`,
      file, line: hit.line, evidence: hit.kind === 'url-password' ? '****' : redact(hit.value),
      fix: o.fix || 'Move it to an environment variable or your OS keychain, reference it as ${env:NAME} / $NAME, and rotate the key.',
      credential: cls.label ? 'supabase-service-role' : hit.kind, // provider id only, never the value
    });
  };

  // ---------- per-file processing ----------
  const iocs = loadIocs(ctx.iocsPath);
  const H = makeHarness(ctx, { addFinding, servers, addServers: (S, map) => addServersFromMap(S, map) }, iocs);
  const locs = locations(ctx);
  const expanded = [];
  for (const loc of locs) {
    if (/[*{]/.test(loc.path)) { for (const p of globPaths(loc.path)) expanded.push({ ...loc, path: p }); continue; }
    if (loc.kind === 'instructions-dir' || loc.kind === 'continue-dir') {
      let entries = [];
      try { entries = fs.readdirSync(loc.path); } catch { continue; }
      for (const e of entries) {
        if (loc.kind === 'continue-dir' && !/\.(ya?ml|json)$/i.test(e)) continue;
        expanded.push({ ...loc, path: ctx.P.join(loc.path, e), kind: loc.kind === 'continue-dir' ? 'continue-config' : 'instructions', format: loc.kind === 'continue-dir' ? (/\.json$/i.test(e) ? 'jsonc' : 'yaml') : 'text' });
      }
    } else expanded.push(loc);
  }

  const scannedPaths = new Set();
  const processLoc = (loc) => {
    if (scannedPaths.has(loc.path)) return;
    const text = readFileSafe(loc.path);
    if (text === null) return;
    scannedPaths.add(loc.path);
    loc.agents.forEach((a) => detected.add(a));
    const fileRec = { path: show(loc.path), agents: loc.agents, kind: loc.kind, scope: loc.scope, parsed: true };
    files.push(fileRec);

    // 1. raw text secret scan (works even if parsing fails)
    const rawHits = scanText(text);
    const seen = new Set(rawHits.map((h) => h.value));
    const where = loc.kind === 'instructions' ? 'in agent instructions — sent to the model every session' : '';
    for (const h of rawHits) addSecret(h, loc.path, loc.agents, loc.scope, where);
    H.onText(loc, text);
    if (loc.format === 'text') return;

    let data;
    try { data = parse(loc.format, text); } catch (e) {
      fileRec.parsed = false;
      addFinding({ id: 'config.unparseable', severity: 'info', category: 'parse-error', agents: loc.agents, title: 'Config file could not be parsed', detail: String(e.message).slice(0, 160), file: loc.path, fix: 'Check the file for syntax errors.' });
      return;
    }
    if (!data || typeof data !== 'object') return;

    // 2. literal secrets under secret-looking keys anywhere in the structure
    deepSecretWalk(data, (k, v) => {
      if (seen.has(v)) return;
      if ([...seen].some((s) => v.includes(s))) return;
      const hits = scanKeyValues({ [k]: v }, text, seen);
      for (const h of hits) addSecret(h, loc.path, loc.agents, loc.scope, '');
    });
    // secrets passed as CLI args / URL query params are handled per-server below
    const S = { ctx, loc, text, data, seen, addFinding, addSecret, servers };
    (HANDLERS[loc.kind] || H.handlers[loc.kind])?.(S);
    if (['claude-settings', 'codex-config', 'gemini-settings'].includes(loc.kind)) H.fromConfig(S);
  };
  for (const loc of expanded) processLoc(loc);

  // ---------- --server / --path: self-hosted agent stacks ----------
  const strengths = [];
  const inventory = { tools: [], models: new Set() };
  const stackFiles = [];
  let stackStats = null;
  if (ctx.server || ctx.paths.length) {
    const secretsInKV = (kv, text, file, where, agents = ['host'], o = {}) => {
      const raw = scanText(Object.values(kv).join('\n'));
      const seen = new Set(raw.map((h) => h.value));
      for (const h of raw) addSecret({ ...h, line: findLine(text, h.value) }, file, agents, 'host', where, o);
      for (const h of scanKeyValues(kv, text, seen)) addSecret(h, file, agents, 'host', where, o);
    };
    const api = {
      addFinding, addSecret, secretsInKV, strengths, inventory, files: stackFiles, show,
      addLoc: (loc) => { const before = files.length; processLoc(loc); if (files.length > before) detected.add('stack'); },
      markScanned: (p) => scannedPaths.add(p),
    };
    const roots = [...ctx.paths];
    let unitEnvFiles = [];
    if (ctx.server) {
      detected.add('host');
      unitEnvFiles = scanHost(ctx, api).envFiles;
      if (!ctx.paths.length) roots.push(...['/opt', '/srv', '/etc'].map((p) => ({ path: sysPath(ctx, p), depth: p === '/etc' ? 2 : 6 })), ...hostHomes(ctx).map((h) => ({ path: h, depth: 5 })));
    }
    const disc = discover(roots);
    disc.files = disc.files.filter((f) => !scannedPaths.has(f.path));
    for (const ef of unitEnvFiles) if (!disc.files.some((f) => f.path === ef)) disc.files.push({ path: ef, kind: 'env' });
    analyzeStack(ctx, disc, api);
    stackStats = { roots: roots.map((r) => show(typeof r === 'string' ? r : r.path)), filesScanned: disc.scanned, skippedLargeDirs: disc.skippedLarge, filesOfInterest: stackFiles.length };
    if (stackFiles.length || findings.some((f) => f.agents.includes('stack'))) detected.add('stack');
    for (const t of inventory.tools) if (t.write.length) addFinding({
      id: 'stack.writeTools', severity: 'info', category: 'inventory', agents: ['stack'],
      title: `Agent can take ${t.write.length} write action${t.write.length === 1 ? '' : 's'} (of ${t.total} tools)`,
      detail: `Write-capable: ${t.write.slice(0, 12).join(', ')}${t.write.length > 12 ? ', …' : ''}. Not a problem by itself; make sure each one needs a human confirmation or is tightly scoped.`,
      file: t.file, evidence: t.key, fix: 'Confirm these write actions require explicit user confirmation and are logged.',
    });
  }
  // extra copies of the same secret: one low finding per secret
  for (const [, info] of secretFiles) if (info.copies.size) addFinding({
    id: 'secret.duplicate', severity: 'low', category: 'secret', agents: info.agents,
    title: `Same ${info.label} is copied in ${info.copies.size} more place${info.copies.size === 1 ? '' : 's'}`,
    detail: `Every copy has to be rotated and protected. Extra copies: ${[...info.copies].map(show).slice(0, 5).join(', ')}${info.copies.size > 5 ? ', …' : ''}.`,
    file: info.first, fix: 'Delete stale copies (old backups, quarantine folders) after rotating the key.',
  });

  // ---------- presence ----------
  for (const [agent, dir] of presenceDirs(ctx)) if (exists(dir)) detected.add(agent);

  // ---------- cross-server checks ----------
  analyzeServers(servers, ctx, addFinding, addSecret);

  // ---------- --deep: .env exposure ----------
  if (ctx.deep && ctx.project) deepEnvScan(ctx, addFinding, servers);

  // ---------- planted instruction files, IOC files/services/packages ----------
  H.post(processLoc);

  // ---------- assemble ----------
  const serverInventory = mergeServers(servers, show);
  const agentIds = Object.keys(AGENTS).filter((a) => detected.has(a) || findings.some((f) => f.agents.includes(a)));
  const agentName = (id) => (id === 'stack' && ctx.label ? ctx.label : AGENTS[id].name);
  const report = {
    tool: 'agent-xray', version: VERSION, schemaVersion: SCHEMA_VERSION,
    generatedAt: ctx.now, sample: ctx.sample,
    platform: ctx.platform, project: ctx.project ? show(ctx.project) : null, deep: ctx.deep,
    agents: agentIds.map((id) => ({ id, name: agentName(id), files: files.filter((f) => f.agents.includes(id)).map((f) => f.path), servers: serverInventory.filter((s) => s.agents.includes(id)).length })),
    servers: serverInventory,
    findings: sortFindings(findings),
    files: [...files.map((f) => ({ path: f.path, agents: f.agents, scope: f.scope, parsed: f.parsed })), ...stackFiles.map((f) => ({ path: show(f.path), agents: ['stack'], scope: 'stack', parsed: true, kind: f.kind }))],
  };
  report.autorun = H.autorun;
  const infected = findings.filter((f) => f.category === 'infected');
  report.infected = {
    status: infected.length ? 'indicators' : 'clean',
    hits: infected.length,
    persistence: [...new Set(infected.filter((f) => f.persistence).map((f) => f.title))],
    iocListUpdated: iocSummary(iocs).updated,
    indicatorsChecked: iocSummary(iocs).indicators,
    ...(infected.length ? { steps: INFECTED_STEPS } : {}),
  };
  if (ctx.server || ctx.paths.length) {
    report.mode = ctx.server ? 'server' : 'paths';
    report.label = ctx.label;
    report.stack = { ...stackStats, tools: inventory.tools, backupConfigs: inventory.backupConfigs || 0, models: [...inventory.models].sort() };
    report.strengths = strengths;
  }
  report.counts = {
    agents: report.agents.filter((a) => a.id !== 'shared').length,
    mcpServers: new Set(serverInventory.map((s) => s.name.toLowerCase())).size,
    mcpDefinitions: serverInventory.length,
    remoteServers: serverInventory.filter((s) => s.transport !== 'stdio').length,
    plaintextSecrets: secretValues.size,
    yoloAgents: new Set(findings.filter((f) => f.category === 'yolo' && f.severity === 'critical').flatMap((f) => f.agents)).size,
    dangerousRules: findings.filter((f) => f.category === 'dangerous-allow').length,
    autoTrust: findings.filter((f) => f.category === 'auto-trust').length,
    unpinnedPackages: findings.filter((f) => f.category === 'unpinned').length,
    insecureRemote: findings.filter((f) => f.category === 'insecure-remote').length,
    broadRoots: findings.filter((f) => f.category === 'broad-root').length,
    sandboxOff: findings.filter((f) => f.category === 'sandbox').length,
    staleServers: findings.filter((f) => f.category === 'stale-server').length,
    envExposure: findings.filter((f) => f.category === 'env-exposure').length,
    hostExposure: findings.filter((f) => f.category === 'host-exposure' && f.severity !== 'info').length,
    autorunEntries: H.autorun.filter((a) => ['hook', 'statusLine', 'apiKeyHelper', 'helper', 'task', 'plugin', 'tool', 'notify'].includes(a.kind) || (a.kind === 'command' && a.command)).length,
    riskyAutorun: findings.filter((f) => f.category === 'autorun' && f.severity !== 'low').length,
    iocMatches: infected.length,
    hiddenUnicode: findings.filter((f) => f.category === 'hidden-unicode').length,
    injection: findings.filter((f) => f.category === 'injection').length,
    plantedFiles: findings.filter((f) => f.category === 'planted').length,
    bySeverity: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, findings.filter((f) => f.severity === s).length])),
  };
  grade(report);
  report.badge = badgeFor(report.overall.grade, { infected: report.infected.status === 'indicators' });
  annotateFixes(report);
  return report;
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function sortFindings(f) { return f.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.category.localeCompare(b.category)); }

function deepSecretWalk(obj, cb, depth = 0, parentKey = '') {
  if (!obj || typeof obj !== 'object' || depth > 10) return;
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      if (looksLikeSecretKey(k) || /^authorization$/i.test(k)) cb(k, v);
    } else if (v && typeof v === 'object') deepSecretWalk(v, cb, depth + 1, k);
  }
}

// ---------- server normalization ----------
function normServer(name, def, loc, extra = {}) {
  if (!def || typeof def !== 'object') return null;
  let command = def.command ?? def.cmd ?? null;
  let args = def.args ?? null;
  let env = def.env ?? def.envs ?? null;
  if (Array.isArray(command)) { // OpenCode: { type: 'local', command: ['npx', '-y', 'pkg'], environment }
    args = [...command.slice(1), ...(Array.isArray(args) ? args : [])];
    command = command[0] ?? null;
  }
  if (command && !Array.isArray(command) && typeof command === 'object') { // Zed: { command: { path, args, env } }
    args = command.args ?? args;
    env = command.env ?? env;
    command = command.path ?? command.command ?? null;
  }
  if (!env && def.environment && typeof def.environment === 'object') env = def.environment;
  if (def.transport && typeof def.transport === 'object') { // Continue legacy
    command = def.transport.command ?? command;
    args = def.transport.args ?? args;
    env = def.transport.env ?? env;
  }
  const url = def.url ?? def.serverUrl ?? def.httpUrl ?? def.uri ?? def.transport?.url ?? null;
  const type = String(def.type ?? def.transport?.type ?? (url ? (def.httpUrl || /streamable/.test(def.type || '') ? 'http' : 'http') : 'stdio')).toLowerCase();
  if (type === 'local' && !url) { /* OpenCode stdio */ }
  if (type === 'builtin' || type === 'platform' || type === 'frontend' || type === 'inline_python') return null; // Goose built-ins
  const transport = url ? (/sse/.test(type) ? 'sse' : 'http') : 'stdio';
  return {
    name: String(def.name ?? name), command: typeof command === 'string' ? command : null,
    args: Array.isArray(args) ? args.map(String) : [], env: env && typeof env === 'object' ? env : {},
    headers: def.headers ?? def.http_headers ?? {}, url: typeof url === 'string' ? url : null, transport,
    disabled: def.disabled === true || def.enabled === false,
    trust: def.trust === true,
    autoApprove: [].concat(def.autoApprove ?? [], def.alwaysAllow ?? []).filter((x) => typeof x === 'string'),
    file: loc.path, scope: loc.scope, agents: loc.agents, ...extra,
  };
}

function addServersFromMap(S, map, extra) {
  if (!map || typeof map !== 'object') return;
  const entries = Array.isArray(map) ? map.map((d, i) => [d?.name ?? `server-${i + 1}`, d]) : Object.entries(map);
  for (const [name, def] of entries) {
    const s = normServer(name, def, S.loc, extra);
    if (s) { s.line = findLine(S.text, `"${s.name}"`) ?? findLine(S.text, s.name); S.servers.push(s); }
  }
}

function claudeSettings(S) {
  const { data, loc, text, addFinding } = S;
  const perms = data.permissions || {};
  const mode = perms.defaultMode;
  const L = (n) => findLine(text, n);
  if (mode === 'bypassPermissions') {
    if (loc.scope === 'project') {
      addFinding({ id: 'claude.bypass.project', severity: 'medium', category: 'yolo', agents: loc.agents, title: 'bypassPermissions set in project settings', detail: 'Current Claude Code ignores bypassPermissions in project settings (the session starts in Manual mode), but it signals intent and older versions may honor it.', file: loc.path, line: L('bypassPermissions'), fix: 'Remove "defaultMode": "bypassPermissions" from project settings.' });
    } else {
      addFinding({ id: 'claude.bypass', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Claude Code skips every permission prompt', detail: 'permissions.defaultMode is "bypassPermissions": shell, file writes and MCP tools all run without asking. Anthropic says to use this only in isolated containers/VMs.', file: loc.path, line: L('bypassPermissions'), fix: 'Use "default" or "acceptEdits" (or "auto") and pass --dangerously-skip-permissions only inside a sandbox/container.' });
    }
  } else if (mode === 'auto' || mode === 'acceptEdits') {
    addFinding({ id: `claude.mode.${mode}`, severity: 'low', category: 'yolo', agents: loc.agents, title: `Claude Code starts in "${mode}" mode`, detail: mode === 'auto' ? 'Most actions run without prompts; a background classifier screens them.' : 'File edits and common filesystem commands run without prompts.', file: loc.path, line: L(`"${mode}"`), fix: 'Fine for trusted projects; switch to "default" for unfamiliar repos.' });
  }
  for (const rule of [].concat(perms.allow || [])) {
    const r = allowRuleRisk(rule);
    if (r) addFinding({ id: 'claude.allow', severity: r.severity, category: 'dangerous-allow', agents: loc.agents, title: r.title, detail: r.why, file: loc.path, line: L(rule), fix: `Remove "${rule}" from permissions.allow or narrow it to the exact command you need.` });
  }
  for (const d of [].concat(perms.additionalDirectories || [])) {
    if (isBroadRoot(d, S.ctx.home)) addFinding({ id: 'claude.additionalDirectories', severity: 'high', category: 'broad-root', agents: loc.agents, title: `Claude Code has access to ${tildify(d, S.ctx.home)}`, detail: 'additionalDirectories includes your whole home folder or the filesystem root — SSH keys, browser profiles and every other repo are in reach.', file: loc.path, line: L(d), fix: 'List only the specific project folders the agent needs.' });
  }
  if (data.skipDangerousModePermissionPrompt === true) addFinding({ id: 'claude.skipDangerousPrompt', severity: 'medium', category: 'yolo', agents: loc.agents, title: 'Bypass-mode warning disabled', detail: 'skipDangerousModePermissionPrompt hides the confirmation shown before entering bypassPermissions mode.', file: loc.path, line: L('skipDangerousModePermissionPrompt'), fix: 'Remove skipDangerousModePermissionPrompt.' });
  if (data.enableAllProjectMcpServers === true) addFinding({ id: 'claude.enableAllProjectMcpServers', severity: 'high', category: 'auto-trust', agents: loc.agents, title: 'Auto-trusts every MCP server in any repo', detail: 'enableAllProjectMcpServers starts every server listed in a project .mcp.json without asking — cloning a malicious repo can mean running its code.', file: loc.path, line: L('enableAllProjectMcpServers'), fix: 'Remove it and approve project servers one by one (enabledMcpjsonServers).' });
  if (data.sandbox && data.sandbox.enabled === false) addFinding({ id: 'claude.sandbox.off', severity: 'low', category: 'sandbox', agents: loc.agents, title: 'Claude Code Bash sandbox explicitly disabled', detail: 'sandbox.enabled is false.', file: loc.path, line: L('"enabled"'), fix: 'Set sandbox.enabled to true (macOS, Linux, WSL2).' });
}

const HANDLERS = {
  'claude-settings': claudeSettings,
  'claude-global'(S) {
    addServersFromMap(S, S.data.mcpServers);
    for (const [proj, cfg] of Object.entries(S.data.projects || {})) {
      if (!cfg || typeof cfg !== 'object') continue;
      addServersFromMap(S, cfg.mcpServers, { projectScope: tildify(proj, S.ctx.home) });
      for (const rule of [].concat(cfg.allowedTools || [])) {
        const r = allowRuleRisk(rule);
        if (r) S.addFinding({ id: 'claude.allowedTools', severity: r.severity, category: 'dangerous-allow', agents: S.loc.agents, title: r.title, detail: `${r.why} (project ${tildify(proj, S.ctx.home)})`, file: S.loc.path, line: findLine(S.text, rule), fix: 'Remove it via /permissions in that project.' });
      }
    }
  },
  'mcp-standard'(S) { addServersFromMap(S, S.data.mcpServers ?? S.data.servers); },
  'vscode-mcp'(S) { addServersFromMap(S, S.data.servers ?? S.data.mcpServers); },
  'cursor-cli'(S) {
    for (const rule of [].concat(S.data.permissions?.allow || [])) {
      const r = allowRuleRisk(rule);
      if (r) S.addFinding({ id: 'cursor.cli.allow', severity: r.severity, category: 'dangerous-allow', agents: S.loc.agents, title: r.title, detail: r.why, file: S.loc.path, line: findLine(S.text, rule), fix: `Remove "${rule}" from permissions.allow.` });
    }
  },
  'cursor-permissions'(S) {
    for (const e of [].concat(S.data.terminalAllowlist || [])) {
      const r = terminalAllowRisk(e);
      if (r) S.addFinding({ id: 'cursor.terminalAllowlist', severity: r.severity, category: 'dangerous-allow', agents: S.loc.agents, title: r.title.replace(/Shell\((.*)\)/, 'terminal "$1"'), detail: r.why, file: S.loc.path, line: findLine(S.text, `"${e}"`), fix: `Remove "${e}" from terminalAllowlist.` });
    }
    for (const e of [].concat(S.data.mcpAllowlist || [])) {
      const r = mcpAllowRisk(e);
      if (r) S.addFinding({ id: 'cursor.mcpAllowlist', severity: r.severity, category: 'dangerous-allow', agents: S.loc.agents, title: r.title, detail: r.why, file: S.loc.path, line: findLine(S.text, `"${e}"`), fix: 'Allow-list specific server:tool pairs instead of *:*.' });
    }
  },
  'codex-config'(S) {
    const { data, loc, text } = S;
    const check = (cfg, label) => {
      const ap = cfg.approval_policy, sb = cfg.sandbox_mode;
      const where = label ? ` (profile "${label}")` : '';
      if (ap === 'never' && sb === 'danger-full-access') {
        S.addFinding({ id: 'codex.yolo', severity: 'critical', category: 'yolo', agents: loc.agents, title: `YOLO mode: Codex runs anything, no sandbox, no prompts${where}`, detail: 'approval_policy = "never" with sandbox_mode = "danger-full-access" is the same as --yolo: full disk and network access, never asks.', file: loc.path, line: findLine(text, 'danger-full-access'), fix: 'Use approval_policy = "on-request" and sandbox_mode = "workspace-write".' });
      } else {
        if (sb === 'danger-full-access') S.addFinding({ id: 'codex.sandbox.off', severity: 'high', category: 'sandbox', agents: loc.agents, title: `Codex sandbox disabled${where}`, detail: 'sandbox_mode = "danger-full-access" lets every command read and write anywhere and use the network.', file: loc.path, line: findLine(text, 'danger-full-access'), fix: 'Use sandbox_mode = "workspace-write".' });
        if (ap === 'never') S.addFinding({ id: 'codex.approval.never', severity: 'medium', category: 'yolo', agents: loc.agents, title: `Codex never asks for approval${where}`, detail: 'approval_policy = "never": the sandbox is the only guard.', file: loc.path, line: findLine(text, 'approval_policy'), fix: 'Use approval_policy = "on-request".' });
      }
      const sww = cfg.sandbox_workspace_write || {};
      for (const r of [].concat(sww.writable_roots || [])) if (isBroadRoot(r, S.ctx.home)) S.addFinding({ id: 'codex.writable_roots', severity: 'high', category: 'broad-root', agents: loc.agents, title: `Codex can write to ${tildify(r, S.ctx.home)}`, detail: 'sandbox_workspace_write.writable_roots includes your home folder or /.', file: loc.path, line: findLine(text, r), fix: 'Only add specific project folders.' });
    };
    check(data, '');
    for (const [name, prof] of Object.entries(data.profiles || {})) if (prof && typeof prof === 'object') check(prof, name);
    addServersFromMap(S, data.mcp_servers);
  },
  'gemini-settings'(S) {
    const { data, loc, text } = S;
    addServersFromMap(S, data.mcpServers);
    const mode = data.general?.defaultApprovalMode ?? data.defaultApprovalMode;
    if (mode === 'yolo') S.addFinding({ id: 'gemini.yolo', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Gemini CLI auto-approves every tool', detail: 'Default approval mode is "yolo".', file: loc.path, line: findLine(text, 'yolo'), fix: 'Use "default" and run --yolo only in a sandbox.' });
    else if (mode === 'auto_edit' || mode === 'autoEdit') S.addFinding({ id: 'gemini.autoEdit', severity: 'low', category: 'yolo', agents: loc.agents, title: 'Gemini CLI auto-approves edits', detail: 'Default approval mode auto-accepts file edits.', file: loc.path, line: findLine(text, String(mode)), fix: 'Fine for trusted projects.' });
    const autoAccept = data.tools?.autoAccept ?? data.autoAccept;
    if (autoAccept === true) S.addFinding({ id: 'gemini.autoAccept', severity: 'low', category: 'yolo', agents: loc.agents, title: 'Gemini CLI autoAccept is on', detail: 'Tool calls Gemini considers safe run without confirmation.', file: loc.path, line: findLine(text, 'autoAccept'), fix: 'Set autoAccept to false if you want to see every call.' });
    for (const rule of [].concat(data.tools?.allowed || [], data.allowedTools || [])) {
      const r = allowRuleRisk(rule);
      if (r) S.addFinding({ id: 'gemini.allowed', severity: r.severity, category: 'dangerous-allow', agents: loc.agents, title: r.title, detail: r.why, file: loc.path, line: findLine(text, rule), fix: `Remove "${rule}" from tools.allowed.` });
    }
  },
  'vscode-settings'(S) {
    const { data, loc, text } = S;
    const L = (k) => findLine(text, k);
    if (data['chat.tools.global.autoApprove'] === true || data['chat.tools.autoApprove'] === true) {
      const k = data['chat.tools.global.autoApprove'] === true ? 'chat.tools.global.autoApprove' : 'chat.tools.autoApprove';
      S.addFinding({ id: 'vscode.globalAutoApprove', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: VS Code auto-approves every agent tool', detail: `${k} is true — Microsoft: "this setting disables critical security protections".`, file: loc.path, line: L(k), fix: `Remove ${k}; use per-session /yolo only when needed.` });
    }
    const pd = data['chat.permissions.default'];
    if (pd === 'autoApprove' || pd === 'autopilot') S.addFinding({ id: 'vscode.permissionsDefault', severity: 'critical', category: 'yolo', agents: loc.agents, title: `VS Code chat sessions start in "${pd}"`, detail: 'New agent sessions approve all tools by default.', file: loc.path, line: L('chat.permissions.default'), fix: 'Set chat.permissions.default to "default".' });
    const term = data['chat.tools.terminal.autoApprove'];
    if (term && typeof term === 'object') {
      for (const [cmd, v] of Object.entries(term)) {
        const on = v === true || (v && typeof v === 'object' && v.approve === true);
        if (!on) continue;
        const pattern = cmd.startsWith('/') ? cmd.replace(/^\/|\/[a-z]*$/g, '') : cmd;
        const r = /^(\.\*|\.\+|\^\.\*\$?|\^?\.\*\$|\*)$/.test(pattern) ? allowRuleRisk('Bash(*)') : allowRuleRisk(`Bash(${pattern.replace(/^\^/, '').replace(/\\b.*$/, '')})`);
        if (r) S.addFinding({ id: 'vscode.terminalAutoApprove', severity: r.severity, category: 'dangerous-allow', agents: loc.agents, title: r.title.replace(/Bash\((.*)\)/, `terminal "${cmd}"`), detail: r.why, file: loc.path, line: L(JSON.stringify(cmd).slice(1, -1)), fix: `Remove "${cmd}" from chat.tools.terminal.autoApprove.` });
      }
    }
    if (data['chat.tools.terminal.ignoreDefaultAutoApproveRules'] === true) S.addFinding({ id: 'vscode.ignoreDefaultRules', severity: 'medium', category: 'dangerous-allow', agents: loc.agents, title: 'VS Code default terminal deny-rules ignored', detail: 'The built-in rules that force prompts for rm, curl, wget, eval, chmod… are turned off.', file: loc.path, line: L('ignoreDefaultAutoApproveRules'), fix: 'Remove chat.tools.terminal.ignoreDefaultAutoApproveRules.' });
    if (data.mcp?.servers) addServersFromMap(S, data.mcp.servers);
  },
  'continue-config'(S) {
    const d = S.data;
    if (Array.isArray(d.mcpServers)) addServersFromMap(S, d.mcpServers);
    else if (d.mcpServers) addServersFromMap(S, d.mcpServers);
    if (Array.isArray(d.experimental?.modelContextProtocolServers)) addServersFromMap(S, d.experimental.modelContextProtocolServers);
  },
  'zed-settings'(S) {
    const { data, loc, text } = S;
    addServersFromMap(S, data.context_servers);
    const ag = data.agent || data.assistant || {};
    if (ag.always_allow_tool_actions === true || ag.tool_permissions?.default === 'allow') {
      S.addFinding({ id: 'zed.allowAll', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Zed agent runs tools without confirmation', detail: ag.always_allow_tool_actions === true ? 'agent.always_allow_tool_actions is true.' : 'agent.tool_permissions.default is "allow".', file: loc.path, line: findLine(text, ag.always_allow_tool_actions === true ? 'always_allow_tool_actions' : 'tool_permissions'), fix: 'Set agent.tool_permissions.default to "confirm".' });
    }
  },
  'goose-config'(S) {
    const { data, loc, text } = S;
    addServersFromMap(S, data.extensions);
    if (String(data.GOOSE_MODE || '').toLowerCase() === 'auto') S.addFinding({ id: 'goose.auto', severity: 'critical', category: 'yolo', agents: loc.agents, title: 'YOLO mode: Goose runs every tool automatically', detail: 'GOOSE_MODE is "auto" (fully autonomous).', file: loc.path, line: findLine(text, 'GOOSE_MODE'), fix: 'Use GOOSE_MODE: smart_approve or approve.' });
  },
};

// ---------- server analysis ----------
function analyzeServers(servers, ctx, addFinding, addSecret) {
  const home = ctx.home;
  for (const s of servers) {
    const label = s.projectScope ? `${s.name} (project ${s.projectScope})` : s.name;
    const text = readFileSafe(s.file) || '';
    // secrets passed as CLI args or in URL query strings
    for (let i = 0; i < s.args.length; i++) {
      const a = s.args[i];
      let value = null, key = null;
      const eq = /^--?([\w\-]*(key|token|secret|password|pat)[\w\-]*)=(.+)$/i.exec(a);
      if (eq) { key = eq[1]; value = eq[3]; } else if (/^--?[\w\-]*(key|token|secret|password)[\w\-]*$/i.test(a) && s.args[i + 1]) { key = a; value = s.args[i + 1]; }
      if (value && !isPlaceholder(value) && !scanText(value).length) addSecret({ kind: 'generic', label: `secret in ${key} argument`, value, line: findLine(text, value) }, s.file, s.agents, s.scope, `server "${label}"`);
    }
    if (s.url) {
      try {
        const u = new URL(s.url);
        for (const [k, v] of u.searchParams) if (looksLikeSecretKey(k) && !isPlaceholder(v) && !scanText(v).length) addSecret({ kind: 'generic', label: `secret in URL ?${k}=`, value: v, line: findLine(text, v) }, s.file, s.agents, s.scope, `server "${label}"`);
      } catch { /* ignore */ }
    }
    if (s.disabled) continue;
    const { base, args, cmd } = unwrapCommand(s.command, s.args);
    if (s.url && insecureUrl(s.url)) addFinding({ id: 'mcp.http', severity: 'high', category: 'insecure-remote', agents: s.agents, title: `Remote MCP server over plain http: ${label}`, detail: 'Tool calls, results and any auth headers travel unencrypted and can be read or rewritten on the network.', file: s.file, line: s.line, evidence: safeUrl(s.url), fix: 'Use an https:// endpoint.' });
    const joined = [cmd, ...args].join(' ');
    if (/(curl|wget|iwr|invoke-webrequest|irm)\b[^|]*\|\s*(ba|z)?sh\b|\|\s*iex\b/i.test(joined)) {
      addFinding({ id: 'mcp.pipe-to-shell', severity: 'critical', category: 'unpinned', agents: s.agents, title: `MCP server pipes a download into a shell: ${label}`, detail: 'Every launch runs whatever that URL serves today.', file: s.file, line: s.line, fix: 'Install a pinned, verified release instead.' });
    }
    if (RUNNERS.has(base)) {
      const spec = packageSpec(base, args);
      if (spec && !spec.pinned) addFinding({ id: 'mcp.unpinned', severity: 'medium', category: 'unpinned', agents: s.agents, title: `Unpinned package runs on every launch: ${label}`, detail: `\`${base}${spec.autoYes ? ' -y' : ''} ${spec.pkg}\` pulls whatever version is newest — a hijacked or typosquatted release runs with your agent's access.`, file: s.file, line: s.line, evidence: `${base} ${spec.pkg}`, fix: base === 'docker' ? 'Pin the image by tag or @sha256 digest.' : `Pin an exact version: ${spec.pkg.replace(/@(latest|next)$/, '')}@<version>.` });
    }
    const isFs = /server-filesystem|filesystem/i.test(joined) || /^(fs|filesystem|files)$/i.test(s.name);
    if (isFs) {
      for (const a of args) if (!a.startsWith('-') && isBroadRoot(a, home)) {
        addFinding({ id: 'mcp.fs.broad', severity: 'high', category: 'broad-root', agents: s.agents, title: `Filesystem MCP server can reach ${a === '/' || /^[A-Za-z]:\\?$/.test(a) ? 'your entire disk' : 'your whole home folder'}: ${label}`, detail: 'SSH keys, cloud credentials, browser profiles and every other project are readable (and often writable) by the agent.', file: s.file, line: s.line, evidence: tildify(a, home), fix: 'Point it at specific project folders only.' });
        break;
      }
    }
    if (s.trust) addFinding({ id: 'mcp.trust', severity: 'high', category: 'auto-trust', agents: s.agents, title: `Every tool auto-approved for server: ${label}`, detail: '"trust": true bypasses all confirmations for this server.', file: s.file, line: s.line, fix: 'Remove "trust": true or use includeTools to limit what is exposed.' });
    if (s.autoApprove.length) addFinding({ id: 'mcp.autoApprove', severity: s.autoApprove.some((t) => t === '*' || /exec|shell|command|write|delete|run/i.test(t)) ? 'medium' : 'low', category: 'auto-trust', agents: s.agents, title: `${s.autoApprove.length} tool(s) auto-approved on ${label}`, detail: `Auto-approved: ${s.autoApprove.slice(0, 6).join(', ')}${s.autoApprove.length > 6 ? '…' : ''}`, file: s.file, line: s.line, fix: 'Keep auto-approve to read-only tools.' });
    if (ctx.checkBinaries && cmd && !s.url) {
      let missing = false;
      if (isAbs(cmd)) missing = !exists(cmd);
      else if (!/[\\\/]/.test(cmd) && !/^\$|\$\{|%/.test(cmd)) missing = !onPath(cmd, ctx);
      const script = ['node', 'python', 'python3', 'deno', 'bun', 'ruby'].includes(base) ? args.find((a) => !a.startsWith('-')) : null;
      if (!missing && script && isAbs(script) && !exists(script)) missing = true;
      if (missing) addFinding({ id: 'mcp.stale', severity: 'low', category: 'stale-server', agents: s.agents, title: `Stale MCP server, binary or script missing: ${label}`, detail: 'The configured command was not found. Stale entries are easy to hijack if something later appears at that path/name.', file: s.file, line: s.line, evidence: tildify(script && isAbs(script) && !exists(script) ? script : cmd, home), fix: 'Remove the entry or fix the path.' });
    }
  }
  // conflicting duplicates: same name, different definition
  const byName = new Map();
  for (const s of servers) {
    const key = s.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(s);
  }
  for (const [name, list] of byName) {
    const defs = new Set(list.map(sig));
    if (defs.size > 1) addFinding({ id: 'mcp.duplicate', severity: 'low', category: 'stale-server', agents: [...new Set(list.flatMap((s) => s.agents))], title: `"${name}" is defined ${list.length} times with different settings`, detail: `Defined in: ${[...new Set(list.map((s) => tildify(s.file, home)))].join(', ')}. Agents may run different versions than you think.`, file: list[0].file, line: list[0].line, fix: 'Keep one definition and remove the others.' });
  }
}

function sig(s) { return JSON.stringify([s.command, s.args, s.url]); }
function safeUrl(u) { try { const x = new URL(u); x.username = ''; x.password = ''; x.search = x.search ? '?…' : ''; return x.toString(); } catch { return '[invalid url]'; } }

function mergeServers(servers, show) {
  const map = new Map();
  for (const s of servers) {
    const k = s.name.toLowerCase() + '|' + sig(s);
    const { base, args } = unwrapCommand(s.command, s.args);
    if (!map.has(k)) {
      const spec = RUNNERS.has(base) ? packageSpec(base, args) : null;
      map.set(k, { name: s.name, transport: s.transport, command: s.command ? show(s.command) : null, package: spec?.pkg ?? null, pinned: spec ? spec.pinned : null, url: s.url ? safeUrl(s.url) : null, envKeys: Object.keys(s.env || {}), agents: [], files: [], disabled: s.disabled });
    }
    const m = map.get(k);
    for (const a of s.agents) if (!m.agents.includes(a)) m.agents.push(a);
    const f = show(s.file) + (s.projectScope ? ` [${s.projectScope}]` : '');
    if (!m.files.includes(f)) m.files.push(f);
  }
  return [...map.values()];
}

// ---------- --deep ----------
const AGENT_IGNORES = ['.cursorignore', '.codeiumignore', '.aiexclude', '.geminiignore', '.aiderignore', '.clineignore', '.rooignore', '.continueignore'];
function deepEnvScan(ctx, addFinding) {
  const root = ctx.project;
  const envFiles = [];
  const walk = (dir, depth) => {
    if (depth > 4 || envFiles.length > 50) return;
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '.venv', 'venv', '__pycache__', 'target'].includes(e.name)) continue;
        walk(nodePath.join(dir, e.name), depth + 1);
      } else if (/^\.env(\..+)?$/.test(e.name) && !/\.(example|sample|template|dist)$/.test(e.name)) envFiles.push(nodePath.join(dir, e.name));
    }
  };
  walk(root, 0);
  if (!envFiles.length) return;
  const read = (n) => readFileSafe(nodePath.join(root, n)) || '';
  const gitignore = read('.gitignore');
  const ignoreBlobs = AGENT_IGNORES.map(read).join('\n');
  const claudeDeny = ['.claude/settings.json', '.claude/settings.local.json'].map((f) => { try { return JSON.stringify(parseJsonc(read(f) || '{}').permissions?.deny || []); } catch { return ''; } }).join('');
  const covers = (blob, rel) => blob.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).some((pat) => globish(pat, rel));
  for (const f of envFiles) {
    const rel = nodePath.relative(root, f).split(nodePath.sep).join('/');
    const hasSecrets = scanText(readFileSafe(f) || '').length > 0 || /^[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*\S{8,}/m.test(readFileSafe(f) || '');
    if (!covers(gitignore, rel)) addFinding({ id: 'env.notGitignored', severity: hasSecrets ? 'high' : 'medium', category: 'env-exposure', agents: ['shared'], title: `${rel} is not in .gitignore`, detail: `An agent running "git add -A" can commit it.${hasSecrets ? ' It contains secret-looking values.' : ''}`, file: f, fix: 'Add .env* to .gitignore (keep .env.example).' });
    const agentBlocked = covers(ignoreBlobs, rel) || /Read\([^)]*\.env/.test(claudeDeny);
    if (!agentBlocked && hasSecrets) addFinding({ id: 'env.readableByAgents', severity: 'medium', category: 'env-exposure', agents: ['shared'], title: `Agents can read ${rel}`, detail: 'No agent ignore file (.cursorignore, .aiexclude, .geminiignore…) or Claude deny rule covers it, so its secrets can end up in model context and logs.', file: f, fix: 'Add .env* to .cursorignore/.aiexclude/.geminiignore and "Read(./.env*)" to Claude permissions.deny.' });
  }
}

function globish(pat, rel) {
  let p = pat.replace(/^\//, '');
  if (p.endsWith('/')) return false;
  const re = new RegExp('^(?:.*/)?' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*') + '$');
  return re.test(rel) || re.test(rel.split('/').pop());
}
