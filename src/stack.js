// Self-hosted / custom agent stacks: anything that is not a known desktop or coding agent.
// Walks the folders given with --path (and, with --server, the usual server locations) looking for
// generic MCP configs, docker-compose files, .env files, loose token files, encrypted credential
// stores and agent tool lists. Strictly read-only. Secret values never leave this module unredacted.
import fs from 'node:fs';
import nodePath from 'node:path';
import { parseJsonc } from './parse/jsonc.js';
import { parseToml } from './parse/toml.js';
import { parseYaml } from './parse/yaml.js';
import { scanText, scanKeyValues, looksLikeSecretKey, isPlaceholder, findLine } from './secrets.js';

const MAX_FILE = 5 * 1024 * 1024;
const MAX_CONFIG = 512 * 1024;
const MAX_TOKEN_FILE = 4096;
const MAX_FILES = 40000;
const MAX_DIR_ENTRIES = 400; // bigger directories are vendored deps/caches, not config
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', '.next', '.nuxt', 'vendor', '.venv', 'venv', 'env', '__pycache__', 'target', '.cache', '.npm', '.pnpm-store', '.yarn', 'site-packages', '.cargo', '.rustup', '.local', 'snap', 'proc', 'sys', 'dev', 'run', 'tmp', 'lost+found', 'coverage', '.turbo', '.vercel', '.terraform']);

export const RE = {
  env: /^\.env(\..+)?$|^[\w.-]+\.env$/,
  envSkip: /\.(example|sample|template|dist|defaults?|tmpl)$|^\.envrc$/i,
  compose: /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i,
  mcp: /^(\.?mcp|mcp[_.-]?(config|settings|servers)|claude_desktop_config|cline_mcp_settings|mcp_settings)\.json$/i,
  config: /^(config|settings|secrets?|credentials?|agent|agents)([\w-]*)\.(json|jsonc|ya?ml|toml)([.-][\w.-]*)?$/i,
  token: /(^|[._-])(token|tokens|pat|secret|secrets|api[_-]?key|apikey|credentials?)$|^\.?[\w-]*_(pat|token)$/i,
  encrypted: /\.(fernet|enc|gpg|age|asc|kdbx|vault)$|\.sops\.|\.secret\.fernet$/i,
};

const AGENT_PORTS = {
  2375: 'Docker API (unauthenticated)', 2376: 'Docker API', 5678: 'n8n', 11434: 'Ollama', 18789: 'OpenClaw gateway', 8888: 'Jupyter',
  6274: 'MCP Inspector', 6277: 'MCP Inspector proxy', 7860: 'Gradio', 8501: 'Streamlit', 3080: 'LibreChat', 8080: 'admin/web UI',
  5432: 'Postgres', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 6333: 'Qdrant', 8000: 'API server', 4000: 'LiteLLM', 1234: 'LM Studio',
};
export { AGENT_PORTS };

const TOOL_KEY = /^(enabled_?)?(operations|tools|allowed_?tools|tool_?allowlist|capabilities|actions|functions|skills)$/i;
const WRITE_VERB = /(send|delete|remove|create|update|write|post|put|patch|transfer|pay|refund|exec|execute|run|shell|revoke|disconnect|approve|cancel|book|purchase|upload|publish|invite|move|rename|drop|insert|charge)/i;
const MODEL_KEY = /^(default_?|fallback_?|primary_?|secondary_?|router_?|guardrail_?|llm_?|chat_?|base_?)?models?(_?(id|name|slug|default|fallback|list))?$/i;

export function readSafe(p, max = MAX_FILE) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > max) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}

/** Permission summary for a file (POSIX only). */
export function perms(p) {
  try {
    const st = fs.statSync(p);
    const m = st.mode & 0o777;
    return { mode: '0' + m.toString(8), world: !!(m & 0o004), group: !!(m & 0o040), uid: st.uid, gid: st.gid };
  } catch { return null; }
}

function walk(root, maxDepth, out, state) {
  const go = (dir, depth) => {
    if (depth > maxDepth || state.count > MAX_FILES) return;
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    if (depth > 0 && ents.length > MAX_DIR_ENTRIES) { state.skippedLarge++; return; }
    for (const e of ents) {
      const p = nodePath.join(dir, e.name);
      if (e.isSymbolicLink()) continue; // never follow links (no loops, no surprises)
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || state.seenDirs.has(p)) continue;
        state.seenDirs.add(p);
        go(p, depth + 1);
      } else if (e.isFile()) {
        state.count++;
        const k = classify(e.name);
        if (k && !state.seenFiles.has(p)) { state.seenFiles.add(p); out.push({ path: p, kind: k }); }
      }
    }
  };
  go(root, 0);
}

export function classify(name) {
  if (RE.encrypted.test(name)) return 'encrypted';
  if (RE.env.test(name)) return RE.envSkip.test(name) ? null : 'env';
  if (RE.compose.test(name)) return 'compose';
  if (RE.mcp.test(name)) return 'mcp';
  if (RE.config.test(name)) return 'config';
  if (/\.key$/i.test(name)) return 'keyfile';
  if (!/\.(js|mjs|cjs|ts|tsx|py|rb|go|rs|java|md|html|css|lock|pid|pub|sock|log|sh|json|ya?ml|toml|db|sqlite|png|jpe?g|svg|zip|gz)$/i.test(name) && RE.token.test(name.replace(/\.txt$/i, ''))) return 'token';
  return null;
}

/** Find candidate files under the given roots. */
export function discover(roots, { depth = 6 } = {}) {
  const out = [];
  const state = { count: 0, skippedLarge: 0, seenDirs: new Set(), seenFiles: new Set() };
  for (const r of roots) {
    const root = typeof r === 'string' ? r : r.path;
    const d = typeof r === 'string' ? depth : r.depth ?? depth;
    let st;
    try { st = fs.statSync(root); } catch { continue; }
    if (st.isFile()) { const k = classify(nodePath.basename(root)) || 'config'; if (!state.seenFiles.has(root)) { state.seenFiles.add(root); out.push({ path: root, kind: k }); } continue; }
    walk(root, d, out, state);
  }
  return { files: out, scanned: state.count, skippedLarge: state.skippedLarge };
}

export function parseEnv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(raw);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, '');
    out[m[1]] = v;
  }
  return out;
}

function parseByExt(p, text) {
  const n = p.toLowerCase().replace(/([.-](bak|prev|old|orig)[\w.-]*|\.\d+)$/i, '');
  if (/\.toml$/.test(n)) return parseToml(text);
  if (/\.ya?ml$/.test(n)) return parseYaml(text);
  return parseJsonc(text);
}

function walkObj(obj, cb, depth = 0, path = []) {
  if (!obj || typeof obj !== 'object' || depth > 12) return;
  for (const [k, v] of Object.entries(obj)) {
    cb(k, v, path);
    if (v && typeof v === 'object') walkObj(v, cb, depth + 1, [...path, k]);
  }
}

/**
 * Analyze discovered files. api = { addFinding, addSecret, addLoc, strengths, inventory, show }
 * addLoc(loc) hands MCP configs to the normal per-file pipeline.
 */
/** Backup / stale copies: *.prev*, *.bak, *.old, *.orig, *~, *.pre-*, quarantine or backup folders. */
export const isBackup = (p) => /(\.(prev|bak|backup|old|orig)([-._\d][\w.:-]*)?$|\.pre-[\w.:-]+$|~$|[\/](quarantine|backups?|old|archive)[\/])/i.test(p) ? 1 : 0;

export function analyzeStack(ctx, disc, api) {
  const AG = ['stack'];
  const { addFinding, addSecret } = api;
  const envFiles = new Set();
  let encrypted = 0;
  const encryptedDirs = new Map();
  const keyFiles = [];
  const permNote = (pm) => (pm?.world ? ' It is readable by every user on the machine.' : pm?.group ? ' It is readable by its group too.' : '');
  const sevFor = (pm, base) => (pm?.world ? 'critical' : pm?.group && base === 'medium' ? 'high' : base);

  const secretsFromKV = (obj, text, file, pm, where, base = 'high') => {
    const raw = scanText(text);
    const seen = new Set(raw.map((h) => h.value));
    for (const h of raw) addSecret(h, file, AG, 'stack', where, { severity: sevFor(pm, base), extraDetail: permNote(pm) });
    const hits = [];
    walkObj(obj, (k, v) => { if (typeof v === 'string' && (looksLikeSecretKey(k) || /^authorization$/i.test(k)) && !seen.has(v) && ![...seen].some((s) => v.includes(s))) hits.push(...scanKeyValues({ [k]: v }, text, seen)); });
    for (const h of hits) addSecret(h, file, AG, 'stack', where, { severity: sevFor(pm, base), extraDetail: permNote(pm) });
  };

  const scanEnvFile = (file) => {
    if (envFiles.has(file)) return;
    envFiles.add(file);
    const text = readSafe(file);
    if (text === null) return;
    api.files.push({ path: file, kind: 'env' });
    secretsFromKV(parseEnv(text), text, file, perms(file), 'in a .env file');
  };

  // Live files first, so a secret's main finding points at the copy in use, not a backup.
  const files = [...disc.files].sort((a, b) => isBackup(a.path) - isBackup(b.path));
  let backupConfigs = 0;
  for (const f of files) {
    if (f.kind === 'encrypted') {
      encrypted++;
      const d = nodePath.dirname(f.path);
      encryptedDirs.set(d, (encryptedDirs.get(d) || 0) + 1);
      continue;
    }
    if (f.kind === 'keyfile') { keyFiles.push(f.path); continue; }
    if (f.kind === 'env') { scanEnvFile(f.path); continue; }
    if (f.kind === 'token') {
      const text = readSafe(f.path, MAX_TOKEN_FILE);
      if (text === null) continue;
      const pm = perms(f.path);
      const hits = scanText(text);
      const t = text.trim();
      if (!hits.length && /^[A-Za-z0-9_\-.:=+\/]{20,512}$/.test(t) && !isPlaceholder(t)) hits.push({ kind: 'generic', label: 'token', value: t, line: 1 });
      if (!hits.length) continue;
      api.files.push({ path: f.path, kind: 'token-file' });
      for (const h of hits) addSecret(h, f.path, AG, 'stack', 'in a loose token file', {
        severity: sevFor(pm, 'medium'), extraDetail: permNote(pm),
        title: `Plaintext ${h.label === 'token' ? 'token' : h.label} in a loose token file`,
        detail: 'A credential is sitting in its own plain-text file. Any agent, script or process running as this user can read it.',
        fix: 'Move it into a secret manager or an encrypted store, load it only into the process that needs it, and rotate it if it was ever shared.',
      });
      continue;
    }
    const text = readSafe(f.path, MAX_CONFIG);
    if (text === null) continue;
    let data = null;
    if (f.kind === 'compose') { try { data = parseYaml(text); } catch { data = null; } }
    else { try { data = parseByExt(f.path, text); } catch { data = null; } }
    const pm = perms(f.path);

    if (f.kind === 'mcp' || (data && typeof data === 'object' && !Array.isArray(data) && (data.mcpServers || (data.servers && f.kind === 'mcp') || data.context_servers))) {
      api.addLoc({ path: f.path, agents: AG, kind: 'mcp-standard', scope: 'stack', format: 'jsonc' });
      continue;
    }
    if (f.kind === 'compose') {
      api.files.push({ path: f.path, kind: 'compose' });
      if (data && typeof data === 'object') analyzeCompose(ctx, f.path, text, data, api, scanEnvFile, secretsFromKV);
      continue;
    }
    // generic config (config.json, settings.yaml, …)
    if (!data || typeof data !== 'object') { const raw = scanText(text); if (raw.length) secretsFromKV({}, text, f.path, pm, 'in a service config'); continue; }
    api.files.push({ path: f.path, kind: 'config' });
    secretsFromKV(data, text, f.path, pm, 'in a service config');
    if (isBackup(f.path)) backupConfigs++; // backups: still scanned for secrets, not listed as live tools
    else inventory(data, f.path, api);
  }

  // --- strengths / custody notes ---
  api.inventory.backupConfigs = (api.inventory.backupConfigs || 0) + backupConfigs;
  if (encrypted) api.strengths.push(`${encrypted} credential file${encrypted === 1 ? '' : 's'} encrypted at rest`);
  for (const k of keyFiles) {
    const d = nodePath.dirname(k);
    if (!encryptedDirs.has(d)) continue;
    const pm = perms(k);
    addFinding({
      id: 'stack.keyNextToVault', severity: pm?.world ? 'high' : 'low', category: 'secret-custody', agents: AG,
      title: 'Encryption key is stored next to the encrypted credentials',
      detail: `The key file sits in the same folder as ${encryptedDirs.get(d)} encrypted credential file(s) (mode ${pm?.mode || '?'}). Anything that can read the folder can decrypt all of them, so the encryption mainly protects backups and copies, not the live box.${permNote(pm)}`,
      file: k, fix: 'Keep the key in a separate location (systemd LoadCredential=, a KMS, or a TPM-sealed secret) readable only by the service.',
    });
  }
  return { envFiles: [...envFiles], encrypted };
}

function analyzeCompose(ctx, file, text, data, api, scanEnvFile, secretsFromKV) {
  const AG = ['stack'];
  const services = data.services && typeof data.services === 'object' ? data.services : {};
  for (const [name, svc] of Object.entries(services)) {
    if (!svc || typeof svc !== 'object') continue;
    const line = findLine(text, `${name}:`);
    const image = String(svc.image || '');
    const vols = [].concat(svc.volumes || []).map((v) => (typeof v === 'string' ? v : `${v?.source || ''}:${v?.target || ''}`));
    if (vols.some((v) => /docker\.sock/.test(v))) {
      api.addFinding({ id: 'compose.dockerSock', severity: 'critical', category: 'host-exposure', agents: AG, title: `Container "${name}" has the Docker socket mounted`, detail: 'Mounting /var/run/docker.sock lets the container start new privileged containers, which is the same as root on the host. If an agent or workflow tool in it is tricked, the whole server goes with it.', file, line, evidence: `${name}: docker.sock`, fix: 'Remove the docker.sock mount, or put a filtering proxy (e.g. tecnativa/docker-socket-proxy with only the calls it needs) in front of it.' });
    }
    if (vols.some((v) => /^(\/|\/root|~|\/home|\/etc)(:|$)/.test(v.split(':')[0] + ':'))) {
      api.addFinding({ id: 'compose.hostRoot', severity: 'high', category: 'broad-root', agents: AG, title: `Container "${name}" mounts a whole host folder like / or a home directory`, detail: 'The container can read (and maybe write) everything under that folder, including keys and configs.', file, line, evidence: `${name}: ${vols.find((v) => /^(\/|\/root|~|\/home|\/etc)(:|$)/.test(v.split(':')[0] + ':')).split(':').slice(0, 2).join(':')}`, fix: 'Mount only the specific folders the service needs, read-only (:ro) where possible.' });
    }
    if (svc.privileged === true) api.addFinding({ id: 'compose.privileged', severity: 'high', category: 'host-exposure', agents: AG, title: `Container "${name}" runs privileged`, detail: 'privileged: true turns off most container isolation.', file, line, evidence: `${name}: privileged: true`, fix: 'Drop privileged and add only the capabilities it needs.' });
    if (svc.network_mode === 'host') api.addFinding({ id: 'compose.hostNet', severity: 'medium', category: 'host-exposure', agents: AG, title: `Container "${name}" uses the host network`, detail: 'With network_mode: host every port it opens is opened on the server itself, and it can reach services bound to localhost.', file, line, evidence: `${name}: network_mode: host`, fix: 'Use a normal bridge network and publish only the ports you need on 127.0.0.1.' });
    const caps = [].concat(svc.cap_add || []).map(String);
    if (caps.some((c) => /^(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)$/i.test(c))) api.addFinding({ id: 'compose.caps', severity: 'medium', category: 'host-exposure', agents: AG, title: `Container "${name}" adds powerful kernel capabilities`, detail: `cap_add: ${caps.join(', ')}`, file, line, evidence: `${name}: cap_add`, fix: 'Remove capabilities the service does not strictly need.' });
    for (const p of [].concat(svc.ports || [])) {
      let host = '', published = '', target = '';
      if (typeof p === 'object' && p) { host = p.host_ip || ''; published = String(p.published ?? ''); target = String(p.target ?? ''); }
      else {
        const parts = String(p).replace(/\/(tcp|udp)$/, '').split(':');
        if (parts.length === 1) { target = parts[0]; published = ''; }
        else if (parts.length === 2) { [published, target] = parts; }
        else { host = parts.slice(0, -2).join(':'); [published, target] = parts.slice(-2); }
      }
      if (!published || /^(127\.|localhost|::1|\[::1\])/.test(host)) continue;
      const port = Number(published.split('-')[0]);
      const tport = Number(target.split('-')[0]);
      if ([80, 443].includes(port)) continue;
      const known = AGENT_PORTS[port] || AGENT_PORTS[tport] || (/n8n|ollama|jupyter|openclaw|flowise|langflow|dify|litellm|qdrant|redis|postgres|mongo/i.test(image) ? image.split(':')[0] : '');
      api.addFinding({ id: 'compose.publicPort', severity: known ? 'high' : 'medium', category: 'host-exposure', agents: AG, title: `Container "${name}" publishes port ${published} on every network interface${known ? ` (${known})` : ''}`, detail: 'A port published without a host IP (or with 0.0.0.0) is reachable from the internet unless a firewall blocks it. Docker-published ports bypass ufw by default.', file, line, evidence: `${name}: ${host ? host + ':' : ''}${published}->${target}`, fix: `Publish it as "127.0.0.1:${published}:${target}" and put an authenticated reverse proxy in front if it must be reachable.` });
    }
    // literal secrets in environment
    let env = svc.environment;
    if (Array.isArray(env)) env = Object.fromEntries(env.map((x) => String(x)).filter((x) => x.includes('=')).map((x) => [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)]));
    if (env && typeof env === 'object') {
      const lit = Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === 'string' && !/^\$\{?[A-Za-z_]/.test(v)));
      if (Object.keys(lit).length) secretsFromKV({ environment: lit }, text, file, perms(file), `in compose service "${name}"`);
    }
    for (const ef of [].concat(svc.env_file || [])) {
      const rel = typeof ef === 'string' ? ef : ef?.path;
      if (rel) scanEnvFile(nodePath.resolve(nodePath.dirname(file), rel));
    }
  }
}

function inventory(data, file, api) {
  walkObj(data, (k, v, path) => {
    if (TOOL_KEY.test(k) && Array.isArray(v)) {
      const names = v.map((x) => (typeof x === 'string' ? x : x && typeof x === 'object' ? x.name || x.id || x.operation : null)).filter((x) => typeof x === 'string' && x.length < 120);
      if (names.length < 2) return;
      const write = names.filter((n) => WRITE_VERB.test(n.split(/[.:/]/).pop() || n) || WRITE_VERB.test(n));
      api.inventory.tools.push({ file: api.show(file), key: [...path, k].join('.'), total: names.length, write });
    }
    if (MODEL_KEY.test(k)) {
      for (const m of [].concat(v)) if (typeof m === 'string' && /^[\w.-]+\/[\w.:-]+$|^(gpt|claude|gemini|llama|mistral|qwen|deepseek|grok|o\d)[\w.:-]*$/i.test(m) && m.length < 100) api.inventory.models.add(m);
    }
  });
}
