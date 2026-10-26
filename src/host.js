// --server: read-only checks of a Linux host that runs agents (VPS, homelab, CI box).
// Reads systemd units, /proc/net listeners, sshd config, authorized_keys comments, ufw state,
// the Docker socket and well-known CLI credential stores. Never writes, never runs commands.
import fs from 'node:fs';
import nodePath from 'node:path';
import { readSafe, perms, parseEnv, AGENT_PORTS } from './stack.js';

const AG = ['host'];
const AGENT_KEY_RE = /(agent|bot|claude|codex|cursor|copilot|gpt|llm|openclaw|n8n|automation|deploy|ci[-_@]|github-actions|runner|worker|box\b|@box|devin|aider|goose|cline|robot)/i;
const SAFE_PORTS = new Set([22, 80, 443]);

export function sysPath(ctx, p) { return ctx.sysRoot && ctx.sysRoot !== '/' ? nodePath.join(ctx.sysRoot, p) : p; }
function ls(p) { try { return fs.readdirSync(p, { withFileTypes: true }); } catch { return []; } }

/** Home directories on the host (root + /home/*). */
export function hostHomes(ctx) {
  const homes = new Set([ctx.home]);
  const root = sysPath(ctx, '/root');
  try { if (fs.statSync(root).isDirectory()) homes.add(root); } catch { /* not readable */ }
  for (const e of ls(sysPath(ctx, '/home'))) if (e.isDirectory()) homes.add(nodePath.join(sysPath(ctx, '/home'), e.name));
  return [...homes];
}

// ---------- systemd ----------
export function parseUnit(text) {
  const out = {};
  let sec = '';
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith(';')) continue;
    const s = /^\[(.+)\]$/.exec(l);
    if (s) { sec = s[1]; continue; }
    const m = /^([A-Za-z]+)\s*=\s*(.*)$/.exec(l);
    if (!m) continue;
    const k = `${sec}.${m[1]}`;
    (out[k] ||= []).push(m[2]);
  }
  return out;
}

const HARDENING = ['NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'CapabilityBoundingSet', 'PrivateTmp', 'ReadOnlyPaths', 'InaccessiblePaths', 'DynamicUser', 'SystemCallFilter'];

function systemd(ctx, api) {
  const dir = sysPath(ctx, '/etc/systemd/system');
  const ents = ls(dir);
  const enabled = new Set();
  for (const e of ents) if (e.isDirectory() && /\.(wants|requires)$/.test(e.name)) for (const w of ls(nodePath.join(dir, e.name))) enabled.add(w.name.replace(/@[^.]*\./, '@.'));
  let custom = 0, sandboxed = 0;
  const envFiles = [];
  for (const e of ents) {
    if (!e.isFile() || !/\.service$/.test(e.name)) continue;
    const file = nodePath.join(dir, e.name);
    const text = readSafe(file, 256 * 1024);
    if (text === null) continue;
    const u = parseUnit(text);
    if (!u['Service.ExecStart']) continue;
    custom++;
    const user = (u['Service.User'] || []).at(-1) || (u['Service.DynamicUser'] || []).at(-1) === 'yes' && 'dynamic' || 'root';
    const isRoot = user === 'root' || user === '0';
    const hard = HARDENING.filter((h) => (u[`Service.${h}`] || []).some((v) => v && !/^(no|false|0)$/i.test(v)));
    const isEnabled = enabled.has(e.name) || enabled.has(e.name.replace(/@[^.]*\./, '@.'));
    if (!isRoot || hard.length >= 2) sandboxed++;
    const exec = (u['Service.ExecStart'] || []).join(' ');
    const efs = (u['Service.EnvironmentFile'] || []).map((v) => v.replace(/^-/, '').trim()).filter(Boolean);
    envFiles.push(...efs.map((p) => sysPath(ctx, p)));
    // literal secrets in Environment=
    const envText = (u['Service.Environment'] || []).join('\n');
    if (envText) {
      const kv = {};
      for (const m of envText.matchAll(/"?([A-Za-z_][A-Za-z0-9_]*)=([^"\s]*)"?/g)) kv[m[1]] = m[2];
      api.secretsInKV(kv, text, file, 'in a systemd unit Environment=');
    }
    if (isRoot && hard.length < 2) {
      const loadsSecrets = efs.length > 0;
      api.addFinding({
        id: 'host.rootService', severity: isEnabled ? (loadsSecrets ? 'high' : 'medium') : 'low', category: 'host-exposure', agents: AG,
        title: `${isEnabled ? 'Service' : 'Disabled service'} ${e.name} runs as root with no sandboxing${loadsSecrets ? ' and loads a secrets file' : ''}`,
        detail: `${isEnabled ? 'If anything it runs (an agent, a worker, a dependency) is compromised, it owns the whole server.' : 'It is not enabled today, but one `systemctl start` gives it full root.'}${loadsSecrets ? ` It reads ${efs.length} EnvironmentFile(s) into a root process.` : ''} Hardening found: ${hard.length ? hard.join(', ') : 'none'}.`,
        file, evidence: `User=${user}${exec ? ' · ' + exec.split(/\s+/)[0].split('/').pop() : ''}`,
        fix: isEnabled ? 'Run it as a dedicated user (User=, or DynamicUser=yes) and add NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes.' : 'Delete the unit if it is retired, or harden it before it is ever started again.',
      });
    }
  }
  if (custom) api.strengths.push(`${sandboxed} of ${custom} custom systemd services run sandboxed (non-root or hardened)`);
  return envFiles;
}

// ---------- listeners ----------
export function parseProcNet(text, v6) {
  const out = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== '0A') continue; // LISTEN
    const [addr, portHex] = f[1].split(':');
    const port = parseInt(portHex, 16);
    const any = /^0+$/.test(addr);
    const loop = v6 ? /^0{24}0100007F$|^0{31}1$/i.test(addr) || addr === '00000000000000000000000001000000' : addr.endsWith('7F');
    out.push({ port, any, loopback: loop, inode: f[9], v6 });
  }
  return out;
}

function inodeOwners(ctx, wanted) {
  const map = new Map();
  if (!wanted.size) return map;
  for (const p of ls(sysPath(ctx, '/proc'))) {
    if (!/^\d+$/.test(p.name)) continue;
    const fdDir = sysPath(ctx, `/proc/${p.name}/fd`);
    let fds;
    try { fds = fs.readdirSync(fdDir); } catch { continue; }
    for (const fd of fds) {
      let l;
      try { l = fs.readlinkSync(nodePath.join(fdDir, fd)); } catch { continue; }
      const m = /^socket:\[(\d+)\]$/.exec(l);
      if (m && wanted.has(m[1]) && !map.has(m[1])) map.set(m[1], (readSafe(sysPath(ctx, `/proc/${p.name}/comm`), 4096) || '?').trim());
    }
  }
  return map;
}

function firewall(ctx) {
  const conf = readSafe(sysPath(ctx, '/etc/ufw/ufw.conf'), 65536) || '';
  const on = /^\s*ENABLED\s*=\s*yes/m.test(conf);
  const def = readSafe(sysPath(ctx, '/etc/default/ufw'), 65536) || '';
  const denyIn = /^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(DROP|REJECT)/m.test(def);
  const rules = (readSafe(sysPath(ctx, '/etc/ufw/user.rules'), 1024 * 1024) || '') + '\n' + (readSafe(sysPath(ctx, '/etc/ufw/user6.rules'), 1024 * 1024) || '');
  const allowed = new Set();
  for (const m of rules.matchAll(/^### tuple ### allow (?:tcp|any) (\d+(?::\d+)?|[\w,]+) /gm)) for (const part of m[1].split(',')) { if (/^\d+$/.test(part)) allowed.add(Number(part)); else if (/^\d+:\d+$/.test(part)) { const [a, b] = part.split(':').map(Number); for (let i = a; i <= b && i - a < 10000; i++) allowed.add(i); } }
  for (const m of rules.matchAll(/^### tuple ### allow \w+ any 0\.0\.0\.0\/0 any (\S+)/gm)) void m; // per-source rules: ignored
  return { on: on && denyIn, enabled: on, allowed };
}

function listeners(ctx, api) {
  const all = [...parseProcNet(readSafe(sysPath(ctx, '/proc/net/tcp')) || '', false), ...parseProcNet(readSafe(sysPath(ctx, '/proc/net/tcp6')) || '', true)];
  if (!all.length) return;
  const fw = firewall(ctx);
  const open = new Map();
  for (const l of all) if (l.any && !open.has(l.port)) open.set(l.port, l);
  const owners = inodeOwners(ctx, new Set([...open.values()].map((l) => l.inode)));
  let local = 0;
  for (const l of all) if (!l.any) local++;
  const other = [];
  for (const [port, l] of open) {
    if (SAFE_PORTS.has(port)) continue;
    const what = AGENT_PORTS[port];
    const proc = owners.get(l.inode);
    const blocked = fw.on && !fw.allowed.has(port);
    if (!what && !blocked) { other.push(`${port}${proc ? ` ${proc}` : ''}`); continue; }
    const sev = port === 2375 && !blocked ? 'critical' : blocked ? 'low' : 'high';
    api.addFinding({
      id: 'host.publicListener', severity: sev, category: 'host-exposure', agents: AG,
      title: `Port ${port}${what ? ` (${what})` : ''} listens on all network interfaces${blocked ? ' (firewall blocks it today)' : ''}`,
      detail: blocked ? 'The firewall blocks it now, but a single ufw/iptables change, or a Docker-published port, would expose it. Bind it to 127.0.0.1 so it never depends on the firewall.' : 'Anything that can reach this server can try this port. Admin UIs, agent gateways and model servers often have weak or no authentication. (A cloud-provider firewall, if any, is not visible from inside the box.)',
      evidence: `0.0.0.0:${port}${proc ? ` · ${proc}` : ''}`,
      fix: `Bind the service to 127.0.0.1 and reach it through an authenticated reverse proxy or an SSH tunnel${fw.enabled ? '' : '; also turn on a default-deny firewall'}.`,
    });
  }
  if (other.length) api.addFinding({
    id: 'host.publicListeners', severity: 'medium', category: 'host-exposure', agents: AG,
    title: `${other.length} other port${other.length === 1 ? '' : 's'} listen on all network interfaces`,
    detail: `Ports: ${other.slice(0, 15).join(', ')}${other.length > 15 ? ', …' : ''}. Each one is reachable from outside unless a firewall (here or at the cloud provider) blocks it.`,
    evidence: `${other.length} public listener(s)`,
    fix: 'Bind internal services to 127.0.0.1; expose only what must be public, behind authentication.',
  });
  const publicOther = [...open.keys()].filter((p) => !SAFE_PORTS.has(p));
  if (!publicOther.length) api.strengths.push(`No services listen publicly except ${[...open.keys()].filter((p) => SAFE_PORTS.has(p)).sort((a, b) => a - b).join(', ') || 'none'} (${local} bound to localhost)`);
  if (fw.on) api.strengths.push(`Firewall on with default-deny inbound (allows ${[...fw.allowed].sort((a, b) => a - b).slice(0, 8).join(', ') || 'nothing'})`);
  else if (!fw.enabled) api.addFinding({ id: 'host.noFirewall', severity: publicOther.length ? 'medium' : 'low', category: 'host-exposure', agents: AG, title: 'No host firewall detected (ufw is off or not installed)', detail: 'Without a default-deny firewall, any service that binds to 0.0.0.0 by mistake is public immediately. (iptables/nftables rules set up by other tools are not checked.)', fix: 'Enable ufw with default deny incoming and allow only 22/80/443, or confirm your cloud firewall does the same.' });
}

// ---------- docker ----------
function docker(ctx, api) {
  const sock = sysPath(ctx, '/var/run/docker.sock');
  let st;
  try { st = fs.lstatSync(sock); } catch { st = null; }
  if (!st) { try { st = fs.lstatSync(sysPath(ctx, '/run/docker.sock')); } catch { st = null; } }
  if (!st) return;
  const groups = readSafe(sysPath(ctx, '/etc/group'), 1024 * 1024) || '';
  const m = /^docker:[^:]*:\d+:(.*)$/m.exec(groups);
  const members = m && m[1].trim() ? m[1].trim().split(',').filter(Boolean) : [];
  const world = (st.mode & 0o002) !== 0;
  if (world) api.addFinding({ id: 'host.dockerSockWorld', severity: 'critical', category: 'host-exposure', agents: AG, title: 'The Docker socket is writable by every user', detail: 'Anyone (or any agent) on the box can start a privileged container and become root.', evidence: `docker.sock mode ${(st.mode & 0o777).toString(8)}`, fix: 'chmod 660 the socket (root:docker) and keep the docker group empty or minimal.' });
  if (members.length) api.addFinding({ id: 'host.dockerGroup', severity: 'medium', category: 'host-exposure', agents: AG, title: `${members.length} user${members.length === 1 ? ' is' : 's are'} in the docker group (root-equivalent)`, detail: 'Membership in the docker group is the same as passwordless root. Agents running as these users can take over the host.', evidence: `${members.length} member(s)`, fix: 'Remove users that do not need Docker, or use rootless Docker for agent workloads.' });
}

// ---------- ssh ----------
function sshdConfig(ctx) {
  const main = readSafe(sysPath(ctx, '/etc/ssh/sshd_config'), 1024 * 1024) || '';
  const inc = ls(sysPath(ctx, '/etc/ssh/sshd_config.d')).filter((e) => e.name.endsWith('.conf')).map((e) => e.name).sort().map((n) => readSafe(sysPath(ctx, `/etc/ssh/sshd_config.d/${n}`), 1024 * 1024) || '');
  const ordered = /^\s*Include\s+\/etc\/ssh\/sshd_config\.d/m.test(main) ? [...inc, main] : [main, ...inc];
  const cfg = {};
  for (const t of ordered) for (const raw of t.split('\n')) {
    const l = raw.trim();
    if (/^match\s/i.test(l)) break; // Match blocks: stop (first-match semantics for globals only)
    const m = /^([A-Za-z]+)\s+(.+)$/.exec(l);
    if (m && !l.startsWith('#')) { const k = m[1].toLowerCase(); if (!(k in cfg)) cfg[k] = m[2].trim().toLowerCase(); }
  }
  return { found: !!main, cfg };
}

export function parseAuthorizedKeys(text) {
  const keys = [];
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#')) continue;
    const m = /(?:^|\s)(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+([A-Za-z0-9+\/=]+)(?:\s+(.*))?$/.exec(l);
    if (!m) continue;
    const opts = l.slice(0, m.index).trim();
    keys.push({ type: m[1], comment: (m[3] || '').trim(), restricted: /(^|,)\s*(command=|from=|restrict)/.test(opts) });
  }
  return keys;
}

function ssh(ctx, api) {
  const { found, cfg } = sshdConfig(ctx);
  const rootLogin = cfg.permitrootlogin || 'prohibit-password';
  const pw = cfg.passwordauthentication || 'yes';
  const kbd = cfg.kbdinteractiveauthentication || cfg.challengeresponseauthentication || 'no';
  if (found) {
    if (rootLogin === 'yes' && (pw === 'yes' || kbd === 'yes')) api.addFinding({ id: 'host.sshRootPassword', severity: 'high', category: 'host-exposure', agents: AG, title: 'Root can log in over SSH with a password', detail: 'PermitRootLogin yes plus password authentication invites brute-force attacks against the most powerful account.', evidence: `PermitRootLogin ${rootLogin} · PasswordAuthentication ${pw}`, fix: 'Set PermitRootLogin prohibit-password (or no) and PasswordAuthentication no.' });
    else if (pw === 'yes') api.addFinding({ id: 'host.sshPassword', severity: 'medium', category: 'host-exposure', agents: AG, title: 'SSH accepts password logins', detail: 'Password logins can be brute-forced; keys cannot.', evidence: `PasswordAuthentication ${pw}`, fix: 'Set PasswordAuthentication no after confirming key login works.' });
    else api.strengths.push(`SSH: password login off, root ${rootLogin === 'no' ? 'login disabled' : 'key-only'}`);
  }
  const jail = [readSafe(sysPath(ctx, '/etc/fail2ban/jail.local'), 1 << 20) || '', ...ls(sysPath(ctx, '/etc/fail2ban/jail.d')).map((e) => readSafe(sysPath(ctx, `/etc/fail2ban/jail.d/${e.name}`), 1 << 20) || '')].join('\n');
  if (/\[sshd\][^\[]*enabled\s*=\s*true/i.test(jail)) api.strengths.push('fail2ban guards SSH');

  const rootCanLogin = rootLogin !== 'no';
  for (const home of hostHomes(ctx)) {
    const f = nodePath.join(home, '.ssh', 'authorized_keys');
    const text = readSafe(f, 1 << 20);
    if (text === null) continue;
    const isRoot = home === sysPath(ctx, '/root');
    const keys = parseAuthorizedKeys(text).filter((k) => !k.restricted);
    if (!keys.length) continue;
    const agentKeys = keys.filter((k) => k.comment && AGENT_KEY_RE.test(k.comment));
    const unlabeled = keys.filter((k) => !k.comment);
    const who = isRoot ? 'root' : 'this user';
    if (isRoot && rootCanLogin && agentKeys.length) api.addFinding({
      id: 'host.agentRootSsh', severity: 'medium', category: 'host-exposure', agents: AG,
      title: `${agentKeys.length} automated agent key${agentKeys.length === 1 ? ' has' : 's have'} full root SSH`,
      detail: `${keys.length} unrestricted keys can log in as root; ${agentKeys.length} of them are labeled like bots/agents (${agentKeys.map((k) => k.comment).join(', ')}). Whoever controls any one of those agents controls the whole server, with no audit trail of which one acted.`,
      file: f, evidence: `${keys.length} root keys · ${agentKeys.length} agent keys`,
      fix: 'Give each agent its own non-root user with only the sudo rules it needs, or restrict its key with command="…",from="…" options. Remove keys for agents you no longer run.',
    });
    if (unlabeled.length) api.addFinding({
      id: 'host.unlabeledKey', severity: isRoot ? 'low' : 'info', category: 'host-exposure', agents: AG,
      title: `${unlabeled.length} ${who} SSH key${unlabeled.length === 1 ? ' has' : 's have'} no label`,
      detail: 'A key without a comment cannot be traced to a person or agent, so you cannot tell if it is still needed or whose laptop it lives on.',
      file: f, evidence: `${unlabeled.length} unlabeled of ${keys.length}`, fix: 'Identify the owner (compare fingerprints with ssh-keygen -lf), add a comment, or remove it.',
    });
  }
}

// ---------- CLI credential stores in each home ----------
const STORES = [
  { rel: '.config/gh/hosts.yml', label: 'GitHub CLI login token', re: /oauth_token:\s*([^\s#]+)/g },
  { rel: '.config/op/config', label: '1Password Secret Key', re: /"accountKey"\s*:\s*"([^"]+)"/g },
  { rel: '.git-credentials', label: 'git credential', re: /:\/\/[^:\s]+:([^@\s]+)@/g, base: 'high' },
  { rel: '.netrc', label: '.netrc password', re: /\bpassword\s+(\S+)/g, base: 'high' },
  { rel: '.npmrc', label: 'npm auth token', re: /_authToken\s*=\s*(\S+)/g },
  { rel: '.docker/config.json', label: 'Docker registry login', re: /"auth"\s*:\s*"([^"]{8,})"/g },
  { rel: '.aws/credentials', label: 'AWS secret key', re: /aws_secret_access_key\s*=\s*(\S+)/g, base: 'high' },
  { rel: '.cache/huggingface/token', label: 'Hugging Face token', re: /^\s*(\S{20,})\s*$/g },
  { rel: '.config/gcloud/application_default_credentials.json', label: 'Google Cloud credential', re: /"(?:refresh_token|private_key)"\s*:\s*"([^"]{8,})"/g, base: 'high' },
  { rel: '.kube/config', label: 'Kubernetes credential', re: /(?:token|client-key-data):\s*(\S{16,})/g, base: 'high' },
];

function credentialStores(ctx, api) {
  for (const home of hostHomes(ctx)) for (const s of STORES) {
    const f = nodePath.join(home, ...s.rel.split('/'));
    const text = readSafe(f, 1 << 20);
    if (text === null) continue;
    const pm = perms(f);
    api.markScanned(f);
    s.re.lastIndex = 0;
    for (const m of text.matchAll(s.re)) {
      const value = m[1];
      if (!value || /^\$|^<|^(true|false|null)$/i.test(value)) continue;
      api.addSecret({ kind: 'cli-store', label: s.label, value, line: text.slice(0, m.index).split('\n').length }, f, AG, 'host', 'in a CLI credential store', {
        severity: pm?.world ? 'critical' : pm?.group ? 'high' : s.base || 'medium',
        title: `${s.label} stored in plain text`,
        detail: `This CLI keeps its credential unencrypted on disk${pm ? ` (mode ${pm.mode})` : ''}. Every agent, script or MCP server running as this user can read and reuse it.${pm?.world ? ' It is readable by every user on the machine.' : ''}`,
        fix: 'Use the OS keyring / credential helper or short-lived tokens; on servers prefer a scoped deploy token and log the CLI out when done.',
      });
    }
  }
}

export function scanHost(ctx, api) {
  const envFiles = systemd(ctx, api);
  listeners(ctx, api);
  docker(ctx, api);
  ssh(ctx, api);
  credentialStores(ctx, api);
  return { envFiles };
}

export { parseEnv };
