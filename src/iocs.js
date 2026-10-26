// Offline indicator-of-compromise (IOC) matching. The list lives in src/iocs.json (dated, cited, easy
// to edit); `--iocs <file>` merges a newer list with the same shape. Matching is by file presence,
// sha256 of a file, or a text pattern. Nothing found here is ever executed or removed.
import fs from 'node:fs';
import crypto from 'node:crypto';

const BUNDLED = new URL('./iocs.json', import.meta.url);
const LISTS = ['files', 'services', 'commands', 'text', 'packages', 'scopes'];

export function loadIocs(extraPath) {
  const base = JSON.parse(fs.readFileSync(BUNDLED, 'utf8'));
  if (extraPath) {
    const extra = JSON.parse(fs.readFileSync(extraPath, 'utf8'));
    for (const k of LISTS) if (Array.isArray(extra[k])) {
      const ids = new Set(extra[k].map((e) => e.id));
      base[k] = [...(base[k] || []).filter((e) => !ids.has(e.id)), ...extra[k]];
    }
    Object.assign(base.sources, extra.sources || {});
    Object.assign(base.campaigns, extra.campaigns || {});
    if (extra.updated && extra.updated > base.updated) base.updated = extra.updated;
  }
  for (const k of ['commands', 'text']) for (const e of base[k] || []) e._re = new RegExp(e.re, 'i');
  return base;
}

export function iocSummary(iocs) {
  return { updated: iocs.updated, indicators: LISTS.reduce((n, k) => n + (iocs[k] || []).length, 0) };
}

/** Public citation list for one IOC entry: [{label,url}] (https only). */
export function iocDocs(iocs, entry) {
  const ids = [...new Set([...(entry.sources || []), ...(iocs.campaigns[entry.campaign]?.sources || [])])];
  return ids.map((id) => iocs.sources[id]).filter((s) => s && /^https:\/\//.test(s.url)).map((s) => ({ label: s.title, url: s.url }));
}

export function sha256File(p, maxBytes = 32 * 1024 * 1024) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > maxBytes) return null;
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  } catch { return null; }
}

export function commandHits(cmd, iocs) {
  if (typeof cmd !== 'string' || !cmd) return [];
  return (iocs.commands || []).filter((e) => e._re.test(cmd));
}

export function textHits(text, iocs) {
  if (typeof text !== 'string' || !text) return [];
  return (iocs.text || []).filter((e) => e._re.test(text));
}

const splitPkg = (spec) => {
  const s = String(spec || '').trim().replace(/^npm:/, '');
  const at = s.startsWith('@') ? s.indexOf('@', 1) : s.indexOf('@');
  return at > 0 ? { name: s.slice(0, at), version: s.slice(at + 1) } : { name: s, version: '' };
};

/**
 * Check one package reference ("name", "name@1.2.3", "@scope/name@^2").
 * Returns null or { entry, severity, status, name, version, exact }.
 */
export function packageHit(spec, iocs, ecosystem = 'npm', version) {
  const p = splitPkg(spec);
  const name = p.name.toLowerCase();
  const ver = String(version ?? p.version ?? '').replace(/^[=v]/, '');
  const exact = /^\d+\.\d+\.\d+([-+][\w.]+)?$/.test(ver);
  for (const e of iocs.packages || []) {
    if ((e.ecosystem || 'npm') !== ecosystem || e.name.toLowerCase() !== name) continue;
    if (e.status === 'malicious') return e.verified === false // reported but primary source not re-checked: high, never "infected"
      ? { entry: e, severity: 'high', status: 'reported', name: e.name, version: ver, exact }
      : { entry: e, severity: 'critical', status: 'malicious', name: e.name, version: ver, exact };
    if (e.status === 'compromised-versions') {
      if (exact && e.versions.includes(ver)) return { entry: e, severity: 'critical', status: 'compromised', name: e.name, version: ver, exact };
      if (!exact) return { entry: e, severity: 'high', status: 'may-resolve', name: e.name, version: ver, exact };
      return null; // pinned to a known-good version
    }
    if (e.status === 'watch') return exact ? null : { entry: e, severity: 'high', status: 'watch', name: e.name, version: ver, exact };
  }
  if (ecosystem === 'npm' && name.startsWith('@') && !exact) {
    const scope = name.split('/')[0];
    for (const e of iocs.scopes || []) if (e.scopes.includes(scope)) return { entry: e, severity: 'medium', status: 'scope-watch', name: p.name, version: ver, exact };
  }
  return null;
}

/** Package names a shell command or instruction line installs / runs ("npm i -g x", "npx -y x@1", "pip install x==1"). */
export function packagesInCommand(cmd) {
  const out = [];
  if (typeof cmd !== 'string') return out;
  const re = /\b(?:npx|bunx|pnpx|(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|exec|dlx|x)|pnpm\s+dlx|yarn\s+dlx)\b((?:\s+(?:-[-\w]+(?:=\S+)?))*)\s+((?:@[\w.-]+\/)?[\w.-]+(?:@[\w.^~<>=*-]+)?)/gi;
  for (const m of cmd.matchAll(re)) out.push({ ecosystem: 'npm', spec: m[2] });
  const py = /\b(?:pip3?|uv\s+pip|pipx|uvx)\s+(?:install\s+|run\s+)?((?:-[-\w]+\s+)*)([A-Za-z][\w.-]*)(?:==([\w.]+))?/gi;
  for (const m of cmd.matchAll(py)) if (!/^(install|run|-)/i.test(m[2])) out.push({ ecosystem: 'pypi', spec: m[2], version: m[3] || '' });
  return out;
}
