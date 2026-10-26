// Secret detection. Values are NEVER returned to renderers: callers get a redacted
// preview (prefix + "..." + last 4) plus the line number.
export const SECRET_PATTERNS = [
  { id: 'anthropic', label: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_\-]{20,}/g },
  { id: 'openrouter', label: 'OpenRouter API key', re: /\bsk-or-v1-[A-Za-z0-9]{32,}\b/g },
  { id: 'openai', label: 'OpenAI API key', re: /\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}/g },
  { id: 'github', label: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g },
  { id: 'github-pat', label: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
  { id: 'gitlab', label: 'GitLab token', re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g },
  { id: 'slack', label: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9\-]{10,}\b/g },
  { id: 'aws', label: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'google', label: 'Google API key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: 'stripe', label: 'Stripe secret key', re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { id: 'huggingface', label: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { id: 'npm', label: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'sendgrid', label: 'SendGrid key', re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/g },
  { id: 'supabase', label: 'Supabase access token', re: /\bsbp_[a-f0-9]{40}\b/g },
  { id: 'notion', label: 'Notion token', re: /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b/g },
  { id: 'linear', label: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{30,}\b/g },
  { id: '1password', label: '1Password Secret Key', re: /\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{5,6}-){2,4}[A-Z0-9]{5}\b/g },
  { id: 'telegram', label: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b/g },
  { id: 'private-key', label: 'Private key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g },
  { id: 'jwt', label: 'JWT / bearer credential', re: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
  { id: 'bearer', label: 'Bearer token', re: /Bearer\s+([A-Za-z0-9_\-.=~+\/]{20,})/g, group: 1 },
  { id: 'url-password', label: 'password in connection URL', re: /\b[a-z][a-z0-9+.\-]*:\/\/[^\s:@\/"']+:([^\s@\/"']{6,})@/gi, group: 1 },
];

const SECRET_KEY_RE = /(api[_\-]?key|apikey|token|secret|passw(or)?d|passwd|credential|access[_\-]?key|private[_\-]?key|auth|^pat$|_pat$|client[_\-]?secret|dsn|connection[_\-]?string|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|service[_\-]?role|[_\-]key$)/i;
const NOT_SECRET_KEY_RE = /(public|publishable|anon[_\-]|^next_public|path|file|url|uri|host|port|endpoint|dir|region|timeout|model|name|type|user(name)?$|enabled|mode|_env_var$|env_vars?$|tokens?_(limit|count|max)|max_?tokens|method|provider|helper|scheme|strategy|header_?name|_?id$)/i;

export function isPlaceholder(v) {
  if (typeof v !== 'string') return true;
  const s = v.trim();
  if (s.length < 8) return true;
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_:\-]*\}?$/.test(s)) return true; // $VAR ${VAR} ${env:VAR}
  if (/^\$\{(env|input|secret|userHome|workspaceFolder)[:}]/.test(s)) return true;
  if (/^%[A-Za-z_][A-Za-z0-9_]*%$/.test(s)) return true;
  if (/^\{\{.*\}\}$/.test(s)) return true;
  if (/^<.*>$/.test(s)) return true;
  if (/^(your|my|insert|replace|enter|put|add)[\s_\-]/i.test(s)) return true;
  if (/(x{4,}|\*{4,}|placeholder|changeme|redacted|dummy|todo|example\.com)/i.test(s)) return true;
  if (/^(true|false|null|none|undefined)$/i.test(s)) return true;
  if (/^(https?|file):\/\//i.test(s) && !/:\/\/[^\/\s]+:[^@\/\s]+@/.test(s)) return true;
  if (/^[~.\/\\]|^[A-Za-z]:[\\\/]/.test(s)) return true; // paths
  if (/^op:\/\/|^keychain:|^vault:/.test(s)) return true; // secret references
  if (/\s/.test(s)) return true; // sentences, commands
  return false;
}

export function looksLikeSecretKey(key) {
  return SECRET_KEY_RE.test(key) && !NOT_SECRET_KEY_RE.test(key);
}

export function redact(value) {
  if (typeof value !== 'string') return '****';
  if (value.startsWith('-----BEGIN')) return '-----BEGIN PRIVATE KEY----- [redacted]';
  const m = /^(sk-or-v1-|sk-ant-|sk-proj-|sk-svcacct-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|AKIA|ASIA|AIza|sk_live_|sk_test_|rk_live_|hf_|npm_|SG\.|sbp_|ntn_|secret_|lin_api_|A3-|eyJ)/.exec(value);
  if (value.length < 16 && !m) return '****';
  const prefix = m ? m[1] : '';
  return `${prefix}...${value.slice(-4)}`;
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

export function findLine(text, needle) {
  if (!text || !needle) return null;
  const idx = text.indexOf(needle);
  return idx < 0 ? null : lineOf(text, idx);
}

/** Scan raw file text with well-known patterns. Returns [{kind,label,value,line}] (value is internal only). */
export function scanText(text) {
  const hits = [];
  const seen = new Set();
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text))) {
      const value = p.group ? m[p.group] : m[0];
      if (!value || seen.has(value)) continue;
      if (p.id === 'bearer' && isPlaceholder(value)) continue;
      if (p.id === 'url-password' && /^\$|^\{|^%/.test(value)) continue;
      // a bearer/url hit that's already covered by a more specific pattern
      if ([...seen].some((v) => v.includes(value) || value.includes(v))) continue;
      seen.add(value);
      hits.push({ kind: p.id, label: p.label, value, line: lineOf(text, m.index + (p.group ? m[0].indexOf(value) : 0)) });
    }
  }
  return hits;
}

/** Walk a key/value object (env, headers) and flag literal secret-looking values. */
export function scanKeyValues(obj, text, already = new Set()) {
  const hits = [];
  if (!obj || typeof obj !== 'object') return hits;
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v !== 'string' || already.has(v)) continue;
    const covered = [...already].some((s) => v.includes(s));
    if (covered) continue;
    let value = v;
    if (/^authorization$/i.test(k)) {
      const m = /^(?:Bearer|Basic|Token)\s+(.+)$/i.exec(v.trim());
      value = m ? m[1] : v;
      if (isPlaceholder(value)) continue;
    } else if (!looksLikeSecretKey(k) || isPlaceholder(v)) continue;
    already.add(value);
    hits.push({ kind: 'generic', label: `secret in ${k}`, value, line: findLine(text, value), key: k });
  }
  return hits;
}

/** Decode a JWT payload (no verification). Returns the claims object or null. Never logged. */
export function jwtClaims(value) {
  if (typeof value !== 'string' || !/^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$/.test(value.trim())) return null;
  try {
    const b = value.trim().split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const c = JSON.parse(Buffer.from(b + '='.repeat((4 - (b.length % 4)) % 4), 'base64').toString('utf8'));
    return c && typeof c === 'object' ? c : null;
  } catch { return null; }
}

/**
 * Classify a credential that is public by design (Supabase anon / publishable keys) or extra-dangerous
 * (Supabase service_role). Returns { publishable: boolean, label?: string, note?: string }.
 */
export function classifyCredential(value) {
  const c = jwtClaims(value);
  if (c) {
    const role = String(c.role || '');
    if (role === 'anon') return { publishable: true };
    if (role === 'service_role') return { publishable: false, label: 'Supabase service_role key', note: 'This key bypasses Row Level Security: it can read and write every row in every table of the project.' };
  }
  if (/^sb_publishable_/.test(value || '')) return { publishable: true };
  return { publishable: false };
}
