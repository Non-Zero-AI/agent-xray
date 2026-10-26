import { AGENTS } from '../agents.js';

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const GRADE_COLORS = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' };
const FONT = "Inter, 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif";
const MONO = "'JetBrains Mono', 'SF Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace";

/** The six stat tiles shared by the card and the HTML report: [value, label, sub, color]. Counts only. */
export function statTiles(r) {
  const c = r.counts;
  const auto = c.autorunEntries ?? 0, risky = c.riskyAutorun ?? 0, ioc = c.iocMatches ?? 0;
  const reach = (c.unpinnedPackages || 0) + c.broadRoots + c.insecureRemote + (c.hostExposure || 0);
  return [
    [c.mcpServers, 'MCP servers', 'reachable by your agents', c.mcpServers > 0 ? '#38bdf8' : '#64748b'],
    [c.plaintextSecrets, 'plaintext keys', r.mode ? 'in configs, .env & token files' : 'sitting in agent configs', c.plaintextSecrets ? '#ef4444' : '#22c55e'],
    [c.yoloAgents, c.yoloAgents === 1 ? 'agent in YOLO mode' : 'agents in YOLO mode', 'no permission prompts', c.yoloAgents ? '#ef4444' : '#22c55e'],
    [c.dangerousRules + c.autoTrust, 'risky auto-approvals', 'rm, curl, Bash(*), trust…', c.dangerousRules + c.autoTrust ? '#f97316' : '#22c55e'],
    [auto, 'auto-run hooks & tasks', ioc ? `${ioc} infection indicator${ioc === 1 ? '' : 's'}` : `${risky} risky · hooks, status line, tasks`, ioc || risky ? '#ef4444' : auto ? '#38bdf8' : '#22c55e'],
    [reach, 'unpinned & over-broad', r.mode === 'server' ? 'npx latest · root SSH · open ports' : 'npx latest · whole-home FS · http', reach ? '#f97316' : '#22c55e'],
  ];
}

/** Shareable 1200x630 card. Contains ONLY counts, grades and agent names — never paths or secret values. */
export function renderCardSvg(r) {
  const W = 1200, H = 630;
  const g = r.overall.grade || '?';
  const gc = GRADE_COLORS[g] || '#94a3b8';
  const c = r.counts;
  const tiles = statTiles(r);
  const tileW = 236, tileH = 118, gap = 14, tx0 = 448, ty0 = 146;
  const tileSvg = tiles.map(([n, label, sub, col], i) => {
    const x = tx0 + (i % 3) * (tileW + gap), y = ty0 + Math.floor(i / 3) * (tileH + gap);
    return `<g transform="translate(${x},${y})">
      <rect width="${tileW}" height="${tileH}" rx="18" fill="#0f172a" stroke="#1e293b" stroke-width="2"/>
      <rect x="0" y="20" width="5" height="${tileH - 40}" rx="2.5" fill="${col}"/>
      <text x="24" y="58" font-family="${FONT}" font-size="50" font-weight="800" fill="${col}">${esc(n)}</text>
      <text x="24" y="86" font-family="${FONT}" font-size="19" font-weight="700" fill="#e2e8f0">${esc(label)}</text>
      <text x="24" y="106" font-family="${FONT}" font-size="14" fill="#64748b">${esc(sub)}</text>
    </g>`;
  }).join('\n');
  const agents = r.agents.filter((a) => a.id !== 'shared');
  let ax = 448, ay = 442, row = 0;
  const chipParts = [];
  for (let i = 0; i < agents.length; i++) {
    const a = agents[i];
    const name = String(a.name || AGENTS[a.id]?.name || a.id).slice(0, 30);
    const w = Math.round(50 + name.length * 8.3);
    const remaining = agents.length - i - 1;
    if (row === 0 && ax + w > W - 48) { row = 1; ax = 448; ay = 490; }
    if (row === 1 && ax + w + (remaining ? 58 : 0) > W - 48) {
      chipParts.push(`<g transform="translate(${ax},${ay})"><rect width="52" height="40" rx="20" fill="#0f172a" stroke="#1e293b" stroke-width="2"/><text x="26" y="26" text-anchor="middle" font-family="${FONT}" font-size="16" font-weight="700" fill="#94a3b8">+${agents.length - i}</text></g>`);
      break;
    }
    chipParts.push(`<g transform="translate(${ax},${ay})"><rect width="${w}" height="40" rx="20" fill="#0f172a" stroke="#1e293b" stroke-width="2"/>
      <circle cx="20" cy="20" r="13" fill="${GRADE_COLORS[a.grade] || '#64748b'}"/>
      <text x="20" y="25.5" text-anchor="middle" font-family="${FONT}" font-size="15" font-weight="800" fill="#0b1020">${esc(a.grade)}</text>
      <text x="40" y="26" font-family="${FONT}" font-size="15" font-weight="600" fill="#cbd5e1">${esc(name)}</text></g>`);
    ax += w + 8;
  }
  const chips = chipParts.join('\n');
  const headline = g === '?' ? 'No AI agents found' : `My AI agents got ${/^[AEF]/.test(g) ? 'an' : 'a'} ${g}`;
  const ioc = c.iocMatches || 0;
  const bw = r.sample ? 516 : 704;
  const btxt = r.sample ? `INFECTED (${ioc}) · remove persistence first` : `INFECTION INDICATORS FOUND (${ioc}) · remove persistence before rotating`;
  const infected = ioc ? `<g transform="translate(448,26)"><rect width="${bw}" height="48" rx="10" fill="#7f1d1d" stroke="#ef4444" stroke-width="2"/><text x="18" y="31" font-family="${FONT}" font-size="19" font-weight="800" fill="#fecaca"${btxt.length * 11 > bw - 36 ? ` textLength="${bw - 36}" lengthAdjust="spacingAndGlyphs"` : ''}>${btxt}</text></g>` : '';
  const sample = r.sample ? `<g transform="translate(${W - 210},34)"><rect width="176" height="40" rx="10" fill="#a21caf"/><text x="88" y="27" text-anchor="middle" font-family="${FONT}" font-size="18" font-weight="800" fill="#fff" letter-spacing="3">SAMPLE DATA</text></g>` : '';
  // rib-cage "x-ray" motif behind the grade
  const ribs = Array.from({ length: 7 }, (_, i) => `<path d="M ${70} ${170 + i * 44} Q 210 ${140 + i * 44} 350 ${170 + i * 44}" stroke="#38bdf8" stroke-opacity="${0.05 + i * 0.006}" stroke-width="10" fill="none" stroke-linecap="round"/>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <defs>
    <radialGradient id="glow" cx="210" cy="300" r="260" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="${gc}" stop-opacity="0.35"/><stop offset="1" stop-color="${gc}" stop-opacity="0"/></radialGradient>
    <pattern id="scan" width="4" height="4" patternUnits="userSpaceOnUse"><rect width="4" height="1" fill="#ffffff" fill-opacity="0.025"/></pattern>
  </defs>
  <rect width="${W}" height="${H}" fill="#060a16"/>
  <rect width="${W}" height="${H}" fill="url(#scan)"/>
  <circle cx="210" cy="300" r="260" fill="url(#glow)"/>
  ${ribs}
  <rect x="210" y="140" width="10" height="320" rx="5" fill="#38bdf8" fill-opacity="0.06"/>
  <text x="48" y="78" font-family="${FONT}" font-size="30" font-weight="900" fill="#38bdf8" letter-spacing="6">AGENT X-RAY</text>
  <text x="50" y="108" font-family="${FONT}" font-size="17" fill="#64748b">${r.mode === 'server' ? 'What can the AI agents on this server actually reach?' : 'What can the AI agents on this machine actually reach?'}</text>
  ${sample}
  ${infected}
  <circle cx="210" cy="300" r="128" fill="#0b1020" stroke="${gc}" stroke-width="10"/>
  <text x="210" y="352" text-anchor="middle" font-family="${FONT}" font-size="150" font-weight="900" fill="${gc}">${esc(g)}</text>
  <text x="210" y="470" text-anchor="middle" font-family="${FONT}" font-size="30" font-weight="800" fill="#f1f5f9">${esc(headline)}</text>
  <text x="210" y="502" text-anchor="middle" font-family="${FONT}" font-size="17" fill="#94a3b8">${r.overall.score != null ? esc(`${r.overall.score}/100 · ${c.agents} ${r.mode ? 'target' : 'agent'}${c.agents === 1 ? '' : 's'} scanned`) : ''}</text>
  <text x="448" y="132" font-family="${FONT}" font-size="15" font-weight="700" fill="#64748b" letter-spacing="2">WHAT IT FOUND</text>
  ${tileSvg}
  <text x="448" y="428" font-family="${FONT}" font-size="15" font-weight="700" fill="#64748b" letter-spacing="2">GRADE BY AGENT</text>
  ${chips}
  <line x1="48" y1="550" x2="${W - 48}" y2="550" stroke="#1e293b" stroke-width="2"/>
  <rect x="48" y="570" width="400" height="44" rx="10" fill="#0f172a" stroke="#38bdf8" stroke-opacity="0.5"/>
  <text x="66" y="599" font-family="${MONO}" font-size="21" font-weight="700" fill="#38bdf8">$ npx @non-zero_ai/agent-xray</text>
  <text x="470" y="598" font-family="${FONT}" font-size="17" fill="#94a3b8">read-only · offline · every secret redacted</text>
  <text x="${W - 48}" y="598" text-anchor="end" font-family="${FONT}" font-size="17" font-weight="700" fill="#475569">Non-Zero-AI</text>
</svg>
`;
}
