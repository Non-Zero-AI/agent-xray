// Harness Hygiene badge: a shields.io static-badge URL (nothing is fetched by agent-xray itself)
// and a self-contained SVG you can commit. Grade only: no paths, counts or names.
export const BADGE_COLORS = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' };
const SHIELDS = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' };

/** { grade, color, url, markdown } for report.badge. */
export function badgeFor(grade, { infected = false } = {}) {
  const g = grade || 'n/a';
  const msg = infected ? `${g} (IOC found)` : g;
  const enc = (s) => encodeURIComponent(s).replace(/-/g, '--').replace(/_/g, '__');
  const url = `https://img.shields.io/badge/${enc('harness hygiene')}-${enc(msg)}-${SHIELDS[grade] || 'lightgrey'}`;
  return { grade: grade || null, color: BADGE_COLORS[grade] || '#64748b', url, markdown: `![Harness Hygiene: ${msg}](${url})` };
}

/** Local flat badge SVG (Verdana-width approximation, like shields). */
export function badgeSvg(grade, { infected = false } = {}) {
  const left = 'harness hygiene';
  const right = (grade || 'n/a') + (infected ? ' · IOC' : '');
  const w = (s) => Math.round(s.length * 6.6 + 12);
  const lw = w(left), rw = Math.max(26, w(right)), W = lw + rw;
  const col = BADGE_COLORS[grade] || '#64748b';
  const esc = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="20" role="img" aria-label="${esc(left)}: ${esc(right)}"><title>${esc(left)}: ${esc(right)}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<clipPath id="r"><rect width="${W}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#0b1222"/><rect x="${lw}" width="${rw}" height="20" fill="${col}"/><rect width="${W}" height="20" fill="url(#s)"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="${lw / 2}" y="14">${esc(left)}</text><text x="${lw + rw / 2}" y="14" font-weight="bold">${esc(right)}</text></g></svg>\n`;
}
