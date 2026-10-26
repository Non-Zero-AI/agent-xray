// Grading rubric — keep in sync with GRADING.md.
export const RISK_POINTS = { critical: 35, high: 15, medium: 7, low: 2, info: 0 };
export const BANDS = [['A', 90], ['B', 80], ['C', 65], ['D', 50], ['F', 0]];
const DECAY = 120;
export const INFECTED_CAP = 20; // any confirmed IOC (critical, category infected) -> overall F, max 20

export function letter(score) { return BANDS.find(([, min]) => score >= min)[0]; }

/** Per agent: score = 100 · e^(−points/120), then capped: 1 critical → max 64 (D), 2+ criticals → max 49 (F). */
export function scoreFindings(findings) {
  const points = findings.reduce((n, f) => n + (RISK_POINTS[f.severity] ?? 0), 0);
  let score = Math.round(100 * Math.exp(-points / DECAY));
  const crit = findings.filter((f) => f.severity === 'critical').length;
  if (crit >= 2) score = Math.min(score, 49);
  else if (crit === 1) score = Math.min(score, 64);
  return score;
}

/** Overall = 0.6·worst + 0.4·mean of graded agents, then: 1 critical anywhere → max 64, 2+ → max 49, any infected indicator → max 20. */
export function grade(report) {
  const graded = [];
  for (const a of report.agents) {
    const fs = report.findings.filter((f) => f.agents.includes(a.id));
    a.score = scoreFindings(fs);
    a.grade = letter(a.score);
    a.findings = Object.fromEntries(['critical', 'high', 'medium', 'low'].map((s) => [s, fs.filter((f) => f.severity === s).length]));
    if (a.id !== 'shared' || fs.some((f) => f.severity !== 'info')) graded.push(a.score);
  }
  if (!graded.length) {
    report.overall = { grade: null, score: null, summary: 'No AI coding agents found on this machine.' };
    return report;
  }
  const min = Math.min(...graded);
  const mean = graded.reduce((x, y) => x + y, 0) / graded.length;
  let score = Math.round(0.6 * min + 0.4 * mean);
  const crit = report.findings.filter((f) => f.severity === 'critical').length;
  if (crit >= 2) score = Math.min(score, 49);
  else if (crit === 1) score = Math.min(score, 64);
  if (report.findings.some((f) => f.category === 'infected' && f.severity === 'critical')) score = Math.min(score, INFECTED_CAP);
  report.overall = { grade: letter(score), score, summary: headline(report) };
  return report;
}

export function headline(r) {
  const c = r.counts;
  const parts = [`${c.mcpServers} MCP server${c.mcpServers === 1 ? '' : 's'}`, `${c.plaintextSecrets} plaintext key${c.plaintextSecrets === 1 ? '' : 's'}`, `${c.yoloAgents} agent${c.yoloAgents === 1 ? '' : 's'} in YOLO mode`];
  if (r.mode === 'server') parts[2] = `${c.hostExposure} host exposure${c.hostExposure === 1 ? '' : 's'}`;
  if (c.riskyAutorun) parts.push(`${c.riskyAutorun} risky auto-run`);
  if (c.lockDrift) parts.push(`${c.lockDrift} lock change${c.lockDrift === 1 ? '' : 's'}`);
  if (c.iocMatches) parts.unshift(`${c.iocMatches} infection indicator${c.iocMatches === 1 ? '' : 's'}`);
  return parts.join(' · ');
}
