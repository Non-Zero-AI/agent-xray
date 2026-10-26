import { AGENTS } from '../agents.js';

const C = (on) => {
  const w = (a, b) => (s) => (on ? `\x1b[${a}m${s}\x1b[${b}m` : String(s));
  return { bold: w(1, 22), dim: w(2, 22), red: w(31, 39), green: w(32, 39), yellow: w(33, 39), blue: w(34, 39), magenta: w(35, 39), cyan: w(36, 39), gray: w(90, 39), bgRed: w('41;97', '49;39'), bgYellow: w('43;30', '49;39'), bgGreen: w('42;30', '49;39'), bgBlue: w('44;97', '49;39'), bgMagenta: w('45;97', '49;39') };
};

export function gradeColor(g, c) {
  return { A: c.green, B: c.green, C: c.yellow, D: c.yellow, F: c.red }[g] || c.gray;
}

const SEV = (c) => ({ critical: c.bgRed(' CRITICAL '), high: c.red(' HIGH     '), medium: c.yellow(' MEDIUM   '), low: c.gray(' LOW      '), info: c.gray(' INFO     ') });

export function renderTerminal(r, { color = true, verbose = false } = {}) {
  const c = C(color);
  const sev = SEV(c);
  const nameOf = (id) => r.agents.find((a) => a.id === id)?.name || AGENTS[id]?.name || id;
  const out = [];
  const p = (s = '') => out.push(s);
  p();
  p(`  ${c.bold(c.cyan('AGENT X-RAY'))} ${c.gray('v' + r.version)}   ${c.gray('read-only · offline · nothing uploaded · secrets redacted')}`);
  if (r.sample) p(`  ${c.bgMagenta(' SAMPLE ')} ${c.magenta('Demo data from a bundled fake home folder — not your machine.')}`);
  p(c.gray('  ' + '─'.repeat(66)));
  if (!r.overall.grade) {
    p(`  ${r.overall.summary}`);
    p();
    return out.join('\n');
  }
  const gc = gradeColor(r.overall.grade, c);
  p(`  Overall grade  ${c.bold(gc(` ${r.overall.grade} `))}  ${c.gray(`(${r.overall.score}/100)`)}`);
  p(`  ${c.bold(r.overall.summary)}`);
  p();
  const inf = r.infected;
  if (inf) {
    if (inf.status === 'indicators') {
      p(`  ${c.bgRed(' AM I INFECTED? ')} ${c.red(c.bold(`${inf.hits} indicator${inf.hits === 1 ? '' : 's'} of compromise matched`))}${inf.persistence?.length ? c.red(` (${inf.persistence.join('; ')})`) : ''}`);
      p(`   ${c.bold(c.red('Remove the persistence service BEFORE rotating any token.'))} ${c.gray('agent-xray never removes anything itself.')}`);
      (inf.steps || []).forEach((st, i) => p(`   ${c.bold(String(i + 1) + '.')} ${st}`));
    } else {
      p(`  ${c.bold('AM I INFECTED?')} ${c.green('No known indicators')} ${c.gray(`(${inf.indicatorsChecked} offline indicators, IOC list dated ${inf.iocListUpdated})`)}`);
    }
    p();
  }
  if (r.lock) {
    const L = r.lock;
    p(`  ${c.bold('LOCK')} ${L.status === 'ok' ? c.green('matches ' + L.file) : L.status === 'missing' ? c.yellow('no lock file: run `npx @non-zero_ai/agent-xray lock`') : c.red(`${L.changes.length} change${L.changes.length === 1 ? '' : 's'} since ${L.file}`)}`);
    p();
  }
  p(`  ${c.bold('AGENTS')}`);
  for (const a of r.agents) {
    const f = a.findings;
    const bits = [f.critical && c.red(`${f.critical} critical`), f.high && c.red(`${f.high} high`), f.medium && c.yellow(`${f.medium} medium`), f.low && c.gray(`${f.low} low`)].filter(Boolean).join(c.gray(', '));
    p(`   ${c.bold(gradeColor(a.grade, c)(a.grade))}  ${a.name.slice(0, 26).padEnd(26)} ${c.gray(`${String(a.servers).padStart(2)} MCP`)}  ${bits || c.green('no issues')}`);
  }
  p();
  const shown = r.findings.filter((f) => verbose || f.severity !== 'info');
  p(`  ${c.bold(`FINDINGS (${shown.length})`)}`);
  if (!shown.length) p(`   ${c.green('Nothing risky found. Nice.')}`);
  for (const f of shown) {
    p(`  ${sev[f.severity]} ${c.bold(f.title)}`);
    const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
    const who = f.agents.map(nameOf).join(', ');
    p(`             ${c.gray(who)}${loc ? c.gray('  ·  ') + c.cyan(loc) : ''}${f.evidence ? c.gray('  ·  ') + c.yellow(f.evidence) : ''}`);
    if (verbose && f.detail) p(`             ${c.dim(f.detail)}`);
    if (f.fix) p(`             ${c.green('→')} ${c.dim(f.fix)}`);
  }
  p();
  if (r.stack) {
    const st = r.stack;
    p(`  ${c.bold(r.mode === 'server' ? 'SERVER / STACK' : 'STACK')}  ${c.gray(`${st.filesScanned} files walked · ${st.filesOfInterest} of interest${st.skippedLargeDirs ? ` · ${st.skippedLargeDirs} large dirs skipped` : ''}`)}`);
    for (const t of st.tools) p(`   ${c.bold('tools')}   ${t.total} in ${c.cyan(t.file)} ${c.gray(t.key)}${t.write.length ? c.yellow(`  ${t.write.length} write-capable`) : ''}`);
    if (st.backupConfigs) p(c.gray(`   (${st.backupConfigs} backup config cop${st.backupConfigs === 1 ? 'y' : 'ies'} scanned for secrets, not listed)`));
    if (st.models.length) p(`   ${c.bold('models')}  ${st.models.slice(0, 8).join(', ')}${st.models.length > 8 ? c.gray(` +${st.models.length - 8}`) : ''}`);
    if (r.strengths?.length) {
      p(`   ${c.bold('good')}`);
      for (const g of r.strengths) p(`     ${c.green('✓')} ${g}`);
    }
    p();
  }
  const ar = r.autorun || [];
  if (ar.length) {
    const lim = verbose ? ar.length : 15;
    const sorted = [...ar].sort((a, b) => (b.flags.length > 0) - (a.flags.length > 0));
    p(`  ${c.bold(`AUTO-RUN (${ar.length})`)} ${c.gray(`hooks, startup tasks, status line, auto-loaded skills/rules/plugins · listed, never executed${r.counts.riskyAutorun ? '' : ''}`)}`);
    for (const e of sorted.slice(0, lim)) {
      const when = [e.event, e.matcher].filter(Boolean).join(' · ');
      const what = String(e.command || e.url || '').slice(0, 70);
      const fl = e.flags.length ? '  ' + e.flags.map((f) => (f === 'ioc' ? c.bgRed(' ioc ') : c.yellow(f))).join(' ') : '';
      p(`   ${e.flags.length ? c.red('!') : c.gray('·')} ${c.bold(e.kind.padEnd(10))} ${c.gray(when.slice(0, 26).padEnd(26))} ${what ? c.cyan(what) + ' ' : ''}${c.gray(e.file || '')}${fl}`);
    }
    if (ar.length > lim) p(c.gray(`   +${ar.length - lim} more (--verbose or --json)`));
    p();
  }
  p(`  ${c.bold(`MCP SERVERS (${r.servers.length})`)}`);
  for (const s of r.servers) {
    const what = s.url ? s.url : [s.command, s.package && s.package !== s.command ? s.package : null].filter(Boolean).join(' ');
    const flags = [s.pinned === false && c.yellow('unpinned'), s.disabled && c.gray('disabled'), s.envKeys.length && c.gray(`env: ${s.envKeys.join(', ')}`)].filter(Boolean).join(' ');
    p(`   ${c.bold(s.name.padEnd(18))} ${c.gray(s.transport.padEnd(5))} ${what}  ${flags}`);
    p(`   ${' '.repeat(18)} ${c.gray('used by ' + s.agents.map(nameOf).join(', '))}`);
  }
  p();
  p(c.gray('  ' + '─'.repeat(66)));
  const base = r.sample ? 'npx @non-zero_ai/agent-xray demo' : `npx @non-zero_ai/agent-xray${r.mode === 'server' ? ' --server' : ''}`;
  p(`  ${c.bold(c.cyan('Interactive report'))} ${c.cyan(`${base} --html --open`)}   ${c.gray('(who fixes what + copy-paste fix prompts)')}`);
  p(`  ${c.bold('Share your grade')}   ${base} --card xray.png`);
  p(`  ${c.bold('Fix it with AI')}     ${base} --fix-prompt   ${c.gray('(paste into your agent)')}`);
  if (!r.mode) p(`  ${c.bold('Scan .env exposure')} npx @non-zero_ai/agent-xray --deep`);
  if (!r.mode && !r.sample) p(`  ${c.bold('Lock it in CI')}      npx @non-zero_ai/agent-xray lock  ${c.gray('then')}  npx @non-zero_ai/agent-xray --ci`);
  p();
  return out.join('\n');
}
