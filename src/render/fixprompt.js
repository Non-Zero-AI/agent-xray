import { AGENTS } from '../agents.js';
import { verifyCommand } from '../fixes.js';

const agentNames = (r, f) => f.agents.map((a) => r.agents.find((x) => x.id === a)?.name || AGENTS[a]?.name || a).join(', ');

/** The fix-all prompt in pieces, so the HTML report can rebuild it from only the findings not yet fixed. */
export function fixPromptParts(r) {
  const P = [];
  P.push(`You are helping me harden the AI coding agents on my ${r.mode === 'server' ? 'server' : 'machine'}. A read-only scanner (Agent X-ray) found the issues below. Secret values are redacted on purpose.`);
  P.push('');
  P.push('Ground rules:');
  P.push('1. NEVER print, echo, log or paste any secret value you see while fixing. Refer to keys by name only.');
  P.push('2. Before editing any file, back it up (copy to <file>.bak) and show me the exact diff. Wait for my OK.');
  P.push('3. Plaintext keys: move each one to an environment variable or the OS keychain, replace it with a reference (Cursor/VS Code: ${env:NAME}; Claude/Gemini/Codex: forward the env var), and tell me which keys to ROTATE — treat them as leaked. Never ask me to paste a key into this chat.');
  P.push('4. YOLO / auto-approve settings: switch to the safer default, but tell me what will start prompting again.');
  P.push('5. MCP servers: do not delete servers I use. Pin package versions (look up the current version), narrow filesystem roots to specific project folders, switch http:// to https://, and remove entries whose binaries are missing only after asking me.');
  P.push('6. If a fix needs a decision only I can make, ask instead of guessing.');
  if (r.mode === 'server') P.push('7. This is a live server. Never restart services, change the firewall, or edit authorized_keys / sshd without showing me the exact change and getting my OK first. Never lock me out of SSH.');
  const item = (f) => {
    const L = [`[${f.severity.toUpperCase()}] ${f.title}`];
    L.push(`   Agent(s): ${agentNames(r, f)}`);
    if (f.file) L.push(`   File: ${f.file}${f.line ? ':' + f.line : ''}`);
    if (f.evidence) L.push(`   Evidence (redacted): ${f.evidence}`);
    if (f.fix) L.push(`   Suggested fix: ${f.fix}`);
    if (f.fixer === 'both') L.push('   Note: I rotate/revoke the credential myself; you only change the config to read it from a safe place.');
    return L.join('\n');
  };
  const items = r.findings.map((f) => (f.severity === 'info' ? null : item(f)));
  const humanItem = (f) => `- [${f.severity.toUpperCase()}] ${f.title}${f.file ? ` (${f.file}${f.line ? ':' + f.line : ''})` : ''}`;
  const humanItems = r.findings.map((f) => (f.severity !== 'info' && f.fixer === 'human' ? humanItem(f) : null));
  const F = [`When you are done, run \`${verifyCommand(r).replace(/ --html$/, '')}\` again and show me the new grade.`];
  if (r.sample) F.push('', '(SAMPLE: generated from Agent X-ray demo data, not a real machine.)');
  return { preamble: P.join('\n'), items, humanItems, footer: F.join('\n') };
}

/** Assemble the prompt from parts. include(i) decides which findings (by index) are still open. */
export function assembleFixPrompt(parts, include = () => true) {
  const idx = parts.items.map((_, i) => i).filter((i) => include(i));
  const forAgent = idx.filter((i) => parts.items[i] && !parts.humanItems[i]);
  const forMe = idx.filter((i) => parts.humanItems[i]);
  const L = [parts.preamble, ''];
  if (!forAgent.length && !forMe.length) L.push('Findings: none left to fix. Just double-check nothing above applies, then stop.');
  if (forAgent.length) {
    L.push(`Findings (${forAgent.length}, most severe first):`);
    forAgent.forEach((i, n) => L.push(`${n + 1}. ${parts.items[i]}`));
  }
  if (forMe.length) {
    L.push('', 'Leave these to me (they need my accounts or console access). Do not attempt them, but remind me at the end:');
    forMe.forEach((i) => L.push(parts.humanItems[i]));
  }
  L.push('', parts.footer);
  return L.join('\n');
}

export function renderFixPrompt(r) { return assembleFixPrompt(fixPromptParts(r)); }
