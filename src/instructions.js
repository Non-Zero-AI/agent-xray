// Instruction-file checks (AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, rules, skills, subagents):
// hidden Unicode (made visible), prompt-injection phrasing, remote-script instructions, and
// instruction files planted where agents pick them up by accident (~/Downloads, home root, tmp).
import { commandFlags } from './autorun.js';
import { scanText, redact } from './secrets.js';

const BIDI = { 0x202a: 'LRE', 0x202b: 'RLE', 0x202c: 'PDF', 0x202d: 'LRO', 0x202e: 'RLO', 0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI', 0x200e: 'LRM', 0x200f: 'RLM', 0x061c: 'ALM' };
const ZW = { 0x200b: 'ZWSP', 0x200c: 'ZWNJ', 0x200d: 'ZWJ', 0x2060: 'WJ', 0x2061: 'U+2061', 0x2062: 'U+2062', 0x2063: 'U+2063', 0x2064: 'U+2064', 0xfeff: 'BOM', 0x180e: 'MVS', 0x00ad: 'SHY' };
const isTag = (cp) => cp >= 0xe0000 && cp <= 0xe007f;
const isVS = (cp) => cp >= 0xe0100 && cp <= 0xe01ef; // variation selectors supplement (used for "invisible ink" payloads)
const PICTO = /\p{Extended_Pictographic}|\p{Emoji_Modifier}|\uFE0F/u;

const safeText = (s) => { let t = s; for (const h of scanText(t)) t = t.split(h.value).join(redact(h.value)); return t; };

/**
 * Find invisible / direction-changing characters.
 * Returns { tags, bidi, zeroWidth, variation, lines:[{line, visible}], decoded } — decoded = text hidden in Unicode tag chars.
 */
export function hiddenUnicode(text) {
  const res = { tags: 0, bidi: 0, zeroWidth: 0, variation: 0, lines: [], decoded: [] };
  if (typeof text !== 'string') return res;
  const lines = text.split(/\r?\n/);
  lines.forEach((ln, i) => {
    let hit = false, visible = '', tagRun = '';
    const cps = [...ln];
    const flushTag = () => { if (tagRun) { visible += `⟦TAG:"${tagRun}"⟧`; res.decoded.push(tagRun); tagRun = ''; } };
    cps.forEach((ch, j) => {
      const cp = ch.codePointAt(0);
      if (isTag(cp)) { hit = true; res.tags++; if (cp >= 0xe0020 && cp <= 0xe007e) tagRun += String.fromCodePoint(cp - 0xe0000); return; }
      flushTag();
      if (BIDI[cp]) { hit = true; res.bidi++; visible += `⟦${BIDI[cp]}⟧`; return; }
      if (ZW[cp] !== undefined) {
        if (cp === 0xfeff && i === 0 && j === 0) return; // BOM at start of file is normal
        if (cp === 0x200d && (PICTO.test(cps[j - 1] || '') || PICTO.test(cps[j + 1] || ''))) { visible += ch; return; } // emoji ZWJ sequence
        if (cp === 0x00ad) { visible += ch; return; } // soft hyphen: harmless, not counted
        hit = true; res.zeroWidth++; visible += `⟦${ZW[cp]}⟧`; return;
      }
      if (isVS(cp)) { hit = true; res.variation++; visible += `⟦VS${cp - 0xe0100 + 17}⟧`; return; }
      visible += ch;
    });
    flushTag();
    if (hit) res.lines.push({ line: i + 1, visible: safeText(visible).slice(0, 220) });
  });
  res.decoded = res.decoded.map(safeText);
  return res;
}

export const INJECTION_PATTERNS = [
  ['conceal', 'high', 'tells the agent to hide what it does from you', /\b(?:do\s+not|don'?t|never)\s+(?:mention|tell|show|display|reveal|inform|report|disclose|output|print)\b[^.\n]{0,60}\b(?:user|human|developer|operator|anyone)\b/i],
  ['ignore-previous', 'high', 'tries to override earlier / system instructions', /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+(?:instructions|prompts?|rules|directions|messages)/i],
  ['override-safety', 'high', 'tries to switch off safety rules', /\b(?:override|bypass|disable|turn\s+off)\s+(?:your|the|all|any)\s+(?:system|safety|security|permission|approval)\s+(?:prompt|instructions|rules|guidelines|checks|prompts)/i],
  ['silent-exec', 'high', 'asks the agent to run or install something silently', /\b(?:silently|quietly|secretly|covertly|in\s+the\s+background|without\s+(?:asking|telling|confirmation|confirming|notifying|prompting))\b[^.\n]{0,80}\b(?:run|execute|install|download|send|upload|curl|wget|post|exec)\b|\b(?:run|execute|install|download|send|upload)\b[^.\n]{0,80}\b(?:silently|quietly|secretly|without\s+(?:asking|telling|confirmation|notifying|prompting)(?:\s+the\s+user)?)\b/i],
  ['exfil-ask', 'high', 'asks the agent to send keys, env vars or files somewhere', /\b(?:send|upload|post|exfiltrate|forward|copy)\b[^.\n]{0,50}\b(?:\.ssh|id_rsa|id_ed25519|\.env\b|api[\s_-]?keys?|credentials|secrets|tokens?|private\s+keys?|wallet|seed\s+phrase|environment\s+variables)\b[^.\n]{0,60}\b(?:to\s+(?:https?:|\S+\.\w{2,})|https?:\/\/|webhook)/i],
  ['background-task', 'medium', 'declares a hidden "background task" to run on session start', /\bbackground\s+task\s*:?\s*(?:run|execute)\b|\bon\s+(?:every\s+)?session\s+start\b[^.\n]{0,40}\b(?:run|execute)\b/i],
  ['tool-poison-tag', 'medium', 'uses <IMPORTANT>/<system> style tags often seen in tool-poisoning payloads', /<\s*(?:IMPORTANT|SYSTEM|system_prompt|admin)\s*>/],
  ['refusal-bait', 'medium', 'contains text meant to make AI security scanners refuse to read the file', /\b(?:if\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|assistant)|ai\s+(?:scanners?|reviewers?|analy[sz]ers?))\b[^.\n]{0,80}\b(?:stop|refuse|do\s+not\s+(?:analy[sz]e|read|continue|report)|report\s+(?:this\s+file\s+as\s+)?(?:safe|clean|benign))\b/i],
];

/** Prompt-injection phrasing. Returns [{id, severity, label, line, snippet}] (one per pattern). */
export function injectionHits(text) {
  const out = [];
  if (typeof text !== 'string') return out;
  const flat = text.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069]|[\u{E0000}-\u{E007F}]/gu, '');
  for (const [id, severity, label, re] of INJECTION_PATTERNS) {
    const m = re.exec(flat);
    if (!m) continue;
    const line = flat.slice(0, m.index).split('\n').length;
    out.push({ id, severity, label, line, snippet: safeText(m[0]).slice(0, 120) });
  }
  return out;
}

/** Lines that tell the agent to run a remote script / exfil command. Returns [{line, flags, snippet}]. */
export function remoteScriptHits(text) {
  const out = [];
  if (typeof text !== 'string') return out;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length && out.length < 5; i++) {
    const l = lines[i];
    if (!/curl|wget|iwr|irm|invoke-|base64|\/dev\/tcp|nc\s|eval|bash\s+-i/i.test(l)) continue;
    const flags = commandFlags(l).filter((f) => ['pipe-to-shell', 'eval-remote', 'base64-exec', 'reverse-shell', 'exfil'].includes(f.id));
    if (flags.length) out.push({ line: i + 1, flags, snippet: safeText(l.trim()).slice(0, 140) });
  }
  return out;
}

/** Cursor .mdc / skill frontmatter: { alwaysApply, globsAll, raw } */
export function frontmatter(text) {
  const m = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---/.exec(text || '');
  if (!m) return null;
  const fm = m[1];
  return { raw: fm, alwaysApply: /^\s*alwaysApply\s*:\s*true\b/mi.test(fm), globsAll: /^\s*globs\s*:.*(?:\*\*\/\*|"\*\*"|'\*\*'|\s\*\s*$)/mi.test(fm), hasHooks: /^\s*hooks\s*:/m.test(fm) };
}

export const INSTRUCTION_NAMES = ['AGENTS.md', 'CLAUDE.md', 'CLAUDE.local.md', 'GEMINI.md', 'QWEN.md', '.cursorrules', '.windsurfrules', '.clinerules', '.goosehints', 'copilot-instructions.md', 'SKILL.md'];
