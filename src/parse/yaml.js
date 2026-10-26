// Minimal YAML subset parser for agent configs (Continue config.yaml, Goose config.yaml).
// Supports block maps, block sequences (incl. "- key: value" items), flow [a, b] / {a: b},
// quoted/plain scalars, booleans/null/numbers, comments, | / > block scalars, and anchors (&a),
// aliases (*a) and merge keys (<<: *a / <<: [*a, *b]) so shared server blocks are not missed.
function stripComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { if (i === 0 || /[\s:\[{,-]/.test(line[i - 1])) q = c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

function splitFlow(inner) {
  const parts = [];
  let depth = 0, q = null, cur = '';
  for (const c of inner) {
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === '[' || c === '{') depth++;
    if (c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim());
}

export function scalar(v) {
  v = v.trim();
  if (v === '' || v === '~' || v === 'null') return null;
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
    try { return JSON.parse(v); } catch { return v.slice(1, -1); }
  }
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) return v.slice(1, -1).replace(/''/g, "'");
  if (v.startsWith('[') && v.endsWith(']')) return splitFlow(v.slice(1, -1)).map(scalar);
  if (v.startsWith('{') && v.endsWith('}')) {
    const o = {};
    for (const p of splitFlow(v.slice(1, -1))) {
      const k = p.indexOf(':');
      if (k > 0) o[scalar(p.slice(0, k))] = scalar(p.slice(k + 1));
    }
    return o;
  }
  if (/^(true|yes|on)$/i.test(v)) return true;
  if (/^(false|no|off)$/i.test(v)) return false;
  if (/^[+-]?\d+(\.\d+)?$/.test(v)) return Number(v);
  return v;
}

function keySplit(content) {
  // returns [key, rest] if content is "key: rest" or "key:"
  let q = null;
  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    if (q) { if (c === q) q = null; continue; }
    if ((c === '"' || c === "'") && i === 0) { q = c; continue; }
    if (c === ':' && (i + 1 === content.length || content[i + 1] === ' ' || content[i + 1] === '\t')) {
      return [scalar(content.slice(0, i)), content.slice(i + 1).trim()];
    }
    if (c === '[' || c === '{') return null;
  }
  return null;
}

export function parseYaml(text) {
  const raw = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  const lines = [];
  for (let n = 0; n < raw.length; n++) {
    const l = raw[n];
    if (/^\s*(---|\.\.\.)\s*$/.test(l)) continue;
    lines.push({ indent: l.match(/^ */)[0].length, text: l, n });
  }
  let pos = 0;
  const anchors = Object.create(null);
  const clone = (v) => (v && typeof v === 'object' ? JSON.parse(JSON.stringify(v)) : v);
  const significant = (l) => stripComment(l.text).trim() !== '';
  const skip = () => { while (pos < lines.length && !significant(lines[pos])) pos++; };

  function blockScalar(indicator, parentIndent) {
    const out = [];
    let ind = null;
    while (pos < lines.length) {
      const l = lines[pos];
      if (l.text.trim() === '') { out.push(''); pos++; continue; }
      if (l.indent <= parentIndent) break;
      if (ind === null) ind = l.indent;
      out.push(l.text.slice(ind));
      pos++;
    }
    while (out.length && out[out.length - 1] === '') out.pop();
    return indicator.startsWith('>') ? out.join(' ') + '\n' : out.join('\n') + '\n';
  }

  function value(rest, indent) {
    const am = /^&([^\s\[\]{},]+)(?:\s+(.*))?$/.exec(rest);
    if (am) { const v = value((am[2] || '').trim(), indent); anchors[am[1]] = v; return v; }
    const al = /^\*([^\s\[\]{},]+)$/.exec(rest);
    if (al && al[1] in anchors) return clone(anchors[al[1]]);
    const als = /^\[\s*(\*[^\]]+)\]$/.exec(rest);
    if (als) { const names = als[1].split(',').map((x) => x.trim().replace(/^\*/, '')); if (names.every((n) => n in anchors)) return names.map((n) => clone(anchors[n])); }
    if (rest === '') {
      skip();
      if (pos >= lines.length) return null;
      const l = lines[pos];
      const t = stripComment(l.text).trim();
      if (l.indent > indent || (l.indent === indent && t.startsWith('- ')) || (l.indent === indent && t === '-')) return block(l.indent);
      return null;
    }
    if (/^[|>][+-]?$/.test(rest)) return blockScalar(rest, indent);
    return scalar(rest);
  }

  function block(indent) {
    skip();
    if (pos >= lines.length) return null;
    const first = stripComment(lines[pos].text).trim();
    if (first.startsWith('- ') || first === '-') {
      const arr = [];
      while (pos < lines.length) {
        skip();
        if (pos >= lines.length) break;
        const l = lines[pos];
        const t = stripComment(l.text).trim();
        if (l.indent !== indent || !(t.startsWith('- ') || t === '-')) break;
        const item = t === '-' ? '' : t.slice(2).trim();
        const kv = item ? keySplit(item) : null;
        if (kv) {
          // rewrite as a map line indented to the item's content
          const childIndent = indent + (stripComment(l.text).slice(indent).match(/^-\s+/)[0].length);
          lines[pos] = { indent: childIndent, text: ' '.repeat(childIndent) + item, n: l.n };
          arr.push(block(childIndent));
        } else {
          pos++;
          arr.push(value(item, indent));
        }
      }
      return arr;
    }
    const obj = {};
    const merges = [];
    while (pos < lines.length) {
      skip();
      if (pos >= lines.length) break;
      const l = lines[pos];
      if (l.indent !== indent) { if (l.indent < indent) break; pos++; continue; }
      const t = stripComment(l.text).trim();
      if (t.startsWith('- ')) break;
      const kv = keySplit(t);
      pos++;
      if (!kv) continue;
      const v = value(kv[1], indent);
      if (kv[0] === '<<' && v && typeof v === 'object') merges.push(...(Array.isArray(v) ? v : [v]));
      else obj[kv[0]] = v;
    }
    for (const m of merges) if (m && typeof m === 'object' && !Array.isArray(m)) for (const k of Object.keys(m)) if (!(k in obj)) obj[k] = m[k];
    return obj;
  }
  skip();
  if (pos >= lines.length) return {};
  return block(lines[pos].indent);
}
