// Minimal TOML parser covering what agent configs use (Codex config.toml):
// tables, dotted/quoted keys, array-of-tables, strings (basic, literal, multi-line),
// numbers, booleans, dates (kept as strings), arrays and inline tables.
export function parseToml(text) {
  const s = text.replace(/^\uFEFF/, '');
  let i = 0;
  const root = {};
  let cur = root;

  const err = (m) => { throw new Error(`TOML: ${m} at offset ${i}`); };
  const ws = () => { while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i++; };
  const wsnl = () => {
    for (;;) {
      while (i < s.length && /[ \t\r\n]/.test(s[i])) i++;
      if (s[i] === '#') { while (i < s.length && s[i] !== '\n') i++; continue; }
      break;
    }
  };
  const ensure = (obj, keys) => {
    let o = obj;
    for (const k of keys) {
      if (o[k] === undefined) o[k] = {};
      else if (Array.isArray(o[k])) { o = o[k][o[k].length - 1]; continue; }
      o = o[k];
    }
    return o;
  };

  function parseKey() {
    const keys = [];
    for (;;) {
      ws();
      if (s[i] === '"' || s[i] === "'") keys.push(parseString());
      else {
        const m = /^[A-Za-z0-9_\-]+/.exec(s.slice(i));
        if (!m) err('bad key');
        keys.push(m[0]);
        i += m[0].length;
      }
      ws();
      if (s[i] === '.') { i++; continue; }
      return keys;
    }
  }

  function parseString() {
    const q = s[i];
    const triple = s.slice(i, i + 3) === q.repeat(3);
    if (triple) {
      i += 3;
      if (s[i] === '\r') i++;
      if (s[i] === '\n') i++;
      const end = s.indexOf(q.repeat(3), i);
      if (end < 0) err('unterminated string');
      let raw = s.slice(i, end);
      i = end + 3;
      while (s[i] === q) { raw += q; i++; }
      return q === '"' ? unescape(raw.replace(/\\\r?\n\s*/g, '')) : raw;
    }
    i++;
    let out = '';
    while (i < s.length && s[i] !== q) {
      if (s[i] === '\n') err('newline in string');
      if (q === '"' && s[i] === '\\') { out += s[i] + s[i + 1]; i += 2; continue; }
      out += s[i++];
    }
    if (s[i] !== q) err('unterminated string');
    i++;
    return q === '"' ? unescape(out) : out;
  }

  function unescape(str) {
    return str.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (_, e) => {
      if (e[0] === 'u' || e[0] === 'U') return String.fromCodePoint(parseInt(e.slice(1), 16));
      return { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '"': '"', '\\': '\\' }[e] ?? e;
    });
  }

  function parseValue() {
    ws();
    const c = s[i];
    if (c === '"' || c === "'") return parseString();
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        wsnl();
        if (s[i] === ']') { i++; return arr; }
        arr.push(parseValue());
        wsnl();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return arr; }
        err('bad array');
      }
    }
    if (c === '{') {
      i++;
      const obj = {};
      ws();
      if (s[i] === '}') { i++; return obj; }
      for (;;) {
        const keys = parseKey();
        if (s[i] !== '=') err('expected =');
        i++;
        const v = parseValue();
        ensure(obj, keys.slice(0, -1))[keys[keys.length - 1]] = v;
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return obj; }
        err('bad inline table');
      }
    }
    const m = /^[^\s,\]\}#]+(?: [0-9:.+\-Z]+)?/.exec(s.slice(i));
    if (!m) err('bad value');
    const tok = m[0];
    i += tok.length;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (/^[+-]?(\d[\d_]*)(\.\d[\d_]*)?([eE][+-]?\d+)?$/.test(tok)) return Number(tok.replace(/_/g, ''));
    if (/^0x[0-9a-fA-F_]+$/.test(tok)) return parseInt(tok.slice(2).replace(/_/g, ''), 16);
    if (/^[+-]?(inf|nan)$/.test(tok)) return tok.includes('nan') ? NaN : (tok.startsWith('-') ? -Infinity : Infinity);
    return tok; // dates/times kept as strings
  }

  for (;;) {
    wsnl();
    if (i >= s.length) break;
    if (s[i] === '[') {
      const arrTable = s[i + 1] === '[';
      i += arrTable ? 2 : 1;
      const keys = parseKey();
      if (arrTable) {
        if (s.slice(i, i + 2) !== ']]') err('expected ]]');
        i += 2;
        const parent = ensure(root, keys.slice(0, -1));
        const k = keys[keys.length - 1];
        if (!Array.isArray(parent[k])) parent[k] = [];
        const o = {};
        parent[k].push(o);
        cur = o;
      } else {
        if (s[i] !== ']') err('expected ]');
        i++;
        cur = ensure(root, keys);
      }
      continue;
    }
    const keys = parseKey();
    if (s[i] !== '=') err('expected =');
    i++;
    const v = parseValue();
    ensure(cur, keys.slice(0, -1))[keys[keys.length - 1]] = v;
    ws();
    if (s[i] === '#') while (i < s.length && s[i] !== '\n') i++;
  }
  return root;
}
