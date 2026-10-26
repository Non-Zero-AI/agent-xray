// JSON-with-comments parser (VS Code, Zed, Cursor permissions.json all allow JSONC).
export function stripJsonc(text) {
  let out = '';
  let i = 0;
  const n = text.length;
  let inStr = false;
  while (i < n) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += text[i + 1] ?? ''; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') out += '\n'; i++; }
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  // trailing commas (outside strings)
  let res = '';
  inStr = false;
  for (let j = 0; j < out.length; j++) {
    const c = out[j];
    if (inStr) {
      res += c;
      if (c === '\\') { res += out[j + 1] ?? ''; j++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; res += c; continue; }
    if (c === ',') {
      let k = j + 1;
      while (k < out.length && /\s/.test(out[k])) k++;
      if (out[k] === '}' || out[k] === ']') continue;
    }
    res += c;
  }
  return res;
}

export function parseJsonc(text) {
  const t = text.replace(/^\uFEFF/, '');
  if (!t.trim()) return {};
  return JSON.parse(stripJsonc(t));
}
