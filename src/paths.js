import path from 'node:path';

/** Replace the home dir (and any /Users/<name>, /home/<name>, C:\Users\<name>) with ~ so output never leaks a username. */
export function tildify(p, home) {
  if (typeof p !== 'string') return p;
  let s = p;
  if (home) {
    const variants = [home, home.replace(/\\/g, '/'), home.replace(/\//g, '\\')];
    for (const h of variants) {
      if (!h || h === '/' ) continue;
      const lower = s.toLowerCase();
      const idx = lower.indexOf(h.toLowerCase());
      if (idx >= 0) s = s.slice(0, idx) + '~' + s.slice(idx + h.length);
    }
  }
  s = s.replace(/(^|[\s"'=:(])\/(?:Users|home)\/[^\/\s"']+/g, '$1~');
  s = s.replace(/(^|[\s"'=(])[A-Za-z]:[\\\/](?:Users|Documents and Settings)[\\\/][^\\\/\s"']+/gi, '$1~');
  return s;
}

export function isAbs(p) {
  return path.posix.isAbsolute(p) || path.win32.isAbsolute(p) && /^[A-Za-z]:[\\\/]|^\\\\/.test(p);
}
