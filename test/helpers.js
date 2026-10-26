import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';

/** Create a throwaway fixture home: files = { 'rel/path': string|object }. Never touches the real home. */
export function fixtureHome(files = {}, { bins = ['npx', 'node', 'uvx', 'docker'] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-test-'));
  const home = path.join(root, 'home', 'tester');
  fs.mkdirSync(home, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(home, ...rel.split('/'));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  }
  const bin = path.join(home, '.bin');
  fs.mkdirSync(bin, { recursive: true });
  for (const b of bins) { fs.writeFileSync(path.join(bin, b), '#!/bin/sh\n'); fs.chmodSync(path.join(bin, b), 0o755); }
  const env = { HOME: home, PATH: bin };
  return {
    root, home, env,
    scan: (opts = {}) => scan({ home, env, platform: 'linux', project: null, now: '2026-01-01T00:00:00.000Z', tmpDirs: [path.join(root, 'tmp')], sysRoot: path.join(root, 'sys'), ...opts }),
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

export const byId = (r, id) => r.findings.filter((f) => f.id === id);
export const agent = (r, id) => r.agents.find((a) => a.id === id);
