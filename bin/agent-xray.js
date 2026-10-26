#!/usr/bin/env node
import { main } from '../src/cli.js';

const [major] = process.versions.node.split('.').map(Number);
if (major < 18) {
  console.error('agent-xray needs Node.js 18 or newer.');
  process.exit(2);
}
main().then((code) => { process.exitCode = code; }, (err) => {
  console.error('agent-xray crashed:', err && err.message ? err.message : err);
  process.exitCode = 2;
});
