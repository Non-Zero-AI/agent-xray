import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJsonc } from '../src/parse/jsonc.js';
import { parseToml } from '../src/parse/toml.js';
import { parseYaml } from '../src/parse/yaml.js';

test('jsonc: comments, trailing commas, BOM, strings containing //', () => {
  const r = parseJsonc('\uFEFF{\n // c\n "url": "https://x.dev/a", /* b */ "a": [1,2,],\n}');
  assert.deepEqual(r, { url: 'https://x.dev/a', a: [1, 2] });
  assert.deepEqual(parseJsonc(''), {});
});

test('toml: Codex config shapes', () => {
  const t = parseToml(`
model = "gpt-5"   # comment
approval_policy = 'never'
[sandbox_workspace_write]
writable_roots = [
  "/tmp", # c
  "~/code",
]
network_access = true
[mcp_servers.my-server]
command = "npx"
args = ["-y", "pkg@1.0.0"]
env = { API_KEY = "abc", "X.Y" = 1 }
[mcp_servers."quoted.name"]
url = """https://x"""
[profiles.yolo]
sandbox_mode = "danger-full-access"
[[arr]]
a = 1
[[arr]]
a = 2
`);
  assert.equal(t.approval_policy, 'never');
  assert.deepEqual(t.sandbox_workspace_write.writable_roots, ['/tmp', '~/code']);
  assert.equal(t.sandbox_workspace_write.network_access, true);
  assert.deepEqual(t.mcp_servers['my-server'].args, ['-y', 'pkg@1.0.0']);
  assert.equal(t.mcp_servers['my-server'].env.API_KEY, 'abc');
  assert.equal(t.mcp_servers['quoted.name'].url, 'https://x');
  assert.equal(t.profiles.yolo.sandbox_mode, 'danger-full-access');
  assert.deepEqual(t.arr, [{ a: 1 }, { a: 2 }]);
});

test('yaml: Continue list + Goose map shapes', () => {
  const c = parseYaml(`name: x
mcpServers:
  - name: fs
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
    env: { TOKEN: abc }
`);
  assert.equal(c.mcpServers[0].name, 'fs');
  assert.deepEqual(c.mcpServers[0].args, ['-y', '@modelcontextprotocol/server-filesystem']);
  assert.equal(c.mcpServers[0].env.TOKEN, 'abc');
  const g = parseYaml(`GOOSE_MODE: auto  # yolo
extensions:
  github:
    enabled: true
    type: stdio
    cmd: npx
    args: [-y, "@modelcontextprotocol/server-github"]
`);
  assert.equal(g.GOOSE_MODE, 'auto');
  assert.equal(g.extensions.github.enabled, true);
  assert.deepEqual(g.extensions.github.args, ['-y', '@modelcontextprotocol/server-github']);
});
