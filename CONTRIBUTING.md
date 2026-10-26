# Contributing

Thanks! The most valuable contributions are **new agents**, **new checks**, and **corrections to config paths**.

Ground rules: zero runtime dependencies, Node 18+, read-only, offline, never print a secret value, and
**every config path and key must cite official docs** (or be clearly marked community/observed) in
`docs/CONFIG-SOURCES.md`.

## Adding an agent

1. **Find the source.** Link the official docs that name the config file location(s) per OS and the
   relevant keys (MCP servers, approval/permission settings). If the docs don't cover it, say so.
2. **Register it** in `src/agents.js`:
   - add `{ id: { name } }` to `AGENTS`;
   - add user-level paths in `locations()` with `add(agentId, path, kind, format)`; use the `appData`/`xdg`
     helpers so macOS, Windows and Linux all work; add project-level paths under `if (ctx.project)`;
   - add its config directory to `presenceDirs()` so a clean install still gets graded.
3. **Parse it.** If the file uses the standard `{ "mcpServers": {...} }` shape, use kind `mcp-standard` and you're done.
   Otherwise add a handler to `HANDLERS` in `src/scan.js`. Turn its servers into the common shape
   `{ name, command, args, env, url, headers, ... }` and call `analyzeServers(...)`. Then add `addFinding(...)` for its
   approval and permission keys, using `L('key')` for line numbers.
4. **Test it.** Add a fixture test in `test/agents.test.js` using `fixtureHome({ 'relative/path': content })`.
   Cover a risky config and a clean one. If paths differ on Windows, add a `platform: 'win32'` case.
   Use `FAKE.*` from `src/demo.js` for secrets. Never commit real-looking secret literals.
5. **Document it.** Add a row to `docs/CONFIG-SOURCES.md` and the README table.

## Adding a check

- Choose the severity using `GRADING.md`. If you're unsure, go one lower.
- Each finding needs: `id`, `severity`, `category` (from `schema/report.schema.json`), `agents`, `title` (plain
  English, under 70 chars), `detail` (why it matters), `file`, `line`, `fix` (one concrete action).
- Evidence must be redacted (`redact()` in `src/secrets.js`).

## Running

```bash
npm test             # node --test
node bin/agent-xray.js demo
node bin/agent-xray.js demo --card /tmp/card.png
```
