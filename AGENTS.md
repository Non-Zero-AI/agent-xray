# AGENTS.md — notes for coding agents working on this repo

Agent X-ray is a read-only, offline CLI that audits AI coding agents' config files. Node ≥ 18, ESM, **zero dependencies**.

## Map

- `bin/agent-xray.js`: entry point (version check → `src/cli.js`).
- `src/cli.js`: argument parsing, output selection, exit codes (0 ok, 1 below `--min-grade`, 2 bad args).
- `src/agents.js`: **where each agent's config lives** (per OS). Every path must be cited in `docs/CONFIG-SOURCES.md`.
- `src/scan.js`: reads files and runs `HANDLERS[kind]` per file. `analyzeServers` holds the shared MCP checks, and it also builds the inventory, `--deep` env scan and counts.
- `src/rules.js`: allow-rule risk, package pinning, broad roots, URL safety.
- `src/secrets.js`: secret patterns, key-name heuristics, placeholder detection, `redact()`.
- `src/harness.js`: hooks, statusLine, apiKeyHelper, plugins, skills/rules/subagents, per-harness handlers
  (Copilot CLI, OpenCode, OpenClaw, Aider, Qwen), instruction-file scan (hidden Unicode, injection, planted files) and IOC hits.
- `src/autorun.js`: `COMMAND_FLAGS` risk patterns for auto-run commands.
- `src/iocs.json` + `src/iocs.js`: the bundled, dated, cited IOC list and its matchers. Update `updated` and `sources` when you edit it.
- `src/instructions.js`: hidden-Unicode detection (`⟦NAME⟧` visible form), injection and remote-script patterns.
- `src/lock.js`: `lock` / `verify` (hashes only, never values). `src/badge.js`: badge URL and SVG.
- `action.yml`, `examples/agent-xray-workflow.yml`: the GitHub Action (runs the bundled CLI with node).
- `src/grade.js`: scoring. Keep it in sync with `GRADING.md`.
- `src/parse/`: tolerant JSONC, TOML subset and YAML subset parsers (with line lookup).
- `src/fixes.js`: **who fixes each finding** (`fixer`: agent / human / both), the per-finding `agent_prompt`,
  `human_steps` and official `docs` links. Add a `RULES` entry when you add a finding id. Only add doc URLs you have checked.
- `src/render/`: terminal, SVG card, PNG via headless Chromium, fix prompt, and `html.js` (the interactive report:
  one self-contained file with a strict CSP, data embedded via `safeJson`, DOM built with `textContent` only.
  `CLIENT_GRADE` mirrors `grade.js` and a test keeps them equal).
- `src/demo.js`: builds a fake home in a tmp dir for `demo` and tests. Fake secrets are assembled at runtime.
- `schema/report.schema.json`: the `--json` contract (`schemaVersion` 1).

## Invariants (tests enforce these)

1. Never write outside the `--card`, `--html` and `--badge` paths and the lockfile (`lock` only). Never make network calls, and the HTML report must not load anything external.
2. Never output a raw secret value or its tail. Use `redact()`. That covers the HTML report and agent prompts too.
3. Never output the user's home path or username. Use `tildify()`.
4. Never read shell history, browser profiles, keychains or agent auth files (`auth.json`, `oauth_creds.json`, `.credentials.json`).
5. Config content is untrusted. In the HTML, never use `innerHTML` with report data, and keep hrefs `https://` only.
6. Never execute anything a scan finds: hooks, statusLine/apiKeyHelper commands, MCP servers, plugins, packages. Only read them.
7. Never read `~/.copilot/config.json` (auth). The lockfile stores hashes and names, never env/header values.
8. Infected (`category: "infected"`) findings are `fixer: "human"` only, are excluded from fix prompts, and their steps
   say to remove persistence **before** rotating tokens. Never add an auto-fix for them.
9. No runtime dependencies. Don't commit secret-shaped literals (build them like `src/demo.js` does).

## Commands

```bash
npm test
node bin/agent-xray.js demo [--json|--fix-prompt|--card out.png|--html out.html [--open]]
node bin/agent-xray.js --from-json report.json --html out.html
```

## If you are running the X-ray for a user

Follow [SKILL.md](SKILL.md): generate and open the HTML report (`--html --open`), summarize by `fixer`, and only apply
`agent` / `both` fixes the user has approved, one finding at a time, backup first, never printing secrets.
