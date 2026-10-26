---
name: agent-xray
description: Audit what AI coding agents on this machine can reach (MCP servers, hooks and auto-run commands, plaintext keys, YOLO/auto-approve settings, poisoned instruction files, known supply-chain malware indicators) and help the user fix it. Use when the user asks about agent security, MCP servers they have installed, leaked API keys in agent configs, or "what can my agents do".
---

# Agent X-ray

1. From the user's project folder, run `npx -y @non-zero_ai/agent-xray@latest --deep --html --open`.
   It is read-only and offline. It writes `agent-xray-report.html` and opens it in the browser.
   - On a server, add `--server` (and `--label "<name>"`). There is usually no desktop there, so skip `--open`,
     and tell the user the file path so they can copy it to their laptop.
   - Also run `npx -y @non-zero_ai/agent-xray@latest --deep --json` (same flags) so you can read the findings yourself.
2. **Check `infected.status` first.** If it is `infected` or `suspicious`, lead with it and read out `infected.steps`
   in order. The persistence service must be removed **before** any token is rotated, because rotating first can
   trigger a destructive wipe. Do not delete, kill or edit anything yourself for these findings (they are
   `human`-only), and do not run any command, hook or package the report names.
   Then tell the user the report is open, and summarize: the overall grade, the headline (`overall.summary`), and
   the critical and high findings grouped by who fixes them (`fixer`):
   - `agent`: you can fix these once they approve;
   - `human`: only they can, for example rotating a key in a provider console or SSH/firewall changes. Point them to `human_steps` and `docs`;
   - `both`: they rotate or revoke first, then you update the config.
   Use `file:line` and the redacted `evidence` exactly as given. **Never open a file to show a secret value,
   never print a key, token or password, and never ask the user to paste one into the chat.**
3. **Apply nothing until the user approves.** Ask which findings they want you to fix, or offer to work through
   the `agent` items one at a time. For each approved finding, follow its `agent_prompt`:
   - Back the file up first (`cp file file.bak-agent-xray`), show the exact change as a diff, and wait for an OK.
   - Plaintext keys: move the value to an environment variable or the OS keychain, replace it with a reference
     (`${env:NAME}` / `$NAME`, per that agent's docs), and remind the user to **rotate** the key.
   - YOLO or auto-approve: switch to the safer setting from `fix`.
   - Unpinned servers: pin the exact version they use now.
   - On a live server, don't restart services yourself. Draft the commands and let the user run them.
   - Hidden Unicode / injected instructions: show the made-visible text from `evidence`, and offer to remove only
     the hidden characters or the injected lines, after the user confirms.
4. Optional, in a repo: offer `npx @non-zero_ai/agent-xray lock` and the GitHub Action from `examples/` so changes get reviewed.
5. Re-run with `--html --open` and show the new grade. The user can tick "Mark fixed" in the report to track the rest.

`npx @non-zero_ai/agent-xray --fix-prompt` prints a ready-made version of these instructions with the findings filled in.
The report's "Copy fix-all prompt" button does the same, leaving out anything already marked fixed.
