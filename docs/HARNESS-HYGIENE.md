# Harness Hygiene (v0.3)

A short, checkable standard for the files that steer an AI coding agent: settings, hooks, MCP server
definitions, skills, rules, subagents, plugins and instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`,
`.cursorrules`, …). `agent-xray` measures it. The badge shows the result.

[![Harness Hygiene: A](https://img.shields.io/badge/harness%20hygiene-A-brightgreen)](docs/HARNESS-HYGIENE.md)

## What the grade means

| Grade | Meaning |
|---|---|
| **A** (≥ 90) | No critical or high findings. Nothing runs unasked, no plaintext keys, every auto-run entry is boring. |
| **B** (≥ 80) | A few medium items: an unpinned server, a broad-but-documented allow rule, a project hook that runs a script. |
| **C** (≥ 65) | Several mediums or one or two highs. Fix soon. |
| **D** (50–64) | At least one critical finding (the grade is capped at 64): something can run without you knowing. |
| **F** (< 50) | Two or more criticals (capped at 49), or **any infection indicator** (capped at 20). |

The full rubric is in [GRADING.md](../GRADING.md). A badge reading `F (IOC found)` means a known-malware indicator
matched. Treat it as an incident, not a style problem.

## The seven rules

1. **Nothing auto-runs that you haven't read.** Every hook, `statusLine`, `apiKeyHelper`, folder-open task,
   plugin and startup command is listed by `agent-xray`. None of them may pipe a download into a shell, `eval`
   remote code, decode base64 and run it, write to shell startup files, send env vars or key files over the network,
   or run scripts from dot-folders, temp or Downloads.
2. **No YOLO by default.** Bypass or auto-approve modes are off at user scope. Allow rules name specific
   commands (`Bash(git status)`), not interpreters (`Bash(node:*)`) or wildcards.
3. **No plaintext secrets** in agent configs, MCP definitions or instruction files. Use env vars or the OS keychain.
4. **Pinned, known servers.** MCP servers and plugins name an exact version and come from a source you trust.
   `npx -y pkg` and `:latest` are drift you didn't choose.
5. **Clean instruction files.** No hidden Unicode (tag characters, bidi overrides, zero-width), no "ignore previous
   instructions / don't tell the user" text, no "run this curl | bash" setup steps, and no stray `AGENTS.md` /
   `CLAUDE.md` in `~/Downloads`, your home root or temp folders, where an agent may pick them up.
6. **Locked and reviewed.** The repo commits `agent-xray.lock`, and CI runs `agent-xray --ci`. Any new or changed
   harness file, hook or server fails the build until a human reviews it and re-locks.
7. **Infected means stop.** If an indicator of compromise matches, remove the persistence service first, then
   rotate tokens. Rotating first can trigger a destructive wipe (CSA advisory on Mini Shai-Hulud). Tools never
   auto-fix this.

## Badge

- Static (shields.io): `npx agent-xray --json | jq -r .badge.markdown` prints the Markdown for your current grade.
  agent-xray itself never contacts shields.io. The image loads when someone views your README.
- Local SVG, no third party: `npx agent-xray --badge docs/harness-hygiene.svg`, then commit it and reference it from
  the README. The badge carries the grade only: no paths, counts or names.

A badge is a snapshot of the files on disk when it was made. It doesn't prove the setup is secure, and it can't see
what an agent or server does at runtime.
