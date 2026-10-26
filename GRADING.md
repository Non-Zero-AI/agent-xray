# Grading

The rubric lives in `src/grade.js`. Keep the code and this file in sync.

## Severities → risk points

| Severity | Points | Examples |
|---|---|---|
| critical | 35 | Claude `bypassPermissions` (user scope), Codex `never` + `danger-full-access`, Gemini `yolo`, VS Code global auto-approve / `autopilot`, Zed `always_allow_tool_actions`, Goose `auto`, allow-all shell rules (`Bash(*)`, terminal allowlist `*`), `curl … \| sh` server commands |
| high | 15 | plaintext API keys, `Bash(rm:*)` / `curl` / `sudo` allow rules, filesystem servers on `/` or `~`, `http://` remotes, `trust: true`, auto-trusting project MCP servers, Codex `danger-full-access` alone, `.env` not gitignored |
| medium | 7 | `npx`/`python`/`node` with any args auto-approved, `mcp__*` / `*:*` MCP allowlists, write-anywhere rules, unpinned `npx`/`uvx`/`docker :latest` servers, Codex `never` alone, MCP `autoApprove` on write-capable tools, project-scope bypass, disabled bypass warning |
| low | 2 | `acceptEdits` / `autoEdit`, sandbox explicitly disabled, stale servers, conflicting duplicates, read-only autoApprove |
| info | 0 | unparseable config files, write-capable tool inventory (`stack.writeTools`) |

### Auto-run, infection and instruction files (v0.3)

| Severity | Findings |
|---|---|
| critical | any IOC match: `ioc.command` (hook/statusLine payload), `ioc.file` (confirmed by hash), `ioc.service` (persistence unit), `ioc.package` (known-malicious or compromised version), `ioc.text`. Also `autorun.risky` with `curl\|sh`, `eval` of a download, base64-decode-and-run, or a reverse shell. Aider `yes-always`, OpenCode/Qwen YOLO and bash-allow-all |
| high | `autorun.risky` sending secrets/env/key files out, writing shell rc / crontab / login items, hidden or temp scripts, `rm -rf ~`. `unicode.hidden` (tags or bidi, or zero-width text in an instruction file), `instructions.injection`, `instructions.remoteScript`, `instructions.planted` (in Downloads, Desktop or tmp; medium in the home root), `ioc.watch` for a package reported malicious but not confirmed, `ioc.file` matched by name only, Copilot/OpenCode access to `~` or `/` |
| medium | `autorun.risky` for downloads, `npx -y` latest, `sudo`, Downloads scripts, `reads-key-file`, obfuscated blobs, `apiKeyHelper`. `autorun.http` hooks, project-scope auto-run commands, `lock.drift`, `ioc.watch` (unpinned package from a hit scope) |
| low | auto-run entries that only contact a URL or run a loose home-folder script, `statusLine` commands, benign project hooks |
| info | the auto-run inventory itself (`report.autorun[]`), not graded |

### Custom stacks and servers (`--path`, `--server`)

| Severity | Findings |
|---|---|
| critical | any plaintext secret in a world-readable file; Docker socket mounted into a container or world-writable on the host; Docker API on public port 2375 |
| high | plaintext secret in a `.env`, compose `environment:` or service config (medium → high when group-readable); privileged containers or `/` mounted; enabled root service with no sandboxing that loads an `EnvironmentFile`; known agent/admin port (n8n, Ollama, OpenClaw, Jupyter, …) public with no firewall, on the host or published by compose; SSH root password login; `.git-credentials`, `.netrc`, AWS, gcloud, kube credentials |
| medium | loose token files; plaintext CLI login stores (`gh`, `op`, npm, Docker, Hugging Face); automated-agent keys (`*-agent`, `ci@…`) with full root SSH; enabled root service without sandboxing; other ports public (one grouped finding on the host; per port in compose); host network / `cap_add`; no firewall while ports are public (low otherwise); users in the `docker` group; SSH password login |
| low | disabled root service still on disk; unlabeled root SSH keys; a secret copied to more places (`secret.duplicate`); encryption key stored next to the encrypted files; public port the firewall blocks today |

Not graded: publishable keys (Supabase `anon` / `sb_publishable_` JWTs), the tool/model inventory and the
"good" list (sandboxed services, default-deny firewall, key-only SSH, fail2ban, encrypted credential files).
A secret is counted once: the main finding points at the first live copy (backups and `quarantine/` folders last).

## Per-agent score

```
points = Σ risk points of the findings that touch this agent
score  = round(100 · e^(−points / 120))
1 critical   → score capped at 64 (D)
2+ criticals → score capped at 49 (F)
any infection indicator (category "infected") → capped at 20 (F)
```

Exponential decay means a few lows barely move you, while a pile of highs really hurts. It also never goes
negative, so a terrible setup gets an F with a score of 20, not 0.

## Bands

| Grade | Score |
|---|---|
| A | ≥ 90 |
| B | ≥ 80 |
| C | ≥ 65 |
| D | ≥ 50 |
| F | < 50 |

## Overall

```
overall = round(0.6 · worst agent + 0.4 · mean of agents)
1 critical anywhere   → overall capped at 64
2+ criticals anywhere → overall capped at 49
any infection indicator → overall capped at 20, and the terminal/HTML verdict reads INFECTED
```

All detected agents count, even if they're clean. In `--path`/`--server` mode the stack (named by `--label`) and
"Server host" are agents too. "Shared project files" (`AGENTS.md`, `.env`) count only if they
have findings. If no agent is found the grade is `null` ("No AI coding agents found on this machine").

The worst agent dominates the overall grade on purpose, because an attacker only needs one way in.

## Badge

`report.badge` holds the grade, a shields.io static-badge URL and Markdown. `--badge file.svg` writes the same badge
locally. If an indicator matched, the badge reads `F (IOC found)`. What each grade means: [docs/HARNESS-HYGIENE.md](docs/HARNESS-HYGIENE.md).

## Headline

`N MCP servers · K plaintext keys · Y agents in YOLO mode`. N counts unique server names. Y counts agents with a
critical `yolo` finding. In `--server` mode the last part becomes `Y host exposures` (findings in the
`host-exposure` category).
