# Config sources

Every location and key Agent X-ray reads, with where we learned it. Sources were checked in October 2026.
**Official** means the vendor's own docs. **Community/observed** means it isn't in the official docs; those entries are marked.
If you find a mistake, please open a PR with a link.

`~` = home folder. `%APPDATA%` = `C:\Users\<you>\AppData\Roaming`. "App data" = `%APPDATA%` (Windows),
`~/Library/Application Support` (macOS), `$XDG_CONFIG_HOME` or `~/.config` (Linux).

## Claude Code — official

| Path | Keys checked |
|---|---|
| `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json` | `permissions.defaultMode` (`bypassPermissions`, `acceptEdits`, `auto`), `permissions.allow`, `permissions.additionalDirectories`, `permissions.deny` (for `--deep`), `skipDangerousModePermissionPrompt`, `enableAllProjectMcpServers`, `sandbox.enabled`, `env` |
| `~/.claude.json` | `mcpServers`, `projects.*.mcpServers`, `projects.*.allowedTools` |
| project `.mcp.json` | `mcpServers` (project scope) |
| `~/.claude/CLAUDE.md`, `CLAUDE.md`, `CLAUDE.local.md` | secret scan only |

- https://code.claude.com/docs/en/settings: file locations and scopes
- https://code.claude.com/docs/en/settings-reference: keys
- https://code.claude.com/docs/en/permissions: allow-rule syntax (`Bash(cmd:*)`, `mcp__server__tool`)
- https://code.claude.com/docs/en/permission-modes: modes. It also notes that `bypassPermissions`/`auto` in project settings files don't take effect.
- https://code.claude.com/docs/en/sandboxing: `sandbox.enabled`

Not read: managed/enterprise settings files and `~/.claude/.credentials.json`.

## Claude Desktop

`<app data>/Claude/claude_desktop_config.json`, `mcpServers`. The macOS and Windows paths are **official**
(https://modelcontextprotocol.io/quickstart/user). The Linux path `~/.config/Claude/` is **community/observed**
(unofficial Linux builds).

## Cursor — official

| Path | Keys |
|---|---|
| `~/.cursor/mcp.json`, project `.cursor/mcp.json` | `mcpServers` (`command`/`args`/`env`/`url`/`headers`) |
| `~/.cursor/cli-config.json` (`$CURSOR_CONFIG_DIR`), project `.cursor/cli.json` | `permissions.allow` (`Shell(cmd)`, `Mcp(server:tool)`, `Write(path)`) |
| `~/.cursor/permissions.json`, project `.cursor/permissions.json` | `terminalAllowlist`, `mcpAllowlist` |
| `.cursorrules`, `.cursor/rules/` | secret scan only |

- https://cursor.com/docs/mcp
- https://cursor.com/docs/cli/reference/configuration
- https://cursor.com/docs/cli/reference/permissions
- https://cursor.com/docs/reference/permissions

Not read: the IDE's run-mode / "auto-run" toggles, which live in Cursor's internal state database rather than a config file.

## Codex CLI — official

`$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) and project `.codex/config.toml`. Keys: `approval_policy`
(`never`), `sandbox_mode` (`danger-full-access`), `[sandbox_workspace_write].writable_roots`, `[profiles.*]`,
`[mcp_servers.*]` (`command`, `args`, `env`, `url`, `bearer_token`, `http_headers`). `AGENTS.md` gets a secret scan only.

- https://developers.openai.com/codex/config-reference
- https://learn.chatgpt.com/docs/config-file/config-basic.md
- https://github.com/openai/codex/blob/rust-v0.63.0/docs/example-config.md

Not read: `~/.codex/auth.json`, on purpose.

## Gemini CLI — official

`~/.gemini/settings.json`, project `.gemini/settings.json` (JSON with comments). Keys: `general.defaultApprovalMode`
(`yolo`, `auto_edit`), `tools.autoAccept`, `tools.allowed`, `mcpServers` (`command`, `url`, `httpUrl`,
`headers`, `trust`, `env`). `GEMINI.md` gets a secret scan only.

- https://geminicli.com/docs/reference/configuration/
- https://geminicli.com/docs/tools/mcp-server/
- https://geminicli.com/docs/reference/policy-engine/ (policy TOML files are **not parsed yet**)

## VS Code / GitHub Copilot — official

| Path | Keys |
|---|---|
| `<app data>/Code/User/mcp.json` (and `Code - Insiders`), workspace `.vscode/mcp.json` | `servers` (`type`, `command`, `args`, `env`, `url`, `headers`) |
| `<app data>/Code/User/settings.json`, workspace `.vscode/settings.json` | `chat.tools.global.autoApprove`, `chat.tools.autoApprove`, `chat.permissions.default`, `chat.tools.terminal.autoApprove`, `chat.tools.terminal.ignoreDefaultAutoApproveRules` |
| `~/.copilot/mcp-config.json` (`$COPILOT_HOME`) | Copilot CLI `mcpServers` |
| `.github/copilot-instructions.md` | secret scan only |

- https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- https://code.visualstudio.com/docs/agents/reference/ai-settings
- https://code.visualstudio.com/docs/agents/run/approvals
- https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference

## Windsurf — official

`~/.codeium/windsurf/mcp_config.json`, `mcpServers` (`command`, `args`, `env`, `serverUrl`, `headers`). It also
secret-scans `~/.codeium/windsurf/memories/global_rules.md` and `.windsurfrules`.

- https://docs.devin.ai/windsurf/plugins/cascade/mcp
- https://docs.devin.ai/desktop/cascade/memories

Not read: Turbo mode / auto-execution level. It's stored in app state, not in a documented file.

## Zed — official

`~/.config/zed/settings.json` (Linux/macOS, honors `$XDG_CONFIG_HOME` on Linux), `%APPDATA%\Zed\settings.json` on Windows,
and project `.zed/settings.json`. Keys: `context_servers`, `agent.always_allow_tool_actions`, `agent.tool_permissions.default`.

- https://zed.dev/docs/ai/mcp.html
- https://zed.dev/docs/ai/tool-permissions

The Windows path is **community/observed**. Zed's Windows docs are sparse.

## Goose — official

`~/.config/goose/config.yaml` (macOS/Linux), `%APPDATA%\Block\goose\config\config.yaml` (Windows). Keys: `GOOSE_MODE`
(`auto`), `extensions.*` (`type: stdio|sse|streamable_http`, `cmd`, `args`, `envs`, `uri`, `enabled`). `secrets.yaml`
in the same folder (the fallback when no keyring is available) gets a secret scan only. `.goosehints` too.

- https://github.com/block/goose/blob/main/documentation/docs/guides/config-files.md

## Continue — official

`~/.continue/config.yaml` (and legacy `config.json`), project `.continue/mcpServers/*.yaml|json`. Key: `mcpServers`.

- https://docs.continue.dev/customize/deep-dives/configuration
- https://docs.continue.dev/customize/deep-dives/mcp

## Cline — official

`<app data>/<Code|Cursor|Windsurf|VSCodium>/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`,
`mcpServers` with `autoApprove`, `disabled`.

- https://docs.cline.bot/mcp/mcp-overview

The extension folder name is official. The editor host list is our assumption, covering editors that run VS Code extensions.
Not read: the "YOLO mode" / auto-approve toggles, which live in extension state.

## Roo Code — community/observed

`.../globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` and project `.roo/mcp.json`, `mcpServers`
with `alwaysAllow`, `disabled`.

- https://github.com/RooCodeInc/Roo-Code/issues/3390

## v0.3: hooks, auto-run and managed policy files

Hook and auto-run locations below are read for the **auto-run inventory**. Nothing found is executed.

| Harness | Path | Keys / what | Source |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json`, `.claude/settings*.json`, managed settings | `hooks` (every event), `statusLine.command`, `apiKeyHelper`, `enabledPlugins`, `extraKnownMarketplaces` | official: https://code.claude.com/docs/en/hooks, https://code.claude.com/docs/en/settings |
| Claude Code | `~/.claude/{skills,agents,commands}/`, `.claude/{skills,agents,commands}/`, `~/.claude/plugins/` | auto-loaded skills / subagents / plugins (listed, instruction-scanned) | official: https://code.claude.com/docs/en/skills, https://code.claude.com/docs/en/sub-agents |
| Claude Code (managed) | Linux `/etc/claude-code/managed-settings.json`, macOS `/Library/Application Support/ClaudeCode/managed-settings.json`, Windows `C:\Program Files\ClaudeCode\managed-settings.json`, `managed-mcp.json` beside each | same keys as settings | official: https://code.claude.com/docs/en/settings |
| Claude Code (managed) | `managed-settings.d/*.json` | drop-in fragments | **unverified** (observed; read if present) |
| Cursor | `~/.cursor/hooks.json`, `.cursor/hooks.json`; enterprise `/etc/cursor/hooks.json`, `/Library/Application Support/Cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json` | `hooks.*[].command` | official: https://cursor.com/docs/agent/hooks |
| Gemini CLI | `settings.json` (user, project, system) | `hooks`, `tools.discoveryCommand`/`callCommand`, extensions | official: https://github.com/google-gemini/gemini-cli/blob/main/docs/get-started/configuration.md |
| Gemini CLI (managed) | Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json` | system settings | official (same page) |
| Gemini CLI (managed) | macOS `/Library/Application Support/GeminiCli/settings.json`; `~/.gemini/extensions/*` | system settings; extension manifests | **unverified** |
| VS Code | `.vscode/tasks.json` | tasks with `runOptions.runOn: "folderOpen"` | official: https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior |

## GitHub Copilot CLI — official (v0.3)

Source: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference (`COPILOT_HOME` overrides `~/.copilot`).

| Path | Keys checked |
|---|---|
| `~/.copilot/settings.json` (JSONC) | `hooks`, `statusLine` (`type: command`), `enabledPlugins`, `extraKnownMarketplaces`, `allowedUrls`, `disableAllHooks` |
| `~/.copilot/mcp-config.json` | `mcpServers` |
| `~/.copilot/permissions-config.json` | `locations.<path>.tool_approvals[]`: `kind: "commands"` + `commandIdentifiers` (`git:*` = prefix), `allowed_directories` |
| `~/.copilot/copilot-instructions.md`, `instructions/*.instructions.md`, `agents/*.agent.md`, `skills/*/SKILL.md`, `hooks/`, `extensions/`, `installed-plugins/` | instruction scan, auto-run inventory |
| repo `.github/copilot/settings.json`, `settings.local.json`, `.github/hooks/*.json`, `.github/copilot-instructions.md`, `.mcp.json`, `.github/mcp.json` | hooks, plugins, MCP servers, instructions |
| managed: Linux `/etc/github-copilot/managed-settings.json`, macOS `/Library/Application Support/GitHubCopilot/managed-settings.json`, Windows `%ProgramFiles%\GitHubCopilot\managed-settings.json` | same keys as settings |

**Never read:** `~/.copilot/config.json` (holds auth).

## OpenCode — official (v0.3)

Sources: https://opencode.ai/docs/config/, https://opencode.ai/docs/plugins/, https://opencode.ai/docs/permissions/, https://opencode.ai/docs/mcp-servers/

| Path | Keys checked |
|---|---|
| `~/.config/opencode/opencode.json(c)`, project `opencode.json(c)`, `OPENCODE_CONFIG` | `permission` (`"allow"`, `bash`, `external_directory`), `mcp` (`command` is an array), `plugin` (npm, installed with Bun at startup) |
| `.opencode/plugins/`, `~/.config/opencode/plugins/` | local plugins, auto-loaded at startup (listed as auto-run) |
| `.opencode/agent(s)/`, `~/.config/opencode/agent(s)/`, `AGENTS.md` | instruction scan |
| default permissions when unset; `~/.config/opencode/AGENTS.md` | **unverified** |

## OpenClaw — official (v0.3)

Source: https://docs.openclaw.ai/gateway/configuration

| Path | Keys checked |
|---|---|
| `~/.openclaw/openclaw.json` (JSON5), `OPENCLAW_CONFIG_PATH` | gateway bind/auth, hooks (webhooks / cron), `agents.defaults.workspace` (default `~/.openclaw/workspace`) |
| `mcpServers` / MCP keys inside `openclaw.json`; workspace `AGENTS.md`, `SOUL.md`, `TOOLS.md` | **unverified** (read if present) |

## Aider — official (v0.3)

Source: https://aider.chat/docs/config/aider_conf.html

| Path | Keys checked |
|---|---|
| `.aider.conf.yml` in home, git root, then cwd (later wins) | `yes-always` (critical), `lint-cmd`, `test-cmd`, `auto-test`, `notifications-command` (auto-run), `load`, `read`; `openai-api-key` / `anthropic-api-key` (plaintext keys) |

## Qwen Code — official (v0.3)

Source: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/

| Path | Keys checked |
|---|---|
| `~/.qwen/settings.json`, `.qwen/settings.json` | `tools.approvalMode` (`yolo` critical, `auto-edit` low), `permissions.allow`, `ui.statusLine.command`, `tools.discoveryCommand`/`callCommand`, `mcp.serverCommand`, `mcpServers`, `skills.directories` |
| system: Linux `/etc/qwen-code/settings.json` + `system-defaults.json`, macOS `/Library/Application Support/QwenCode/…`, Windows `C:\ProgramData\qwen-code\…` (`QWEN_CODE_SYSTEM_SETTINGS_PATH`, `QWEN_CODE_SYSTEM_DEFAULTS_PATH`) | same keys |
| `.qwen/skills/`, `~/.qwen/skills/`, `~/.agents/skills/`, `QWEN.md` | instruction scan |
| Qwen `hooks` schema | **unverified** (read like Gemini's if present) |

## Instruction-file scan (v0.3)

Files: `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `QWEN.md`, `.cursorrules`, `.cursor/rules/**`,
`.windsurfrules`, `.windsurf/rules/**`, `.clinerules`, `.roo/rules/**`, `.github/copilot-instructions.md`,
`.github/instructions/**`, skills (`SKILL.md`) and subagent files in the folders above.
Checks: Unicode tag characters (U+E0000–E007F, decoded), bidi controls (U+202A–202E, U+2066–2069), zero-width
(U+200B–200D, U+2060, U+FEFF), prompt-injection phrases, and imperative remote-script steps (`curl … | sh`).
Planted-file check: `AGENTS.md`/`CLAUDE.md`/`GEMINI.md`/`.cursorrules` directly in `~/Downloads`, `~/Desktop`, the home
root, `/tmp` and `$TMPDIR` (no recursion). Background: https://forever.security/blog/hijacking-ai-agents-via-downloads-folder/,
https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents

## IOC list (v0.3)

`src/iocs.json`, updated 2026-10-26. Every entry cites one of these:

- StepSecurity, Mini Shai-Hulud: https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared
- Sonar, Mini Shai-Hulud targets AI coding agents: https://www.sonarsource.com/blog/mini-shai-hulud-targets-ai-coding-agents/
- CSA research note (wipe-on-rotate warning): https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-supply-chain-20260517-csa-st/
- Tenable, agent-harness attacks: https://www.tenable.com/blog/ai-coding-assistant-agent-harness-attacks
- GHSA-2f6m-69ww-37wv: https://github.com/advisories/GHSA-2f6m-69ww-37wv
- OSV MAL-2026-4219: https://osv.dev/vulnerability/MAL-2026-4219
- Forever Security / BleepingComputer, AGENTS.md in Downloads: https://forever.security/blog/hijacking-ai-agents-via-downloads-folder/, https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/
- OX Security, npm worm in CI workflows: https://ox.security/blog/npm-worm-hijacks-ci-workflows-ai-packages/

To update it, edit `src/iocs.json` (or ship an extra file and pass `--iocs`), bump `updated`, and add the source.

## Unverified (v0.3) — read if present, marked here until confirmed

- Claude Code `managed-settings.d/*.json` drop-ins; Claude Desktop on Linux (community builds)
- Gemini CLI macOS system-settings path and `~/.gemini/extensions/*` manifests
- OpenCode defaults when `permission` is unset; `~/.config/opencode/AGENTS.md`
- OpenClaw MCP-server keys and workspace instruction files
- Qwen Code `hooks` schema
- IOC list: the exact bad version range of `atool`, and fake MCP package names other than those in the cited advisories
  (for example `gadgethumans-mcp`). These are graded `ioc.watch` (high, never "infected") until a primary source confirms them.

## Shared

`AGENTS.md` in the project root, read by several agents (Codex, Cursor, Copilot and others). Secret scan only.

With `--deep`: `.env*` files in the project root. These are checked against `.gitignore`, the agent ignore files
(`.cursorignore`, `.codeiumignore`, `.aiexclude`, `.geminiignore`, `.aiderignore`, `.clineignore`, `.rooignore`, `.continueignore`) and Claude `permissions.deny` `Read(...)` rules. The values are never printed.

## Custom stacks (`--path`, `--server`) — v0.2

Only with these flags. Folders are walked without following symlinks, skipping `node_modules`, `.git`, virtualenvs,
build output, caches and any directory with more than 400 entries (max 40,000 files). Files are picked by name:

| Kind | Names |
|---|---|
| env | `.env`, `.env.*`, `*.env` (not `.example/.sample/.template`, not `.envrc`) |
| compose | `docker-compose*.yml`, `compose*.yaml` |
| MCP | `mcp.json`, `.mcp.json`, `mcp_config.json`, `mcp-settings.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`, or any config with `mcpServers` / `context_servers` |
| service config | `config*`, `settings*`, `secret(s)*`, `credential(s)*`, `agent(s)*` `.json/.jsonc/.yaml/.toml`, including `.prev-*`/`.bak` backups |
| token file | `*_token`, `*_pat`, `*.token`, `token(s)`, `secret(s)`, `api_key`, `credentials` (read up to 4 KB) |
| encrypted / key | `*.fernet`, `*.enc`, `*.gpg`, `*.age`, `*.kdbx`, SOPS files (counted, never opened); `*.key` (permissions only) |

`--server` roots: `/opt`, `/srv`, `/etc` (depth 2) and `/root` + `/home/*` (depth 5). It also reads:

- `/etc/systemd/system/*.service` and `multi-user.target.wants/` (which units are enabled), plus each custom unit's `EnvironmentFile=`
- `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/*/fd` link names and `/proc/*/comm` (which process owns a public port)
- `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user*.rules`
- `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf`, `/etc/fail2ban/jail.local`, `jail.d/*`, `/etc/group`, `/var/run/docker.sock` (permissions)
- `~/.ssh/authorized_keys` for each home (key types and comments only; public keys)
- plaintext CLI credential stores, to report that a token is there: `~/.config/gh/hosts.yml`, `~/.config/op/config`,
  `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.docker/config.json`, `~/.aws/credentials`, `~/.cache/huggingface/token`,
  `~/.config/gcloud/application_default_credentials.json`, `~/.kube/config`

## Never read

Shell history, browser profiles, OS keychains, SSH private keys, the contents of encrypted stores, and agent auth files
(`~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.claude/.credentials.json`, `~/.copilot/config.json`). Nothing found is ever executed. Cloud CLI credential files are
read only in `--server` mode, as listed above.
