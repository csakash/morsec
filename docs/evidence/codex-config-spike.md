# L13 spike: how Codex reads `config.toml` (PRD open question 2)

Checked 2026-11-14 against `codex-cli 0.162.1` (installed) and `openai/codex@main`. The old
`developers.openai.com/codex/*` doc URLs now redirect (308) to `learn.chatgpt.com/docs/...`.
Source links point at `main`, which may be ahead of 0.162.1; anything checked live is marked
**live**.

## Answer to PRD open question 2

**Yes: the Codex desktop app, the IDE extension and the CLI read the same `config.toml`.**

- The app docs say agents in the app "inherit the same configuration as the IDE extension and
  CLI" — <https://learn.chatgpt.com/docs/developer-settings?surface=app>.
- Config basics: "The CLI and IDE extension share the same configuration layers" —
  <https://learn.chatgpt.com/docs/config-file/config-basic>.
- The desktop app is an `app-server` client ("local stdio desktop sessions (`Codex Desktop`)"),
  and the TUI goes through app-server too, so config loading is one code path —
  <https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md>,
  `codex-rs/tui/src/app_server_session.rs`.
- Not app-wide keys: the IDE's `chatgpt.*` settings live in the editor, and
  `desktop.custom_file_handlers` is app-only —
  <https://learn.chatgpt.com/docs/config-file/config-advanced>.

**Not confirmed:** whether the macOS app honours a `CODEX_HOME` exported in a shell (a GUI
launch usually doesn't see shell env). `ms connect codex` therefore writes `~/.codex/config.toml`
unless `CODEX_HOME` is set, and then warns that the app may still read `~/.codex`.

## Key names (current)

| Need | Key | Source |
|---|---|---|
| Env for agent commands | `shell_environment_policy.set.<NAME> = "<value>"` | <https://learn.chatgpt.com/docs/config-file/config-reference>, <https://github.com/openai/codex/blob/main/codex-rs/config/src/shell_environment_policy.rs> |
| Order of the env steps | inherit → default excludes → `exclude` → **`set`** → `include_only` → thread id → non-inheritable vars stripped. So `set` survives excludes but `include_only` (and the new `filters`) can still drop it | <https://github.com/openai/codex/blob/main/codex-rs/protocol/src/shell_environment.rs> (lines 120-179) |
| Does `set` reach Codex's own API calls? | No: only `create_env` for spawned commands reads it; Codex's HTTP clients use system/process proxy settings | <https://github.com/openai/codex/blob/main/codex-rs/http-client/src/outbound_proxy.rs> |
| Does `set` reach MCP servers? | No. Stdio servers start with `env_clear()` plus a fixed safelist (HOME, LOGNAME, PATH, SHELL, USER, LANG, LC_ALL, TERM, TMPDIR, TZ, `__CF_USER_TEXT_ENCODING`), then `env_vars`, CA vars and the server's own `env` | <https://github.com/openai/codex/blob/main/codex-rs/rmcp-client/src/utils.rs>, `codex-rs/utils/pty/src/child_command.rs` (line 101) |
| MCP servers | `[mcp_servers.<id>]`: stdio `command`, `args`, `env`, `env_vars`, `cwd`; HTTP `url`, `bearer_token_env_var`, `http_headers`, …; both `enabled`, `startup_timeout_sec`, `tool_timeout_sec`, `enabled_tools`, … | config-reference above |
| Network proxy | No setting points sandboxed commands at an **external** proxy. `features.network_proxy` / `[permissions.<p>.network]` start Codex's **own** managed proxy (experimental, off by default: `codex features list` → `network_proxy experimental false`, **live**). Its upstream is the Codex process's own `HTTP(S)_PROXY`, which config can't set, and when it is on it overwrites `HTTP_PROXY`/`HTTPS_PROXY` in the command env | <https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md>, `codex-rs/network-proxy/src/proxy.rs` (`apply_proxy_env_overrides`) |
| Sandbox network | `sandbox_workspace_write.network_access` (default `false`) | config-reference above |

## Live sandbox checks (`codex sandbox`, throwaway `CODEX_HOME`)

A local HTTP server on `127.0.0.1:47811` answered 200 from the host.

| Sandbox | `curl http://127.0.0.1:47811/` | `curl https://example.com/` |
|---|---|---|
| `sandbox_mode="workspace-write"` (default network off) | refused: "Couldn't connect to server" | "Could not resolve host" |
| workspace-write + `sandbox_workspace_write.network_access=true` | 200 | 200 |
| `danger-full-access` | 200 | — |

And `-c 'shell_environment_policy.set.FOO="ms://x/y"' -c 'shell_environment_policy.set.HTTPS_PROXY="http://127.0.0.1:1"'`
puts both values in the sandboxed command's `env` verbatim (**live**).

**What this means:** with Codex's default sandbox, commands can't reach msd at all (loopback is
blocked with the rest of the network). When the user allows network, proxy-aware clients
reach msd through `HTTPS_PROXY`, but Codex does not stop a command from going direct. morsec
does not turn network on (that loosens the sandbox, SDLC-2); it tells the user.

## Codex writes `config.toml` itself

`ConfigEdit` writes (`codex-rs/core/src/config/edit.rs`): model, notices (`[notice]`), project
trust (`[projects."…"] trust_level`), `ReplaceMcpServers` (rewrites the whole `mcp_servers`
table, used by `codex mcp add/remove`), skills, generic `SetPath`/`ClearPath`. They parse with
`toml_edit` and write atomically (`write_atomically`, following symlinks). The app and IDE write
through app-server `config/value/write` / `config/batchWrite`.

So a byte-for-byte restore is only possible when the file still hashes to what morsec wrote;
otherwise disconnect removes morsec's own keys by content and keeps everything else.

## Inspection commands usable for a live check (no login, no model)

`codex mcp list [--json]`, `codex mcp get <id> [--json]`, `codex features list`,
`codex sandbox -- <cmd>`, all with `-c key=value`. **Note:** `codex mcp list --json` prints MCP
`env` values in clear (the table output masks them), so tests never log it with real values.
