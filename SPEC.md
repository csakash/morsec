# SPEC: L08 `connect-claude`

Card: `docs/PLAN.md` § "L08 `connect-claude`". Depends on L07 (merged, 9d18109).
Owns `crates/ms-connect/src/claude/` and the `ms connect` / `ms disconnect` CLI module
(`crates/ms-cli/src/connect.rs`). Shared files are touched only additively: `ms-connect`'s
`lib.rs` (one `pub mod claude;`), its `Cargo.toml`, `ms-cli/src/main.rs` (wire two commands),
the SDLC-2 / SDLC-4 / MCP-4 rows and a changelog line in `ARI42.md`, and
`docs/evidence/connect-claude.md`.

## Goal

`ms connect claude-code` sets up Claude Code (terminal, desktop app, IDE extensions — they all
read the same user settings) so that commands Claude runs reach keys only through morsec, and
`ms disconnect claude-code` puts every file back exactly as it was. No secret value is ever
written anywhere: only `ms://` references, ports, paths and a marker.

## Claude Code settings, verified 2026-11-14 against Claude Code 2.1.318 docs

| What | Name / format | Source |
|---|---|---|
| User settings file | `~/.claude/settings.json` (strict JSON; `$CLAUDE_CONFIG_DIR/settings.json` when set). Read by terminal, VS Code, JetBrains and the desktop app. Reloaded on save. | https://code.claude.com/docs/en/settings |
| `env` | Object of string → string. Applied to Claude Code's **own process** and every subprocess; values copied as written (no `~`/`$VAR` expansion). | https://code.claude.com/docs/en/env-vars ("Set variables in settings files") |
| Proxy variables | Claude Code uses `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` for its **own** API traffic, also when they come from `env`. | https://code.claude.com/docs/en/network-config |
| `sandbox.enabled` | bool; Bash sandboxing on macOS, Linux, WSL2. | https://code.claude.com/docs/en/settings-reference , https://code.claude.com/docs/en/sandboxing |
| `sandbox.network.allowedDomains` | string list, `*.example.com` wildcards. Lists merge across scopes. | same |
| `sandbox.network.httpProxyPort` / `socksProxyPort` | localhost port of your own proxy. Once set, **that proxy filters everything sent to it**; `allowedDomains` no longer applies to that traffic. Settable from user settings. | https://code.claude.com/docs/en/sandboxing ("Custom proxy configuration") |
| `sandbox.network.allowUnixSockets` | Unix socket paths sandboxed commands may use (macOS). | settings-reference |
| MCP servers | **Not** in `settings.json`. User scope and local scope live in `~/.claude.json` (`mcpServers` top level for user scope; `projects.<path>.mcpServers` for local). Project scope is `.mcp.json` in the repo. A stdio entry is `{ "type": "stdio", "command", "args", "env" }`; `type` may be omitted for stdio. | https://code.claude.com/docs/en/mcp ("MCP installation scopes") |
| `hooks` | `{ "<Event>": [ { "matcher"?: string, "hooks": [ { "type": "command", "command", "args"?, "timeout"?, "shell"?, ... } ] } ] }`. With `args` the hook is **exec form** (no shell); without, **shell form** (`sh -c`). `SessionStart` hooks get `CLAUDE_ENV_FILE`; `export` lines appended to it apply to every later Bash command. | https://code.claude.com/docs/en/hooks ("Command hook fields", "Exec form and shell form", "Persist environment variables") |
| `statusLine` | `{ "type": "command", "command": "<shell command>", "padding"?: n }`; the command gets session JSON on stdin and its stdout is shown. | https://code.claude.com/docs/en/statusline |

## Decisions (made in this loop; flagged for the orchestrator)

- **D1 — proxy through the sandbox port, not `env` proxy variables.** Putting `HTTPS_PROXY` in
  `env` would route Claude Code's own API traffic through msd, which refuses every unbound host,
  so Claude Code would stop working. The connector sets `sandbox.network.httpProxyPort` to msd's
  proxy port instead: sandboxed Bash commands (where keys are used) go through msd; Claude Code's
  own traffic does not. No `socksProxyPort` (msd doesn't speak SOCKS), so SOCKS traffic stays on
  Claude Code's built-in proxy and its `allowedDomains`. Consequence: a command run outside the
  sandbox gets no proxy, so refs don't resolve (fail closed, nothing leaks). The proxy username
  `claude-code` can't be carried this way; msd identifies the caller from the process tree, and
  the username is only a cross-check (L06), so this loses nothing.
- **D2 — msd's tunnel allowlist is not L08's to change.** With D1, msd filters all sandboxed HTTP
  traffic and (L07 hand-over) refuses every host no key is bound to. So inside the sandbox, only
  hosts bound to keys work; `npm install` etc. are refused by msd. Giving msd a tunnel allowlist
  needs a MAC'd source (a rules section), which is L03/L07 code. L08 writes `allowedDomains`
  = the rules' hosts (per the card; it governs SOCKS and documents intent) and records the msd
  allowlist as a follow-up. **Orchestrator: please confirm or schedule.**
- **D3 — `--wrap` (hooks and local MCP servers through `ms run --`) and `--with-mcp` (the `ms
  mcp` server) are opt-in for now.** `ms run` (L12) and `ms mcp` (L14) still exit 69. Wrapping
  every hook in a command that fails would break the user's hooks; an MCP server that fails shows
  as an error in every session. Both are fully built and tested; L12/L14 flip the defaults.
- **D4 — the `ms mcp` entry runs under `/usr/bin/env -i`** with an explicit minimal environment
  (`HOME`, `PATH=/usr/bin:/bin`, and `MORSEC_SOCKET` only if set at connect time) so the server
  never inherits Claude Code's environment (provider keys, tokens). That is MCP-4's "minimal
  explicit env". Wrapped third-party local MCP servers go through `ms run --`, which owns their
  environment from L12 on.
- **D5 — `PATH` comes from a `SessionStart` hook, not `env`.** `env` doesn't expand `$PATH`, so
  writing `PATH` there would freeze the user's PATH at connect time and replace Claude Code's own.
  The connector adds an exec-form `SessionStart` hook `ms connect claude-code --session-env`, which
  appends `export PATH='<shim dir>':"$PATH"` to `$CLAUDE_ENV_FILE`.
- **D6 — the CA bundle is the connector's file:** `~/.morsec/ca-bundle.pem` = macOS system roots
  (`/etc/ssl/cert.pem`) + the morsec CA (from `Status.ca_pem`, never from `ca.pem` on disk) + any
  CA file the user's settings already named in a CA variable (so a corporate CA keeps working).
  It is always written (roots only when no host is bound), so the CA variables never point at a
  missing file. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`
  point at it. Re-run `ms connect claude-code` after adding a host (the CA is re-issued); L17
  doctor will detect a stale bundle. PLAN §3.5 put the bundle under msd's state dir; msd never
  reads it, so it moves to the connector's directory.
- **D7 — restore is byte-exact when nothing else changed, structural otherwise.** JSON has no
  comments, and an unknown top-level key may draw a Settings Warning, so the "marked block" is:
  a marker `env.MORSEC_CONNECTED = "claude-code"` in the file, plus a state file
  `~/.morsec/connect/claude-code.json` (0600, dir 0700) holding the original bytes and every
  change as `(JSON path, value before, value written)`. `ms disconnect`: if the file is still
  exactly what `ms connect` wrote, the original bytes come back; if the user (or Claude Code)
  edited it since, each recorded change whose current value is still ours is undone, the user's
  edits stay, and a warning says so. `~/.claude.json` is always restored structurally (Claude
  Code rewrites it constantly).
- **D8 — refusals instead of guesses.** The connector refuses (and changes nothing) when a target
  file is a symlink (dotfile managers: re-pointing it would replace the link), is not a regular
  file, is over 4 MiB, isn't valid JSON, isn't a JSON object, or has a duplicate key anywhere
  (JSON.parse keeps the last one; a reviewer reads the first — SDLC-4). It also refuses an
  existing `sandbox.network.httpProxyPort` it didn't write (the user runs their own proxy) and an
  existing `mcpServers.ms` it didn't write, unless `--force`.
- **D9 — own JSON editor, no new dependency.** `serde_json` sorts keys unless `preserve_order` is
  on, and that feature would unify across the workspace and change other crates' output. A small
  order-preserving JSON parser/printer in `ms-connect` keeps the user's key order, detects their
  indent (2/4 spaces or tab), keeps numbers as written and keeps the trailing-newline choice.
- **D10 — `ms disconnect` refuses inside an agent session** (process-tree check, like `ms add`
  replacing a key): an agent removing its own sandbox is loosening its policy (SDLC-4). Run it
  from your own terminal. `ms connect` is allowed anywhere (it only adds controls), except
  `--force`, which can override the user's own proxy and is refused inside an agent session too.
- **D11 — the frozen `Connector` trait stays as is.** `plan()` can't return an error, so the
  real work is `ClaudeConnector::try_plan` (Result); `plan()` returns an empty diff on error.
  Connector options that `ConnectCfg` doesn't carry (home, `ms` path, flags) live on
  `ClaudeConnector`. `ConnectCfg.env` holds the CA variables and `--env` refs; `shim_dir` the shim
  directory; `proxy_port` and `allowed_domains` as named.
- **D12 — the `ms` path written into settings** is the first `ms` on `PATH` that resolves to the
  running binary (a stable Homebrew symlink survives upgrades), else the running binary's path.
- The live check the card puts in `tests/e2e` lives in `crates/ms-connect/tests/live_claude.rs`
  (opt-in, `MORSEC_LIVE_CLAUDE=1`), because `tests/e2e/` is owned by L09, which runs in parallel.

## Behaviour

### What `ms connect claude-code` writes

`~/.claude/settings.json` (created if missing), merged into whatever is there:

| Key | Value | Merge |
|---|---|---|
| `env.MORSEC_CONNECTED` | `"claude-code"` | set |
| `env.SSL_CERT_FILE`, `env.REQUESTS_CA_BUNDLE`, `env.CURL_CA_BUNDLE`, `env.NODE_EXTRA_CA_CERTS` | absolute path of `~/.morsec/ca-bundle.pem` | set; a user value is replaced (recorded, restored) and its file is folded into the bundle |
| `env.<NAME>` for each `--env NAME=ms://ref` | the ref | set; the value must parse as a `SecretRef`; `NAME` must be `[A-Z_][A-Z0-9_]*` and not a loader, proxy, CA, `PATH`, `MORSEC_*`, `CLAUDE_*` or `ANTHROPIC_*` variable |
| `sandbox.enabled` | `true` | set |
| `sandbox.network.httpProxyPort` | msd's proxy port (`Status.proxy_port`) | set; refuse if the user set another (unless `--force`) |
| `sandbox.network.allowedDomains` | user's list ∪ every host in the user rules (`RulesGet`), as `api.x.com` / `*.x.com` | union; only the added entries are recorded |
| `sandbox.network.allowUnixSockets` | user's list ∪ msd's socket path, so shims and `ms` work inside the sandbox | union |
| `hooks.SessionStart` | appended group `{ "hooks": [ { "type": "command", "command": "<ms>", "args": ["connect", "claude-code", "--session-env"] } ] }` | append |
| `statusLine` (only with `--statusline`) | `{ "type": "command", "command": "'<ms>' status" }` | only when absent; otherwise a note |
| with `--wrap`: every existing `type: "command"` hook (not ours, not PowerShell) | exec form `<ms> run -- <command> <args…>`; shell form `<ms> run -- /bin/sh -c '<command>'` | recorded, restored exactly |

`~/.claude.json` (only with `--with-mcp` or `--wrap`; never created by `--wrap` alone):

- `--with-mcp`: `mcpServers.ms = { "type": "stdio", "command": "/usr/bin/env", "args": ["-i",
  "HOME=<home>", "PATH=/usr/bin:/bin", ("MORSEC_SOCKET=<path>",) "<ms>", "mcp"], "env": {} }`.
- `--wrap`: every stdio server in `mcpServers` and `projects.*.mcpServers` (not `ms`) becomes
  `command: <ms>, args: ["run", "--", <command>, <args…>]`; `env` unchanged.

Never written: project files (`.claude/settings.json`, `.claude/settings.local.json`,
`.mcp.json`), `permissions`, any bypass or auto-approve setting, `excludedCommands`,
`allowUnsandboxedCommands`, `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY`.

Connect warns (doesn't change) when the user's settings have `permissions.defaultMode:
"bypassPermissions"` or `sandbox.excludedCommands`, since those weaken the sandbox (SDLC-2).

### Idempotence

Re-running `ms connect claude-code` first undoes the previous connect in memory (D7), then
plans again from that state, so a second identical run produces byte-identical files and the
state file keeps the original bytes from the first run. A changed port, host list or flag set
updates the block in place.

### Writes

- Every write is atomic (temp file in the same directory, `fsync`, `rename`), mode 0600 for new
  files, existing mode kept.
- `apply` is compare-and-swap: each file must still have the bytes the plan was computed from,
  or nothing more is written and the user is told to re-run.
- Order: state file, CA bundle, `settings.json`, `~/.claude.json`. Remove: `settings.json`,
  `~/.claude.json`, then the state file.

### CLI

```
ms connect claude-code [--dry-run] [--yes] [--env NAME=ms://ref]... [--with-mcp] [--wrap]
                       [--statusline] [--force]
ms disconnect claude-code [--yes]
```

- `connect` asks msd for `Status` (proxy port, CA) and `RulesGet` (hosts); if msd is down it
  stops with the usual "daemon not running. Start it with: ms start" (fail closed).
- It prints the planned change to `settings.json` (and `~/.claude.json`) as changed lines only
  (no context lines, terminal-safe), then asks `Apply? [y/N]` on a terminal. `--yes` skips the
  question; without a terminal and without `--yes` it writes nothing and exits 1. `--dry-run`
  prints and exits 0.
- `disconnect` shows what it will restore, asks the same way, and refuses inside an agent
  session (D10). Not connected: says so, exit 0.
- Hidden `ms connect claude-code --session-env` (used by the hook): appends one `export PATH=…`
  line (shim path single-quoted) to `$CLAUDE_ENV_FILE`; no-op without it.
- `codex`, `cursor`, `gemini`: "not built yet (L13 / L22)", exit 69. Unknown agent: usage error.
- `ms connect` with no agent lists the agents and whether each is connected.

### `verify()` (for L17 `ms doctor`)

Checks: connected (state file and marker agree); `sandbox.enabled` is true; `httpProxyPort`
equals the recorded port; CA variables point at the bundle and it exists; the `SessionStart`
hook is present; `mcpServers.ms` present when it was requested. Each failing check says the fix
(`ms connect claude-code`).

## Acceptance criteria

1. Golden diffs: `empty` (no file), `typical` and `complex` existing `settings.json` (plus a
   `~/.claude.json` with servers for `--with-mcp --wrap`) produce the committed expected files.
2. Round trip: connect then disconnect gives byte-identical files for all goldens and for odd
   formatting (4-space indent, tabs, no trailing newline, unicode, big numbers).
3. Idempotent: connect twice = connect once, byte for byte, state unchanged.
4. A user edit between connect and disconnect survives disconnect; our keys are gone.
5. Refusals (D8) change nothing and say why.
6. `--env` accepts only valid names with `ms://` refs (SDLC-4: no secret value can be written).
7. SDLC-2: the plan enables the sandbox, routes it through msd, never writes a bypass or
   escape-hatch setting, and warns about the user's own.
8. SDLC-4: only user-scope files under `HOME` are written; `disconnect` refuses inside an agent
   session; `verify()` reports drift when the proxy port or sandbox flag is edited.
9. MCP-4: the `ms mcp` entry, spawned with a parent environment holding provider keys, gives the
   server only `HOME`, `PATH` (and `MORSEC_SOCKET`).
10. CLI end to end against a dev msd with a temp `HOME`: dry-run writes nothing, `--yes` writes,
    the session-env hook line is correct, disconnect restores. Tests never touch the real
    `~/.claude`.
11. `npm run build` (`scripts/check.sh`) green; ARI-42 scan clean.

## Out of scope

msd's tunnel allowlist (D2); `ms run` and `ms mcp` themselves (L12, L14); Codex/Cursor/Gemini
(L13, L22); managed (root-owned) settings; Windows; the desktop app's "saved local environment".

## Amendments made during the build (from the fresh-context review)

- **A1 (R2, tightens D10):** `--wrap` is refused inside an agent session too, like `--force`
  (while `ms run` is a stub, wrapping makes a blocking hook stop blocking), and prints a warning
  when used. The hidden `--rules FILE` test option exists only in debug builds; a release `ms`
  takes hosts only from msd's MAC-verified rules.
- **A2 (R1, R3, R4):** connect and disconnect check every file before writing any. Disconnect
  never rewrites a settings file that holds nothing of morsec's, always restores
  `settings.json` even when `~/.claude.json` can't be read (the state file then keeps only what
  is left to undo there), and removes a `~/.claude.json` that connect created.
- **A3 (R5, R7, R8):** `verify()` compares with the values recorded at connect; a re-run after
  `--force` may replace again only the exact value that was force-replaced, and only while
  morsec's own value is still in place (a value the user set since needs a fresh `--force`);
  an unknown agent is a usage error (exit 2).
- **A4 (R10, R11):** a disconnect that could not finish `~/.claude.json` exits 1, says
  "partly disconnected", keeps the record, and `ms connect` (list) and `verify()` report it;
  the next disconnect finishes it without reading `settings.json`.
- **A5 (security review S1):** the state file never stores a value from the user's files. The
  original `settings.json` is kept as a skeleton (every string value blanked, layout, keys and
  numbers kept) plus its SHA-256; restore fills the values back from the undone document and is
  byte-exact when the hash matches, else structural. Wrapping is recorded as a hash plus two
  bits. A raw `env` value that an `--env` ref replaces is not kept: disconnect removes the entry
  and says so. Residuals: a string written with non-canonical escapes (e.g. `é`) keeps its
  literal; the user's own `mcpServers.ms`, replaced only with `--force`, is kept so it can be put
  back; the user's CA file paths are kept.
- **A6 (S2, S4):** a plain re-run keeps the opt-in parts of the last connect (`--with-mcp`,
  `--wrap`, `--statusline`); only `ms disconnect` drops them. The `ms` path written into hooks is a
  PATH entry only in a directory outside `HOME` and the current directory that no other user can
  write, else the canonical binary path.
