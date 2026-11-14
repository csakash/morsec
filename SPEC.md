# L13 `connect-codex`: `ms connect codex` / `ms disconnect codex`

Card: `docs/PLAN.md`, "L13 `connect-codex`". Spike: `docs/evidence/codex-config-spike.md`.
Owns `crates/ms-connect/src/codex/`. Follows L08 (`crates/ms-connect/src/claude/`) where it can.

## Problem

Codex (CLI, desktop app, IDE extension) runs commands and MCP servers that need API keys. Users
put real keys in `~/.codex/config.toml` (`mcp_servers.<id>.env`) or their shell. morsec should
give Codex references (`ms://…`) instead, route traffic that carries them through msd's swap
proxy, and do it with one reversible command.

## What `ms connect codex` writes

All of it goes into **`$CODEX_HOME/config.toml`** (default `~/.codex/config.toml`; the spike
shows the app, IDE and CLI share it). Nothing else of Codex's is touched. morsec also writes
`~/.morsec/connect/codex.json` (state) and `~/.morsec/codex-ca-bundle.pem`.

1. `[shell_environment_policy.set]` (env of every command Codex runs):
   - `MORSEC_CONNECTED = "codex"` (marker).
   - `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy` = `http://127.0.0.1:<msd proxy port>`.
   - `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` = the bundle
     (system roots + msd's CA from `Status` + CA files the user's `set` already named).
   - `MORSEC_SOCKET` when set at connect time (dev daemons).
   - `--env NAME=ms://ref` references (same name/value rules as L08 `check_ref_env`).
2. `[mcp_servers.<id>.env]` for `--mcp-env <id>:NAME=ms://ref` on an existing **stdio** server
   (one with `command`): the reference, plus the proxy and CA variables, because Codex starts
   MCP servers with a cleared environment (spike) and `shell_environment_policy` does not reach
   them. HTTP servers (`url`) are refused: they don't run locally.
3. `[mcp_servers.ms]` only with `--with-mcp` (opt-in until L14 ships `ms mcp`, like L08):
   `command = "/usr/bin/env"`, `args = ["-i", "HOME=…", "PATH=/usr/bin:/bin", ("MORSEC_SOCKET=…",) "<ms>", "mcp"]`
   (MCP-4: explicit minimal environment).

## Decisions

- **D1 Proxy routing.** Codex has no setting that points sandboxed commands at an external
  proxy; its managed proxy (`features.network_proxy`, `permissions.*.network`) is experimental,
  and its upstream can't be set from config. So morsec sets the proxy variables in
  `shell_environment_policy.set`. It **never** turns on `sandbox_workspace_write.network_access`,
  changes `sandbox_mode` or `approval_policy`, or writes `features.*` / `permissions.*`
  (SDLC-2). When the user's sandbox has network off (the default), connect says that commands
  can't reach morsec until they allow network; when Codex's managed proxy is on, it warns that
  Codex overrides the proxy variables. Direct egress is not blocked for Codex (follow-up for
  L17 doctor to report).
- **D2 One record per key path.** Every change is a record keyed by its full TOML key path.
  Nothing is identified by array position or by value shape (L08 F1). Records live in a
  path-keyed list where a second record for a path replaces the first, and every plan starts
  from the document with the previous connect undone (L08 F2). Re-running with the same inputs
  writes nothing.
- **D3 Merge, not append.** Edits go through `toml_edit`: comments, ordering and formatting of
  everything morsec doesn't touch are kept. New keys go in the existing table when there is one
  (header, dotted or inline); missing tables are created implicitly and recorded, and undo
  removes them only when empty. A key that already holds morsec's exact value is left alone and
  not recorded.
- **D4 Byte-exact restore, proven before writing.** Connect computes the new text, then undoes
  it in memory from that text and requires the exact original bytes back. If not (e.g. CRLF
  line endings, which `toml_edit` doesn't keep), connect refuses and changes nothing. Disconnect
  on a file still hashing to what connect wrote therefore restores it byte for byte (also
  checked against the recorded hash of the original). A connect that created the file removes it.
- **D5 Edited since connect.** Codex itself rewrites `config.toml` (trust levels, notices,
  `codex mcp add`). If the file changed, disconnect removes each morsec key whose value is still
  what morsec wrote (compared by content, not layout), keeps everything else, and says what it
  left alone.
- **D6 Values of the user's.** A different value already at a key morsec needs:
  - proxy or CA variables, `mcp_servers.ms`: refused unless `--force` (user only, not inside an
    agent session). CA files the user named are folded into the bundle instead.
  - `--env` / `--mcp-env` replacing a value: allowed (that is the point: a plaintext key becomes
    a reference). The old value is **not** kept anywhere (L08 S1), so disconnect removes the
    entry instead of putting it back, and says so.
  - With `--force`, the old value is kept for restore only when it holds no credentials (a
    proxy URL with `user:pass@` is dropped like a key); an old `mcp_servers.ms` is never kept.
- **D7 State file holds no user values.** It keeps the SHA-256 of the original and of the
  written text, the records (paths and the values morsec wrote, which are references, paths,
  ports), the created tables and the options.
- **D8 Safe file handling** (reused from L08 `fsio`): refuse a symlinked or non-regular
  `config.toml`, files over 4 MiB, non-UTF-8, invalid TOML; atomic write keeping the file mode
  (new files 0600); every file is re-checked against the plan before anything is written.
- **D9 Preview redaction.** The plan shows only changed lines; a value is printed only if every
  string in it is one morsec wrote, else `"…"`; continuation and comment lines are `…`.
- **D10 Agent can't loosen.** `ms disconnect codex` and `--force` refuse inside an agent session
  (L08 D10). `--wrap` / `--statusline` are Claude-only and refused for codex.
- **D11 Re-run keeps state.** A plain re-run keeps the previous `--env`, `--mcp-env` and
  `--with-mcp`; dropping one is `ms disconnect`'s job.
- **D12 Warnings, never changes, for weaker settings** (SDLC-2): `sandbox_mode =
  "danger-full-access"`, `approval_policy = "never"`, `include_only`/`filters` that may drop
  morsec's variables, profiles overriding `shell_environment_policy`, `CODEX_HOME` set (the app
  may read `~/.codex`).

## Not in scope

Allowed-domains for Codex (no stable key), `ms run` wrapping of MCP servers (L12), PATH shims
(no Codex session hook that can prepend to PATH safely), `ms doctor` (L17; `verify()` returns
the checks).

## Acceptance

1. Golden round trips: empty/missing file, a typical config, and a complex one (comments, dotted
   keys, inline `set`, existing `mcp_servers`, profiles, arrays of tables, no final newline):
   connect then disconnect gives byte-identical output; the connected text matches a golden.
2. Re-run with the same inputs: no file changes, one record per path; changing an `--env`
   reference updates its one record.
3. Codex-style edits between connect and disconnect (new `[projects."…"]`, a reformatted
   `mcp_servers` table) are kept; morsec's keys are gone.
4. `--env`/`--mcp-env` take only `ms://` references with safe names; a value of the user's is
   replaced, never stored in the state file, and the preview never shows it.
5. Refusals change nothing: symlink, invalid TOML, CRLF, non-table `shell_environment_policy`,
   conflicting proxy without `--force`, `--mcp-env` on an unknown or HTTP server.
6. MCP-4: the `ms` entry runs under `env -i` with only HOME, PATH (and MORSEC_SOCKET).
7. SDLC-2: no write ever contains `network_access`, `sandbox_mode`, `approval_policy`,
   `features`, `permissions`; warnings fire for the weaker settings in D12.
8. Tests use a temp HOME / `CODEX_HOME` only. Live check (opt-in) with the installed `codex`:
   `codex mcp list/get` accepts the written file, and `codex sandbox -- env` shows the marker,
   the proxy and CA variables.
9. `npm run build` green; ARI42.md SDLC-2, SDLC-4, MCP-4 updated.
