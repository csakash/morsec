# SPEC: L12 `run-core`

Card: `docs/PLAN.md` § "L12 `run-core`". Depends on L07 (merged). Owns `crates/ms-run/`
(except `src/adapters/`), the `ms-shim` binary and the `ms run` CLI module
(`crates/ms-cli/src/run.rs`). Shared files are touched only additively:

| File | Change |
|---|---|
| `crates/ms-ipc/src/protocol.rs` | optional `env` on `Run`; new `RunStream`, `RunInput`, `RunInputEnd` requests; `RunOutput`, `RunExit`, `RunResult` replies; error code `not_run` |
| `crates/ms-ipc/src/server.rs` | `Handler::handle_stream` (default: not implemented) and the stream pump for `RunStream` |
| `crates/ms-ipc/src/client.rs` | `Client::run_stream` |
| `crates/ms-rules/src/{model,change}.rs` | per-key `roots` (run keys only); adding a root is loosening |
| `crates/ms-scan/src/lib.rs` | `Needles::patterns()` (read-only accessor) |
| `crates/ms-cli/src/{main,rules}.rs` | wire `ms run`; `ms rules --add-root/--remove-root` |
| `crates/msd/src/daemon.rs` | dispatch `Run`/`RunStream` to `daemon/run.rs` |
| `ARI42.md` | OUT-1, OUT-4, GW-1 rows and a changelog line |

## Decide first: DSN userinfo refs in `SecretRef::find_all`

**Decision: keep `find_all` as it is.** `postgres://app:ms://pg/staging@db/app` is not a ref
and stays one that is never resolved. A DSN password is stored as the **whole value**
(`DATABASE_URL=ms://pg/staging`, the vault holding the full URL), which is what `ms import`
(L04) already writes: it rewrites a whole variable to `ms://<key>`, never part of it. The
`?password=ms://…` query form still works where an adapter accepts it.

Why: `ms://pg/staging@db/app` is ambiguous to a reader and to `parse` (is `@db` part of it?),
`ms-core` is a frozen crate, and today's behaviour fails closed (the literal ref reaches the
database and authentication fails; no value moves). L15 owns the Postgres adapter and can
split a whole-value DSN into a password-less URL plus a passfile. The `find_all_embedded` test
keeps the DSN case in its "not matched" table; its comment is updated to point here.

## Goal

An agent's command that carries an `ms://` ref runs **in msd**, with the value given to the
child the least exposed way, under the key's rules, and its output comes back with every
encoding of the value redacted. Without a ref, nothing about the command changes.

## Decisions (made in this loop; flagged for the orchestrator)

- **D1 — streaming over the socket.** `RunStream {argv, cwd, env}` opens a stream on its own
  connection: the client sends `RunInput {data}` frames (stdin) and `RunInputEnd`; msd sends
  `RunOutput {stream, data}` frames and ends with one `RunExit {code, signal}` (or an `Error`),
  then closes the connection. Bytes travel base64 in the JSON body (frames stay JSON; chunks
  ≤ 32 KiB). A client that disconnects cancels the run: msd kills the child's process group.
  The frozen `Run` stays as the buffered form (no stdin; reply `RunResult {code, signal,
  stdout, stderr, truncated}`, each stream capped at 256 KiB) for L14's MCP tools. A run is
  bounded by the connection lifetime (10 min). At most 8 runs at a time.
- **D2 — project roots are per-key `roots` in the user rules.** "Registered" means in the
  MAC'd `rules.toml`, changed only through `ms rules <key> --add-root DIR` (loosening: needs an
  approval; `--remove-root` tightens). A run key with no roots can't run anything (fail closed;
  the error says how to add one). Roots are absolute, normalised, not `/`. The request's cwd
  must be absolute and its canonical path (symlinks resolved) must lie inside a root's
  canonical path for **every** key the call uses. A project `.morsec.toml` cannot add roots
  (the merge leaves them as the user set them). Run rules also merge the project file found
  from the cwd up to the git root, like `ms rules` does.
- **D3 — the binary comes from a trusted search path, never the agent's `PATH`.** Policy sees
  `argv[0]` as the bare tool name (the shim sends the name it was invoked as). msd resolves a
  bare name in `/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin` (Homebrew dirs
  macOS only), skipping `~/.morsec/shims` and any file that is the shim. A relative path with a
  `/` (`./deploy.sh`) is refused: an agent can rewrite it. An absolute `argv[0]` is run only
  when a rule pattern names that exact absolute path. The resolved file must be a regular,
  executable file that is not group- or world-writable. The child is spawned with that
  absolute path and the argv array; no shell is ever involved.
- **D4 — the generic adapter delivers values through environment variables only.** The client
  forwards only the environment variables whose value contains a ref (at most 64; names
  `[A-Za-z_][A-Za-z0-9_]{0,127}`; never `PATH`, `HOME`, `SHELL`, `IFS`, `ENV`, `BASH_ENV`,
  `LD_*`, `DYLD_*`). msd substitutes each run-mode ref in them. A ref in an argument is refused
  by the generic adapter ("put it in an environment variable"): argv is visible to every user
  through `ps`; a same-user process can read the environment too (OUT-4 residual until L23).
  Adapters with a better channel (L15 passfile, L16 agent) take argv refs themselves.
- **D5 — minimal environment.** The child gets `PATH` (the trusted search path), `HOME`,
  `USER`, `LOGNAME`, `LANG`, `TMPDIR` (from msd's own environment, when set) and the resolved
  ref variables. Nothing else from the agent or from msd.
- **D6 — what the shim does.** `ms-shim` is hard-linked as `psql`, `stripe`… It looks for a
  ref in its arguments and environment. None: it `exec`s the next binary of that name on
  `PATH` after its own directory, skipping itself (same device and inode) and, when it was
  exec'd straight from another shim (`MORSEC_SHIM_PID` equals its own PID), searching only
  after its own directory, so two shim directories can't loop. A ref present: it sends
  `RunStream` to msd. If msd answers `not_run` (no run-mode key among the refs, e.g. only swap
  refs), the shim `exec`s the real tool unchanged: the literal refs reach it, as without
  morsec, and the swap proxy resolves them for HTTP. msd down: refuses loudly (exit 69), never
  runs the tool with the raw ref silently. A ref in a non-UTF-8 argument is refused.
- **D7 — `ms run -- <cmd>`** is the explicit form of the shim's forward path: same request,
  same exit codes; with no ref anywhere it refuses (exit 64) instead of running locally; a
  `not_run` answer is an error too. Not a pty: interactive full-screen tools are out of scope.
- **D8 — production keys go through `Approver`.** Each production key in the call raises one
  `ApprovalRequest` built by msd from the normalised argv, canonical cwd, the adapter's
  preview and `argv_hash`; only `Approved` runs. Today msd's approver is the L11 deny-stub, so
  production run keys are refused with the pre-L11 message. The token is recorded in the
  receipt; checking its MAC against the exec plan is L11's (its card: "the executor refuses").
- **D9 — exit codes.** The child's code passes through; a signal becomes 128+N. morsec's own
  failures: 77 refused by policy or a person, 69 daemon unavailable, 64 usage, 70 internal;
  each with a `morsec:` message on stderr.
- **D10 — redaction.** Per run, the patterns are every key's value in the call plus its
  JSON-escaped, URL-encoded (both hex cases), hex (both cases), base64 and base64url forms at
  every alignment (reusing `ms-scan`'s encoders), for values ≥ 8 bytes; shorter values are
  redacted raw only. One Aho–Corasick automaton finds overlapping matches; the union of
  matched spans is replaced with `[redacted ms://<key>]`. The streaming redactor holds back
  the last `maxlen − 1` bytes of each chunk, so a match split across chunks (or frames) is
  still caught; stdout and stderr have separate state. Residual: the automaton's own memory is
  not zeroized (same class as the proxy's hyper buffers).

## Build

1. `ms-run`
   - `inspect`: validate argv (non-empty, UTF-8, ≤ 1024 args, ≤ 256 KiB total), the forwarded
     env (D4), normalise `argv[0]` (D3); list the keys referenced in argv and env.
   - `cwd::check(cwd, roots)` (D2); `resolve::Program` (D3).
   - `redact::{Patterns, StreamRedactor}` (D10).
   - `generic::GenericAdapter` (the fallback `RunAdapter`; D4/D5).
   - `Runner`: adapter selection (registered adapters first, generic last), `plan` (adapter
     plan + env refs + program check + redactor), `execute` (spawn with `env_clear`, argv,
     cwd, own process group, stdin pump, redacted stdout/stderr pumps, kill the group on
     cancel or timeout, exit status).
   - `client`: the shared client side of the shim and `ms run` (find refs, forward, print).
   - `src/bin/ms-shim.rs` (D6).
2. `ms-ipc` (D1), `ms-rules` (D2), `ms-scan` accessor.
3. `msd`: `daemon/run.rs` — identify session, effective rules for the cwd, per-key decision
   (`decide_run`), roots check, approvals, receipts (one per key: allowed / approved / blocked
   / denied / failed, with `argv_hash`), plan, execute, reply.
4. `ms run -- <cmd>` (D7); `ms rules --add-root/--remove-root` (D2).

## Verify (minimum; card list first)

- OUT-1: injection payloads in arguments (`; rm -rf`, `$(id)`, backticks, `| nc`, newlines,
  `&&`) reach the child as literal single arguments and never a shell (child echoes its argv).
- Split-chunk redaction: the value and each encoding split at every byte offset across two
  chunks, across three, overlapping secrets, a value repeated back-to-back; property test.
- "Agent runs `env`": through msd, `env` with a ref-bearing variable prints the minimal
  environment with the value redacted in every encoding, and nothing from the caller's or
  msd's environment (canary variables absent).
- A non-allowlisted binary is refused (and recorded as blocked); a relative `./x` is refused;
  a binary that is the shim is skipped.
- A cwd outside the key's roots is refused (including via a symlink into a root and `..`).
- Also: production key → asks the approver, denied by the stub; approved by a fake → runs;
  exit codes pass through; stdin is forwarded; a client disconnect kills the child; the shim
  passes through without a ref and doesn't loop through a second shim directory; `ms run`
  end to end against a dev msd; `roots` round-trip and loosening classification.

Done when: the above pass, `npm run build` (scripts/check.sh) is green, review and security
review converged, QA run, `PROOF.md` written, `ARI42.md` updated. No push, no PR.
