# L16 `run-ssh-git` — SSH agent and git credential helper in run mode

Card: docs/PLAN.md "L16 `run-ssh-git`". Builds on L12 (runner, `ms run`, shims) and L11
(approver). Owns `crates/ms-run/src/adapters/ssh_git/`.

## Problem

An agent needs to `git push` (or `ssh` to a host) with a deploy key or a git token, without the
private key or token ever reaching the agent, its files or its environment, and without the key
being usable for any host other than the ones the user bound. L12's generic adapter only puts a
value into an environment variable of the child, which is the wrong shape for an SSH private key
and gives no destination check.

## Behaviour

### Selecting the mechanism (D1)

- Two reserved variable names select this adapter: `MS_SSH_KEY=ms://<key>` (SSH agent) and
  `MS_GIT_CREDENTIAL=ms://<key>` (git HTTPS credential helper). As for every L12 run variable, the
  name must be in the key's rule `env` and the value must be exactly the ref.
- msd takes these variables out of the call: their value never goes into the child's
  environment. The run then uses this adapter.
- `argv[0]` must be `ssh` or `git` (a bare name, resolved from the trusted path as in L12).
  Anything else with one of these variables is refused (`denied`).
- Rules, roots, command patterns, receipts and approvals for the run are exactly L12's.

### Rules (D2)

- New per-key field `ssh_host_keys` (run keys only): known_hosts-style lines
  `HOST ssh-ed25519 BASE64`, where HOST is a host name or IP, or `[HOST]:PORT`. At most 32. Only
  `ssh-ed25519` host keys are accepted in this loop; other types are rejected with a message.
- Adding a host key is a loosening (needs L11 approval, like every other loosening); removing one
  tightens. A project `.morsec.toml` can't add host keys; a key it disables loses them.
- `ms rules <key> --add-ssh-host-key 'LINE'` / `--remove-ssh-host-key 'LINE'`; `ms rules <key>`
  shows them.
- `MS_SSH_KEY` with no host keys pinned is refused. `MS_GIT_CREDENTIAL` uses the rule's existing
  `hosts`; with none, refused.

### SSH agent (D3–D5)

- The vault value for an `MS_SSH_KEY` key is an unencrypted OpenSSH `ssh-ed25519` private key
  (`-----BEGIN OPENSSH PRIVATE KEY-----`). Other formats are refused with a message.
- For the run, msd serves an SSH agent on a Unix socket in a new 0700 directory under `$TMPDIR`.
  It accepts a connection only from the same user and only from a process in the run's process
  group (the child and what it starts). It stops, and the directory is removed, when the run ends
  (exit, timeout, `ms stop`, client gone).
- The key is read from the vault for every identities request and every sign request, parsed in
  wiped buffers and dropped right after. It is never written to disk, never put in the child's
  environment and never sent to the client: only signatures leave msd.
- Destination restriction (OpenSSH `session-bind@openssh.com`):
  - A sign request is refused unless the same agent connection first sent exactly one valid
    session-bind: an `ssh-ed25519` host key that is pinned in the rule, a valid host-key
    signature over the session id, and `is_forwarding = false`. A second bind, a forwarding bind
    or an invalid bind refuses every later sign request on that connection.
  - The data to sign must be an SSH `publickey` (or `publickey-hostbound-v00@openssh.com`)
    user-auth request for that same session id and for this key (and, when host-bound, for the
    bound host key). Anything else is refused.
  - Only `REQUEST_IDENTITIES`, the session-bind extension and `SIGN_REQUEST` are served; every
    other message (add, remove, lock, other extensions) answers failure.
  - At most 16 sign requests per run.
- ssh is always started with these options before the caller's arguments (ssh keeps the first
  value): `-F /dev/null`, `IdentityAgent=<socket>`, `IdentitiesOnly=yes`,
  `IdentityFile=<public key file>`, `UserKnownHostsFile=<pinned keys file>`,
  `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no`,
  `ForwardAgent=no`, `ProxyCommand=none`, `ProxyJump=none`, `ControlMaster=no`,
  `ControlPath=none`, `PermitLocalCommand=no`, `BatchMode=yes`, `PasswordAuthentication=no`,
  `KbdInteractiveAuthentication=no`. The public key and pinned-keys files are public data in the
  run's 0700 directory.
- Direct `ssh`: the flags `-A -F -J -S -M -I` are refused, and the destination (with `-p` or
  `ssh://…:PORT`) must match a pinned host, else refused before anything runs.
- `git`: `argv[1]` must be the subcommand (no global options such as `-c`, `-C`, `--git-dir`,
  `--exec-path`, `--config-env`). The child gets `GIT_SSH_COMMAND` (the forced ssh, quoted),
  `GIT_SSH_VARIANT=ssh`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_TERMINAL_PROMPT=0`, and through `GIT_CONFIG_COUNT`: `core.hooksPath=/dev/null`,
  `core.fsmonitor=false`, `http.sslVerify=true`, and (with `MS_GIT_CREDENTIAL`)
  `credential.helper=` (reset) followed by the morsec helper.

### Git credential helper (D7)

- New binary `ms-git-credential` (in `ms-run`), found next to `msd`. git runs it with `get`; it
  forwards git's request to a per-run credential socket served by msd (same directory, same peer
  checks as the agent socket) and prints what msd answers. `store` and `erase` do nothing.
- msd answers only `protocol=https` with a `host` (no port) matched by the rule's `hosts`, and
  only while the repository's local and worktree git config has no `http.*`, `credential.*`,
  `include.*`, `includeIf.*` or `remote.*.proxy` keys (checked when the credential is asked
  for). The answer is `username` (the request's, else `x-access-token`) and `password` (the
  value). At most 4 answers per run. Everything else gets an empty answer, and git fails.

### Receipts and approvals (D8–D9)

- Every sign request and every credential request is recorded as a receipt (allowed or
  refused): the key, mode `run`, a target naming the action, the pinned host (or HTTPS host) and
  the run's argv, the run's argv hash, rules version and approval id. If the receipt can't be
  written, the signature or credential is refused.
- A production key goes through L11's approver for the run (`approve_exact`, as in L12). The
  approval shows an effect line naming the pinned hosts (SSH) or HTTPS hosts (git credential).
  Signatures and credentials inside an approved run carry its approval id; there is no prompt
  per signature.
- After `ms stop` or a LOG-2 session stop, every sign and credential request is refused.

## Verify

1. A sign request for an unbound host is refused: a session-bind for a host key that is not
   pinned, a missing bind, a forwarding bind, a bad bind signature, and user-auth data for
   another session id are each refused, with a receipt (unit tests on the agent).
2. The private key is never on disk outside the vault: after a run (and during it), no file
   under the run directory, msd's state directory or `$TMPDIR` written by the run holds the key
   in any encoding; the child's environment does not hold it (test).
3. `git push` to a bound remote works through the agent: a throwaway `sshd` on 127.0.0.1 (as the
   current user, throwaway host and client keys, never `~/.ssh`), a local bare repository, and
   `git push` run through msd's run path; the push lands and receipts show the signature. The
   same run against a remote whose host key is not pinned fails.
4. The credential helper answers for a bound HTTPS host and refuses an unbound host, a port, a
   non-HTTPS protocol, and a repository whose config adds a credential helper or a proxy
   (`git credential fill` through the run). `git push` over HTTPS is not tested end to end (no
   local HTTPS git server); recorded as not verified.
5. Rules: `ssh_host_keys` round-trips, is rejected on non-run keys and for other key types;
   adding one classifies as loosening; projects can't add them.
6. `npm run build` green.

## Out of scope

- Non-ed25519 SSH keys and host keys (RSA, ECDSA), encrypted private keys, SSH certificates.
- HTTPS git through the swap proxy (the stronger option for tokens; see Risk).
- Packaging `ms-git-credential` (like `ms-shim`, not shipped by L10 yet).

## ARI-42

AUTH-2 (the key works only for pinned hosts and allowlisted commands), GW-1 (private key never
leaves msd; token only to the run's git for bound hosts), LOG-1 (receipt per signature and per
credential).
