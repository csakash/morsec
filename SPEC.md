# L16 `run-ssh-git` — SSH agent for ssh and git in run mode

Card: docs/PLAN.md "L16 `run-ssh-git`". Builds on L12 (runner, `ms run`, shims) and L11
(approver). Owns `crates/ms-run/src/adapters/ssh_git/`.

**Scope change during build (user decision, 2026-11-14):** the card's git credential helper for
HTTPS was built and then dropped. Code review found that a program git starts inside the run
can ask the helper for the raw token, and three rounds of fixes did not close every way to start
one. The repository config the agent can write controls what git runs. This loop ships the SSH
agent only. HTTPS git tokens belong in swap mode (msd's proxy adds the token for bound hosts and
the child never holds it); that is a follow-up.

## Problem

An agent needs to `git push` (or `ssh` to a host) with a deploy key, without the private key
ever reaching the agent, its files or its environment, and without the key being usable for any
host other than the ones the user bound. L12's generic adapter only puts a value into an
environment variable of the child, which is the wrong shape for an SSH private key and gives no
destination check.

## Behaviour

### Selecting the mechanism (D1)

- The reserved variable `MS_SSH_KEY=ms://<key>` selects this adapter. As for every L12 run
  variable, the name must be in the key's rule `env` and the value must be exactly the ref.
- msd takes the variable out of the call: its value never goes into the child's environment
  (it stays among the values the output is redacted for). The run then uses this adapter.
- `argv[0]` must be the bare name `ssh` or `git`, resolved from the trusted path as in L12. Any
  other tool with `MS_SSH_KEY` is refused (`denied`), with a receipt.
- Rules, roots, command patterns, receipts and approvals for the run are exactly L12's.

### Rules (D2)

- New per-key field `ssh_host_keys` (run keys only): known_hosts-style lines
  `HOST ssh-ed25519 BASE64`, where HOST is a host name or IP, or `[HOST]:PORT`. At most 32. Only
  `ssh-ed25519` host keys are accepted in this loop; other types are rejected with a message.
- Adding a host key is a loosening (needs L11 approval, like every other loosening); removing one
  tightens. A project `.morsec.toml` can't add host keys (the file fails to parse, which disables
  every key); a key it disables loses them.
- `ms rules <key> --add-ssh-host-key 'LINE'` / `--remove-ssh-host-key 'LINE'`; `ms rules <key>`
  shows them.
- `MS_SSH_KEY` with no host keys pinned is refused.

### SSH agent (D3–D5)

- The vault value for an `MS_SSH_KEY` key is an unencrypted OpenSSH `ssh-ed25519` private key
  (`-----BEGIN OPENSSH PRIVATE KEY-----`). Other formats are refused with a message.
- For the run, msd serves an SSH agent on a Unix socket in a new 0700 directory under `$TMPDIR`.
  It accepts a connection only from the same user and only from a process in the run's process
  group (the child and what it starts), waiting up to 1 s for the group to be known. It stops,
  and the directory is removed, when the run ends (exit, timeout, `ms stop`, client gone).
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
- Direct `ssh`: the flags `-A -F -J -S -M -I` are refused; `-o` takes only `ServerAliveInterval`,
  `ServerAliveCountMax`, `ConnectTimeout`, `ConnectionAttempts`, `LogLevel`, `RequestTTY`,
  `Compression`, `TCPKeepAlive`, `User`; the destination (with `-p` or `ssh://…:PORT`) must
  match a pinned host. Otherwise refused before anything runs.

### git (D6)

- Only `git push`, `git fetch`, `git pull` and `git ls-remote`, with the subcommand at
  `argv[1]` (no global options such as `-c`, `-C`, `--git-dir`). Submodule recursion
  (`--recurse-submodules` and every abbreviation git accepts, such as `--recurse`) and signing
  (`--signed`, `--gpg-sign`, their abbreviations, `-S`) are refused. These rules stop
  subcommands and aliases that run a command the caller chose inside the run, where it could use
  the agent.
- Before git starts, msd lists the repository's effective config
  (`git config --list --show-scope --includes`, with system and global config off) and refuses
  the run unless the repository's own files (`local`, `worktree`) set only data keys: core
  basics, `user.*`, `remote.<n>.{url,pushurl,fetch,tagopt,prune,mirror,promisor,partialclonefilter}`,
  `branch.<n>.{remote,merge,rebase,pushremote,description,vscode-merge-base}`, `lfs.*` and a
  few other inert keys. Keys that run programs, route traffic or include other files are refused
  by name in the message.
- The child gets `GIT_SSH_COMMAND` (the forced ssh, quoted), `GIT_SSH_VARIANT=ssh`,
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_PAGER=cat`, `GIT_EDITOR=true`, `GIT_SEQUENCE_EDITOR=true`, `GIT_MERGE_AUTOEDIT=no`, and
  through `GIT_CONFIG_COUNT`: `core.hooksPath=/dev/null`, `core.fsmonitor=false`,
  `http.sslVerify=true`, no submodule recursion, `gpg.program`, `gpg.ssh.program` and
  `gpg.x509.program` set to `false`, an empty `diff.external`, and the transports:
  `protocol.allow=never`, `protocol.ssh.allow=always`, and `file`, `ext`, `git`, `http`,
  `https` set to `never`.

### Receipts and approvals (D8–D9)

- Every sign request is recorded as a receipt (allowed or refused): the key, mode `run`, target
  `ssh-sign <pinned host> for: <run argv>` (with the reason when refused), the run's argv hash,
  rules version and approval id. If the receipt can't be written, nothing is signed. After the
  16th, one receipt records the limit and later requests are refused unrecorded.
- A production key goes through L11's approver for the run (`approve_exact`, as in L12). The
  approval shows an effect line naming the pinned hosts and their host-key fingerprints.
  Signatures inside an approved run carry its approval id; there is no prompt per signature.
- After `ms stop` or a LOG-2 session stop, every sign request is refused.

## Verify

1. A sign request for an unbound host is refused: a session-bind for a host key that is not
   pinned, a missing bind, a forwarding bind, a bad bind signature, and user-auth data for
   another session id are each refused, with a receipt (unit tests on the agent).
2. The private key is never on disk outside the vault: after a run (and during it), no file
   under the run directory, msd's state directory or `$TMPDIR` written by the run holds the key;
   the child's environment does not hold it (tests and QA).
3. `git push` to a bound remote works through the agent: a throwaway `sshd` on 127.0.0.1 (as the
   current user, throwaway host and client keys, never `~/.ssh`), a local bare repository, and
   `git push` run through msd's run path; the push lands and receipts show the signature. The
   same run with a key whose pin is another host key fails.
4. Rules: `ssh_host_keys` round-trips, is rejected on non-run keys and for other key types;
   adding one classifies as loosening; projects can't add them.
5. Argument and config checks: refused ssh flags and `-o` options, refused git subcommands,
   options (including abbreviations) and repository config keys; the forced git settings are in
   the plan.
6. `npm run build` green.

## Out of scope

- The git credential helper for HTTPS tokens (dropped, see above); HTTPS git through swap mode.
- Non-ed25519 SSH keys and host keys (RSA, ECDSA), encrypted private keys, SSH certificates.
- `git clone` with a morsec key (it can set the new repository's config and templates).

## ARI-42

AUTH-2 (the key signs only for pinned hosts and allowlisted commands), GW-1 (private key never
leaves msd), LOG-1 (receipt per signature).
