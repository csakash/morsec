# Guided setup and local dashboard

Status: design, agreed 2026-11-18. Built by four loops, L31 to L34 (cards in
[docs/PLAN.md](../PLAN.md) §5, Wave 7). Each loop lifts its own section of this file into its
`SPEC.md`.

## 1. Why

morsec works today, but only for someone who already thinks in terminals. To protect one Stripe key
a user types five commands and has to know what `api.stripe.com`, a tier and a swap mode are.
The people who need morsec most, those who have just started vibe coding, give up at step 4.

What they should get instead:

```
cd ~/code/shop
ms init
```

```
morsec is on.

Project   shop   (~/code/shop)
Found     14 secrets in 3 files
Protected 12  ·  2 need a website (open the dashboard to pick one)
Agents    Claude Code, Codex connected
In code   1 key written straight into src/lib/stripe.ts:4 (move it to .env)

Dashboard http://127.0.0.1:7311   (opening it now)
Run your app with:  ms dev -- npm run dev
```

No questions asked. Everything that happened is on the dashboard, and anything can be undone
there.

## 2. Decisions taken (2026-11-18)

| # | Decision | Chosen | Consequence |
|---|---|---|---|
| D1 | Show and copy real values in the dashboard | Yes, behind Touch ID on every use | Breaks ARI-42 GW-1 ("keys never reach the browser"). Recorded as an accepted exception in `ARI42.md`. Controls in §6.6 |
| D2 | Questions during project setup | None. Undo afterwards from the dashboard | `ms init` imports what the classifier calls a secret. Undo per secret or per project restores the original lines (Touch ID) |
| D3 | The user running the app themselves | Add `ms dev` | Without it, after import the user's own `npm run dev` sends `ms://` refs and fails (msd's proxy only serves agent sessions today) |
| D4 | Build split | One epic, four loops | L31 setup, L32 read-only dashboard, L33 dashboard actions, L34 `ms dev` |

## 3. Current state (verified on `main` at fa86d26)

| Piece | What exists | Gap for this design |
|---|---|---|
| `ms init` (`crates/ms-cli/src/service.rs`) | Creates the vault in the login keychain, installs the msd LaunchAgent | Knows nothing about the directory it runs in |
| `ms import` (`crates/ms-import`, `crates/ms-cli/src/import.rs`) | One `.env` file at a time: parses (`dotenv.rs`), classifies against the 157-entry catalog (`classify.rs`, `catalog/providers.toml`), shows a masked review table (`plan.rs`), rewrites the file atomically with refs (`envfile.rs`), warns if the file is in git history | Single file, needs a confirmation, key names come from the provider (`stripe/test`), not the project. The CLI reads the values and sends them over IPC |
| Key names (`crates/ms-core/src/key.rs`) | `a-z0-9-` segments separated by `/`, up to 8 segments of 63 bytes, 255 bytes in all | Fits `<project>/<var>` and `<project>/<file>/<var>` |
| Rules (`crates/ms-rules`) | MAC'd `rules.toml`; per key: mode, tier, hosts, commands, roots, env, SSH host keys, git hosts. Tighten-only `.morsec.toml` | No notion of a project |
| IPC (`crates/ms-ipc/src/protocol.rs`) | 19 requests: Status, PutKey, ListKeys, Run, RunStream, McpCall, RunInput(End), Mint, RulesGet, RulesProposeLoosen, Stop, Start, LogQuery, DoctorProbe, Scan, ApprovalPending, ApprovalDecide | No replace, delete, reveal, project or dashboard requests |
| Approvals (`crates/ms-approve`) | msd raises Touch ID through LocalAuthentication with a reason it renders itself (`render::inert`); refused inside agent sessions | Reused as is for every dashboard action that needs a person |
| Session identity (`crates/ms-session`) | Unix peer PID, and loopback source port to PID for the proxy; walks up to the outermost agent process | Reused to refuse dashboard connections from agent process trees |
| HTTP stack | `hyper` 1, `hyper-util`, `http`, `bytes` already in `ms-proxy` | No new HTTP dependency needed |
| Landing site (`site/src/shared.css`) | Tokens: `--paper #f2f0eb`, `--ink #121212`, `--signal #2340e8`, `--deny #d4301f`, dark variants; fonts Archivo, Instrument Serif, IBM Plex Mono from Google Fonts | The dashboard must not load Google Fonts (no network). Fonts are vendored |
| Menu-bar app (PLAN L25) | Deferred on 2026-11-14 to keep one approval surface | The dashboard is not a second approval surface: every approval is still msd's Touch ID sheet. It replaces L25's screen |

## 4. The two setup modes

`ms init` decides the mode from the directory it runs in. No prompt.

### 4.1 Mode detection

```
root = git rev-parse --show-toplevel (from cwd), if any
if root is $HOME or / or none:
    root = cwd if cwd has a project marker, else none
if root is none, $HOME, /, or inside ~/Library, /System, /Applications, /Volumes/* root:
    MACHINE mode
else:
    PROJECT mode at root
```

- Project markers: `package.json`, `pyproject.toml`, `requirements.txt`, `Pipfile`, `Cargo.toml`,
  `go.mod`, `Gemfile`, `composer.json`, `pom.xml`, `build.gradle(.kts)`, `deno.json(c)`,
  `wrangler.toml`, `wrangler.jsonc`, `vercel.json`, `netlify.toml`, `docker-compose.y(a)ml`,
  `compose.y(a)ml`, any `.env` or `.env.*` file.
- A git repo whose top level is `$HOME` (a dotfiles repo) counts as no repo. This is the case that
  would otherwise scan a whole home directory.
- Overrides: `ms init --machine`, `ms init --project [PATH]`, `ms init --name NAME`.
- Running `ms init` again is safe in both modes: machine steps that are done are skipped; in a
  project it rescans, imports only new values and reports what is already protected.

### 4.2 Machine mode ("set up this Mac")

1. Vault, daemon and CA trust, as `ms init` does today (macOS asks once to trust the CA).
2. Detect installed agents (`claude` or `~/.claude`, `codex` or `~/.codex`) and run
   `ms connect` for each, with no `--env` (refs come from each project's `.env`).
3. `ms doctor` (static checks only).
4. Open the dashboard on its empty state: "No projects yet. Run `ms init` inside a project, or add
   one here", with a folder path field (§6.5 Add project).

No file outside morsec's own directories is read in machine mode.

### 4.3 Project mode ("protect this project")

1. Machine steps 1 to 3, if not done yet.
2. Name the project (§4.4).
3. Scan (§4.5).
4. Import every value the classifier calls a secret (§4.6). No review table, no question (D2).
5. Write the project record (§5.2) and the agent hint block (§4.7).
6. Print the summary in §1 and open the dashboard on the project's page (`--no-open` to skip;
   never opened when stdout is not a TTY).

Steps 3 to 5 run inside msd (request `ProjectInit`), not in the CLI. Values go from the file to
the vault without crossing the socket, and the dashboard's Add project uses the same code.
`ProjectInit` is refused inside an agent session, like `Scan` and approvals.

> **Refinement (L31 SPEC D-1, D-2).** L31 runs steps 2 to 5 in `ms init` itself, not in msd: the
> logic lives in the library crate `crates/ms-projects` (walk, naming, record, MAC'd store), and
> values reach the vault through the same `IpcStore` / `PutKey` path `ms import` uses, so they
> cross the peer-verified socket exactly as they do today. There is no `ProjectInit` request;
> instead `ProjectSave { record, rules }` (refused in agent sessions and while stopped) carries
> the record and the first rules of the project's new keys, which msd checks against the catalog
> and applies after **one** approval bound to the hash of their canonical TOML (`put_key` still
> gives every new key a rule that allows nothing). L33's dashboard Add project calls the same
> library inside msd with a direct vault `KeyStore`. The summary points at `ms projects` until
> L32 and L34 land (SPEC D-3).

### 4.4 Project name

- `slug(basename(root))`: lowercase, every run of characters outside `a-z0-9` becomes `-`, trimmed
  of `-`, cut to 40 bytes, and prefixed with `p-` if it would start with something other than
  `a-z0-9`. Empty result: `project`.
- Display name: the basename as it is, shown through the inert renderer.
- Collision with another project at a different root: append `-` and the first 6 hex of
  `sha256(canonical root)`. Deterministic, so re-running gives the same name.
- A moved project (same git first-commit hash, new root) keeps its name and record; the root is
  updated after a Touch ID approval because it widens where run-mode keys may run.

### 4.5 Deep scan

The walk goes as deep as the tree does, inside hard budgets so a huge monorepo cannot hang it.

| Rule | Value |
|---|---|
| Start | project root, opened as a directory fd; every child opened with `openat` + `O_NOFOLLOW` |
| Symlinks | never followed; never cross a mount point (`st_dev` differs) |
| Skipped directories | `.git`, `node_modules`, `bower_components`, `target`, `dist`, `build`, `out`, `.next`, `.nuxt`, `.svelte-kit`, `.output`, `.vercel`, `.netlify`, `.wrangler`, `.turbo`, `.cache`, `.parcel-cache`, `coverage`, `vendor`, `.venv`, `venv`, `env`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.tox`, `.terraform`, `.gradle`, `Pods`, `DerivedData`, `.idea`, `.vscode` |
| Budgets | 200,000 entries visited; 10 s wall time; env files up to 1 MiB; source files up to 512 KiB; 5,000 source files read |
| Over budget | stop, import what was found, and say so on the summary and the dashboard ("Scan stopped after 200,000 files; run `ms init --project PATH` on a subfolder") |
| `.gitignore` | not used to skip: env files are almost always ignored |

What it looks for:

1. **Env files, imported.** `.env`, `.env.*`, `*.env`, `.dev.vars` (Cloudflare), `.envrc`
   (only `export NAME=value` lines). Parsed with the existing `ms_import::dotenv` parser.
2. **Example files, read for hints only, never imported.** `.env.example`, `.env.sample`,
   `.env.template`, `.env.dist`, `*.example`. Their variable names raise the classifier's
   confidence that the same name in a real file is a secret.
3. **Keys written into code, reported only.** Text files with source extensions (`js ts jsx tsx
   mjs cjs py rb go rs java kt swift php cs json yaml yml toml`) are matched against the catalog's
   value prefixes only (`Catalog::match_prefix`: `sk_live_`, `ghp_`, `AKIA`, `xoxb-` and so on).
   A hit is a **code finding**: file, line, provider, masked value. Never rewritten, never stored.
   The dashboard tells the user to move it into `.env` and re-run `ms init`.

### 4.6 Import without questions

Per env file, run the existing `ms_import::plan::plan` with these project defaults:

- **Key name:** `<project>/<var>` with the variable name slugged (`STRIPE_SECRET_KEY` →
  `shop/stripe-secret-key`). If the same variable has different values in different files, each
  one after the first gets a file segment: `shop/production/stripe-secret-key` from
  `.env.production`, `shop/apps-web/stripe-secret-key` from `apps/web/.env`. The same value
  in several files is stored once (the plan's existing `Reuse` action).
- **Tier:** the classifier's tier, raised (never lowered) by the file name: `.env.production`,
  `.env.prod`, `.env.live` → production. Everything else keeps the classifier's answer.
- **Mode and hosts:** from the catalog, as `ms import` does now. A secret with no known provider
  is stored with no hosts and shows "needs a website" on the dashboard. That fails closed: until a
  host is added, the ref is never swapped.
- **Run-mode roots:** database URLs (Postgres, MySQL, Redis, MongoDB) get the project root as their
  only run root.
- **Rewrite:** each file atomically with refs (existing `envfile::commit`). No plaintext backup.
- **Git history:** existing warning, kept per file on the project record and shown on the
  dashboard as "Committed to git: rotate these keys".
- **Failure:** any file that fails to parse is left untouched and listed; the others still go
  through. A vault write that fails rolls back that file's keys and leaves the file as it was.

### 4.7 Agent hint block

If `CLAUDE.md` or `AGENTS.md` exists at the root, append this block (and remove it on project
Undo). If neither exists, nothing is written.

```markdown
<!-- morsec:begin -->
## Secrets in this project

Values in `.env` files that look like `ms://shop/...` are morsec references. Keep them as they are:
do not replace them with real keys or ask for the real values. Calls to the services they belong to
work as they are. If a call is blocked, ask the user to open the morsec dashboard (`ms dashboard`).
<!-- morsec:end -->
```

The text is a fixed template; only the project slug is filled in. It gives no permission, it only
stops agents from trying to "fix" refs.

## 5. Data model

### 5.1 Keys

No change to `KeyName`. Project keys are ordinary keys whose first segment is the project slug.
Keys added outside a project (`ms add stripe/test`) appear under "Not in a project".

### 5.2 Project records

New crate `crates/ms-projects` owns `projects.toml` in msd's directory
(`~/Library/Application Support/morsec/`), MAC'd like `rules.toml` with its own HMAC key, kept
in the vault and separate from the rules key. A bad MAC fails closed: the dashboard shows the
projects as unreadable and Undo is disabled.

```toml
version = 3

[[project]]
slug = "shop"
display = "shop"
root = "/Users/me/code/shop"          # canonical, no symlinks
first_commit = "9f2c…"               # optional, for moved-project detection
created = "2026-11-18T10:02:11Z"
scan = { entries = 4211, stopped_early = false, ms = 812 }

[[project.file]]
path = ".env"                          # relative to root
git_history_commits = 2

[[project.file.secret]]
var = "STRIPE_SECRET_KEY"
line = 4
key = "shop/stripe-secret-key"
quote = "double"                       # none | single | double: restores the original form
action = "import"                      # import | reuse

[[project.finding]]                    # code findings, never values
path = "src/lib/stripe.ts"
line = 4
provider = "stripe"
masked = "sk_live_…(107)"

[[project.hint]]
path = "CLAUDE.md"
```

Limits: 500 projects, 2,000 secrets per project, 64 KiB per path list. The record never holds a
value.

### 5.3 New IPC requests

Protocol version bump. All of these are refused with `PeerRejected` when the peer is inside an
agent session, except `ProjectList` and `KeyInfo` (read-only, no values).

| Request | Approval | What it does |
|---|---|---|
| `ProjectInit { root, name?, open }` | none (moves values into the vault, which only tightens) | §4.3 steps 2 to 5 |
| `ProjectList` | none | slugs, roots, counts, statuses |
| `ProjectGet { slug }` | none | the record in §5.2 plus key status (protected, needs website, blocked uses in 24 h) |
| `ProjectUndo { slug, keys? }` | Touch ID, reason names every file to be written | writes the values back into the recorded lines (§6.7), deletes the keys, removes the hint block |
| `KeyReplace { key, value }` | Touch ID | new value, same name and rules (§6.8) |
| `KeyDelete { key }` | Touch ID | removes the value and its rule; refused while a project file still holds its ref, unless `force` |
| `KeyReveal { key }` | Touch ID every time | returns the value to the dashboard only (§6.6) |
| `KeyCopy { key }` | Touch ID every time | msd puts the value on the pasteboard itself (§6.6) |
| `DashOpen` | none | starts the dashboard listener if needed, returns `{ port, launch_token }` |
| `DevStart { argv, cwd }` | Touch ID once per run, every tier (L34 review) | L34, §7 |

## 6. The dashboard

### 6.1 Where it runs

- Served by **msd itself** (new module `crates/msd/src/dash.rs`), with handlers, routes and
  assets in a new crate `crates/ms-dash`. Values go straight from msd to the page: no third
  process holds them.
- `127.0.0.1` only, IPv4. Port 7311; if taken, the next free port in 7312 to 7320. msd binds
  first and reports the port it actually holds, so the CLI never opens a port something else holds.
- On demand: `ms dashboard`, `ms init` and `ms status --open` start it through `DashOpen`. It
  closes after 30 minutes without an authenticated request, and when msd stops.

### 6.2 Who may connect

Every check is in msd's code; none depends on the page.

1. **Process check, per TCP connection.** Map the source port to a PID (`ms-session`, as the
   proxy does), walk up the process tree. If the tree has an agent session, or the uid differs,
   close the connection and write a `blocked` receipt (it counts towards LOG-2 alerts).
2. **Launch token.** `DashOpen` (refused inside agent sessions) mints a 32-byte random token,
   single use, valid 60 s. The CLI opens `http://127.0.0.1:<port>/#t=<token>` with `open(1)`. The
   token sits in the fragment, so it never reaches a request line, a log or a `Referer`.
3. **Session cookie.** The page posts the token to `POST /api/session`; msd answers with
   `Set-Cookie: ms_dash=<32 random bytes>; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`
   and a CSRF token in the body, held in page memory only. Sessions live in msd's memory: a
   restart signs everyone out.
4. **Request checks.** `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (stops DNS
   rebinding). Every non-GET needs a matching `Origin`, `X-Morsec-CSRF`, and
   `Sec-Fetch-Site: same-origin` when the browser sends it. Bodies up to 64 KiB, JSON only.
5. **Headers on every response:** `Content-Security-Policy: default-src 'none'; script-src 'self';
   style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self';
   frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Frame-Options: DENY`,
   `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
   `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`.
6. **Rate limits:** 20 requests/s per session; reveal and copy 10 per 10 minutes in all.

### 6.3 Look and build

- Same tokens as the landing page, copied from `site/src/shared.css` into
  `crates/ms-dash/assets/dash.css` (paper, ink, signal blue, deny red, dark mode under
  `prefers-color-scheme`), hairline rules, mono for refs and hosts, serif italic for headings.
- Fonts vendored as woff2 under `crates/ms-dash/assets/fonts/` with their OFL licence files
  (Archivo, Instrument Serif, IBM Plex Mono), SHA-256 pinned in a test.
- Plain HTML, CSS and JavaScript embedded with `include_bytes!`. No npm, no build step, no
  framework, nothing fetched at run time. A test fails if any asset contains `http://` or
  `https://` outside the licence files.
- Every string that came from a file, an agent or a user (project names, variable names, paths,
  hosts, argv in the log) is put in the page with `textContent`. A test fails on any
  `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write` in the assets.
- Works at 375 px wide.

### 6.4 Screens

| Screen | Shows | Actions |
|---|---|---|
| **Home** | On or stopped, in big type. Pending approval, if any. Counts: projects, protected, need a website, blocked in 24 h. Connected agents | Stop all agents (no Touch ID). Start (Touch ID). Approve or deny the pending request (Touch ID sheet from msd) |
| **Projects** | One card per project: name, root, secrets, warnings (needs a website, in code, committed to git, scan stopped early) | Add project (path field). Open |
| **Project** | Table: variable, file, key, provider, tier, mode, status, last use. Code findings. Git warnings | Undo all. Per row: open the secret |
| **Secret** | Name, provider, tier, mode, masked value, where it is used (files, lines), hosts, commands, roots, last 20 uses | Show, Copy, Replace, Delete, Undo this one, add or remove a host or command (adding loosens: Touch ID), tier (lowering loosens: Touch ID) |
| **Activity** | `ms log` as a table with filters (time, project, key, agent, result) | Verify the chain. Export JSON or CSV (saved by the browser) |
| **Agents** | Each agent: connected or not, `ms doctor` results | Connect, disconnect, re-run checks |
| **Scan** | Transcript leak scan results (`ms scan`) | Run scan (Touch ID, as today) |

### 6.5 CLI parity

The rule: anything the CLI does for the user, the dashboard does too. Run-time agent paths are the
exception, because a person never calls them.

| CLI | Dashboard | Notes |
|---|---|---|
| `ms init` | Add project | machine-mode steps are CLI only: they install the daemon that serves the page |
| `ms add` | Secret → Add (hidden field) | |
| `ms import` | Add project / re-scan | |
| `ms rules` | Secret screen | loosen = Touch ID |
| `ms connect`, `ms disconnect` | Agents | |
| `ms log`, `ms log --verify`, `--export` | Activity | |
| `ms stats` | Home counts | |
| `ms stop`, `ms start` | Home | |
| `ms approve` | Home | |
| `ms status` | Home | |
| `ms doctor` | Agents | `--live` stays CLI only (it starts agents and spends tokens) |
| `ms scan` | Scan | |
| `ms projects` (new) | Projects | |
| `ms set` (new, replace a value) | Secret → Replace | |
| `ms rm` (new) | Secret → Delete | |
| `ms undo` (new) | Undo | |
| `ms dashboard` (new) | n/a | opens it |
| `ms run`, `ms mcp` | exempt | agent run-time paths |
| `ms dev` (L34) | exempt | needs the user's terminal; the Project screen shows the command with a copy button |

A test in `ms-dash` lists every clap subcommand and fails if one has neither a route nor an
entry in the exemption list with its reason.

### 6.6 Show and Copy (D1, ARI-42 exception)

- **Show:** `POST /api/keys/{key}/reveal` → msd raises Touch ID with the reason "Show the value
  of shop/stripe-secret-key in the dashboard" → the response holds the value, `no-store`. The
  page puts it in one element with `textContent`, clears it after 15 s, on `visibilitychange` and
  on `blur`, and never writes it to storage, the URL or the console.
- **Copy:** `POST /api/keys/{key}/copy` → Touch ID → msd writes the value to `NSPasteboard` with
  the `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` markers (clipboard
  managers skip it), then clears it after 30 s if `changeCount` has not moved. The value never
  goes to the browser.
- Every Show and Copy writes a receipt (`mechanism = reveal | copy`, `actor = dashboard`).
- Touch ID every time, test keys included. The approval token is bound to that key and that action
  and is good for one use.
- Residual, written in the exception: a program running as the user while the value is shown or on
  the clipboard can read it (screen capture, `pbpaste`, an agent driving the browser through an
  extension). The Touch ID sheet makes each use a deliberate act; it does not make the shown
  value safe from such a program.

### 6.7 Undo (D2)

- Per secret or per project, Touch ID. The sheet's reason lists every file that will receive a
  value.
- For each recorded secret: open the root as a directory fd, open the file with `openat` +
  `O_NOFOLLOW`, check it is a regular file, owned by the user, still under the root, and that the
  recorded line still holds exactly `VAR=<the ref>` in the recorded quote style. If any check fails,
  that line is skipped and listed. Otherwise write the value back with the same atomic rewrite as
  import.
- Then delete the keys that are no longer referenced, remove the hint block, and drop the project
  record (whole-project undo).

### 6.8 Replace

msd stores the new value as a new keychain item, switches the key to it, then deletes the old
item. If any step fails the old value stays in use. Rules, refs and receipts do not change.

## 7. `ms dev` (D3, L34)

Problem: after import, `.env` holds refs. Agents' commands work through msd's proxy. The user's own
`npm run dev` sends `ms://` refs to Stripe and fails, because msd only swaps for agent sessions.

```
ms dev -- npm run dev
```

1. Refused inside an agent session, and refused when `argv[0]` resolves to a known agent binary
   (`claude`, `codex`, `cursor-agent`, `gemini`).
2. `ms` sends `DevStart { argv, cwd }`. msd checks that `cwd` is inside a project root, raises Touch
   ID once if any key of the project is production, and returns a dev session id and a proxy
   credential for it.
3. `ms` spawns the command itself (so it keeps the user's terminal), with:
   - `HTTPS_PROXY` / `HTTP_PROXY` pointing at msd with the dev session credential as proxy
     username; `NODE_USE_ENV_PROXY=1` (Node 24+); the CA variables the connectors already set
     (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`);
   - for run-mode keys of this project only (database URLs and other non-HTTP values), the real
     value in the child's environment, because a database driver cannot go through an HTTP proxy.
4. msd ties the dev session to the child's PID and start time. Proxy connections from that process
   tree are served under the same rules as agents (hosts, tiers, receipts). A process inside it
   that is itself an agent is classified as an agent session by the existing walk.
5. The session ends when the child exits.

> **Refinement (L34 SPEC D-1, D-3, D-7).** The dev session is bound to the `ms dev` process
> itself (the kernel peer of `DevStart`: PID and start time), which is the child's parent: the
> same tree, with no second request naming a PID. The proxy serves the credential only to a
> process with that `ms dev` process on its parent chain and no agent above it. Run-mode values
> reach `ms dev` as raw frames after the `DevStarted` reply (names only in JSON). Dev sessions
> use only their project's keys, and may tunnel to hosts no key is bound to (the user's own
> process is not sandboxed); agents are unchanged.

Residuals, recorded in L34's PROOF: run-mode values in the dev process environment can be read by
any same-user process (as for run mode before L23), and a child the user starts from the dev
server inherits them. Node older than 24 does not read `HTTPS_PROXY` by itself: `ms dev` warns
and `ms doctor` checks the project's Node version.

## 8. Threats added to `docs/threat-model.md`

Each build loop adds its own entries with the test that proves the control (the gate checks the
test names exist).

| Threat | Control | Test (loop) |
|---|---|---|
| Agent `curl`s the dashboard | process check per connection; no token | `dash_refuses_agent_process_tree` (L32) |
| Agent runs `ms dashboard` to get a token | `DashOpen` refused in agent sessions | `dash_open_refused_in_agent_session` (L32) |
| Web page in the user's browser calls the API (CSRF) | SameSite=Strict, Origin, CSRF header | `dash_rejects_cross_origin_post` (L32) |
| DNS rebinding | Host header check | `dash_rejects_foreign_host_header` (L32) |
| XSS through a crafted variable, file or project name | `textContent` only, CSP | `dash_assets_have_no_html_sinks`, `dash_csp_on_every_response` (L32) |
| Assets fetch from the network | no external URLs | `dash_assets_have_no_external_urls` (L32) |
| Port squatting | msd binds first and reports the port; CLI opens only that | `dash_open_reports_bound_port` (L32) |
| Reveal without the person | Touch ID per use, one-use token bound to key and action | `reveal_requires_fresh_approval` (L33) |
| Reveal or copy floods | 10 per 10 minutes | `reveal_rate_limited` (L33) |
| Tampered `projects.toml` sends Undo values to another file | MAC, root-relative `openat` + `O_NOFOLLOW`, exact ref line check | `undo_refuses_tampered_record`, `undo_refuses_symlink_swap` (L33) |
| Scan hangs on a huge tree or follows a symlink out of the root | budgets, no symlinks, one device | `scan_budget_stops_early`, `scan_never_follows_symlinks` (L31) |
| `ms init` in `$HOME` reads the whole disk | machine-mode detection | `init_in_home_is_machine_mode` (L31) |
| Agent drives `ProjectInit` or `ProjectUndo` | refused in agent sessions | `project_requests_refused_in_agent_session` (L31, L33) |
| Agent starts `ms dev` to get raw run-mode values | `DevStart` refused in agent sessions and for agent binaries | `dev_refused_in_agent_session` (L34) |

## 9. ARI-42 requirements touched

| ID | How | Loop |
|---|---|---|
| GW-1, INJ-5 | Show and Copy: accepted exception (D1). Everything else keeps values out of the browser and out of agents | L33 |
| AUTH-3 | Show, Copy, Replace, Delete, Undo, loosen rules, Start, `ms dev` with production keys: Touch ID rendered by msd | L33, L34 |
| AUTH-4 | Stop from the dashboard, no approval | L33 |
| MCP-3 | The dashboard is a local API: loopback, process check, token, cookie, CSRF, rate limits | L32 |
| INJ-3 | Inert rendering in the page; CSP | L32 |
| OUT-1 | Paths for Add project and Undo validated against the root; bounded bodies | L31, L33 |
| LOG-1, LOG-2 | Receipt for every dashboard action and refused connection | L32, L33 |
| SDLC-4 | Agent hint block written to `CLAUDE.md` / `AGENTS.md` from a fixed template, removed by Undo | L31 |
| GW-2 | No new package ecosystem; vendored fonts pinned by hash; no new crates beyond what `ms-proxy` already uses | L32 |

## 10. Out of scope

- Agents running the app with a database (`npm run dev` started by an agent cannot reach Postgres
  with a ref: needs a database-protocol swap). Follow-up loop.
- Scanning `docker-compose` `environment:` literals, Kubernetes secrets, Terraform variables.
  Code findings cover hard-coded keys of known providers only.
- Rewriting code findings automatically.
- Remote access to the dashboard, more than one user, Linux (L21 will add it).
- A menu-bar app (L25 stays deferred; the dashboard takes its place).
- 1Password and Bitwarden import (L26).

## 11. Loops

```
L31 guided-init ──> L32 dash-core ──> L33 dash-actions
        └────────────────────────────> L34 ms-dev
```

L31 first: it creates the projects the dashboard shows. L32 before L33: the security envelope
(who may connect) is reviewed on its own before any action that touches a value goes behind it.
L34 needs only L31 (projects and roots) and can run beside L32 and L33.

Effort per loop (human / Claude Code): L31 3 days / 4 h; L32 3 days / 4 h; L33 3 days / 5 h;
L34 2 days / 3 h.
