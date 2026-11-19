# SPEC: L32 `dash-core` (read-only local dashboard)

Source: `docs/design/guided-setup-dashboard.md` §5.3 (`DashOpen`), §6.1 to §6.5, §8 and §9 (L32
rows); `docs/PLAN.md` Wave 7, card L32. Builds on L31 (`ms-projects`, `ProjectList` / `ProjectGet`).

## Goal

`ms dashboard` (and `ms init` in a project, and `ms status --open`) opens a page in the user's
browser, served by msd itself on `127.0.0.1`, that shows everything morsec knows: on or stopped,
projects and their secrets (names, refs, hosts, statuses), the activity log, agents and the last
leak scan. **Read-only**: no action in L32 changes anything, and no secret value ever reaches the
browser. L33 adds the actions behind the same envelope; this loop is the envelope (who may connect)
so it can be reviewed on its own.

## Decisions

- **D-1 Fonts (deviation from design §6.3).** No font files are vendored: downloading them needs the
  user's approval, which this loop does not have. The page uses system stacks: headings
  `ui-serif, "New York", Georgia, serif` in italic, body `system-ui, -apple-system, sans-serif`,
  refs and hosts `ui-monospace, "SF Mono", Menlo, monospace`. Colour tokens are copied from
  `site/src/shared.css` (paper, ink, signal, deny, their dark variants). The design's "woff2 pinned
  by hash" test is replaced by `dash_assets_have_no_external_urls`, which covers HTML, CSS and JS
  (no `http://`, `https://`, `//host`, `@import` or `url(` pointing anywhere but `data:`).
- **D-2 No new crates.** HTTP/1.1 with `hyper` 1, `hyper-util`, `http`, `http-body-util`, `bytes`,
  the versions `ms-proxy` already locks. No npm, no build step, no framework: plain HTML, CSS and
  JS embedded with `include_str!`. Randomness from `/dev/urandom` (`ms_approve::token::random_bytes`).
- **D-3 Read-only by construction.** `ms-dash` talks to msd only through the `DashData` trait,
  whose methods all read (the one write is `record_refused`, a receipt). It returns view structs of
  names, refs, paths, hosts, counts and statuses; none has a field that can carry a value. The
  Secret screen shows "hidden" where L33 will add Show and Copy, and renders no buttons for Show,
  Copy, Replace, Delete, Undo or rules edits.
- **D-4 CSRF header on every API request, GET included** (stronger than design §6.2.4). Cookies are
  scoped by host, not port, so any other server the browser visits on `127.0.0.1` receives
  `ms_dash`. The CSRF token lives only in page memory, so a leaked cookie alone reads nothing. A
  custom header also makes every API call need a CORS preflight, which msd never answers.
  Consequence: reloading the page signs it out ("open it again with `ms dashboard`"); the token is
  never put in storage.
- **D-5 `DashOpen` is additive.** New `RequestBody::DashOpen` and `ResponseBody::Dash { port,
  launch_token }`, appended at the end of each enum; `PROTOCOL_VERSION` stays 1 (as L31 did with
  `ProjectSave`). Refused inside an agent session (`Denied`) like `Scan` and approvals. Allowed while
  stopped (the page shows "stopped").
- **D-6 Scan stays in the CLI.** Running a scan reads every value and needs Touch ID (L11), which is
  an action: L33. msd keeps the last scan report (`ScanReport`: transcript file, line, key name,
  encoding; never a value) in memory and the Scan screen shows it with the command to run.
- **D-7 Agents screen.** For Claude Code and Codex: connected (the connector's state file
  `~/.morsec/connect/<agent>.json` exists, read through `ms-connect` paths), sessions and blocks seen
  in the receipts, and msd's own checks (proxy port, CA bound, connector-settings drift alerts).
  `ms doctor` (its static checks live in the CLI) stays CLI; "re-run checks" is L33.
- **D-8 Ports.** First free port of 7311 to 7320 on `127.0.0.1` (IPv4 only). `msd --dash-port N`
  moves the range to N..N+9 (dev and tests); with `--port P` (dev daemon) the range starts at P+2.
  msd binds before it answers `DashOpen`, and returns the port it holds.
- **D-9 Receipts for refusals.** A refused connection (agent process tree, other uid, owner not
  identifiable) and a refused request (Host, Origin, Sec-Fetch-Site, CSRF, cookie, token, body,
  rate) write a receipt: key `morsec/dashboard`, mode `run`, result `blocked` (reason
  `host_not_allowed`: the dashboard is a host that caller may not reach; `ms-core`'s reasons are
  frozen), target `dashboard: <why>`, session = the caller's agent session when there is one (so it
  counts towards that session's LOG-2 alert), else `other("dashboard")` with the owner's PID.
  At most 30 refusal receipts per session per minute (an agent looping `curl` can't fill the disk);
  the rest are counted in the log.
- **D-10 Unauthenticated surface.** Without a session only `GET /`, `/dash.css`, `/dash.js`,
  `/favicon.svg` (static, no data) and `POST /api/session` are served; they share one 20 req/s
  bucket. Everything else under `/api/` needs the cookie and the CSRF header.
- **D-11 Opening the browser.** The CLI runs `/usr/bin/open http://127.0.0.1:<port>/#t=<token>[&v=<view>]`.
  The token is in the fragment, so it never reaches a request line, a log or a `Referer`; the page
  removes it from the address bar with `history.replaceState` before posting it. Debug builds only:
  `MORSEC_TEST_OPEN=<program>` replaces `open` (tests capture the URL). `ms init` opens it only in
  project mode, when stdout is a terminal and `--no-open` is not given; otherwise it prints
  `Dashboard  ms dashboard`. The printed line never contains the token.

## Acceptance criteria

1. **Listener.** msd serves the dashboard on `127.0.0.1` only, first free port in its range
   (7311..7320 by default), started on demand by `DashOpen`, and reports the port it actually bound.
   If every port in the range is taken, `DashOpen` fails with a clear message.
2. **Idle close.** The listener and every open connection close after 30 minutes without an
   authenticated request, and when msd stops; sessions and launch tokens are dropped with it. The
   next `DashOpen` starts it again.
3. **Process check per connection.** Each accepted TCP connection's owner is found from its address
   pair (`ms_session::PortResolver`, as the proxy does) and its process tree walked: an agent session,
   another uid, or an owner that can't be identified gets the connection closed before any byte is
   read or written, plus a `blocked` receipt (D-9).
4. **`DashOpen`.** Refused with `Denied` inside an agent session. Otherwise starts the listener if
   needed and returns `{ port, launch_token }`: 32 random bytes (hex), single use, valid 60 s.
5. **Session.** `POST /api/session` with `{"token": "<launch token>"}` (and the request checks of 6)
   answers `Set-Cookie: ms_dash=<32 random bytes>; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`
   and `{"csrf": "<32 random bytes>"}`. A used, expired or unknown token gets 403. Sessions live in
   msd memory only.
6. **Request checks.** `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>` (else 421).
   Every non-GET needs `Origin` equal to `http://<Host>`, `Sec-Fetch-Site: same-origin` when present,
   `Content-Type: application/json`, a body of at most 64 KiB (else 413). Every `/api/` request
   except `POST /api/session` needs the session cookie and a matching `X-Morsec-CSRF` (D-4), else
   401/403. A GET with `Sec-Fetch-Site: cross-site` is refused too. Only GET and POST are served.
7. **Headers on every response** (including errors, 404 and refusals): the CSP of design §6.2.5,
   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
   `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`,
   `Cross-Origin-Resource-Policy: same-origin`.
8. **Rate limit.** 20 requests/s per session (token bucket, burst 20); over it, 429. Unauthenticated
   requests share one 20 req/s bucket (D-10).
9. **Screens (read-only).** Home (on/stopped, pending approval with the command to answer it,
   counts: projects, protected, need a website, blocked in 24 h; agents), Projects (cards, keys not
   in a project), Project (variable, file, key, provider, tier, mode, status, last use; code findings;
   git warnings; the `ms init` re-run hint), Secret (name, provider, tier, mode, "hidden" value, where
   it is used, hosts, commands, roots, last 20 uses; no value actions), Activity (receipts table with
   filters on time, project, key, agent, result; verify the chain; export JSON or CSV saved by the
   browser), Agents (D-7), Scan (D-6). Works at 375 px wide; light and dark by
   `prefers-color-scheme`.
10. **No value reaches the browser.** No API response holds a vault value; canary tests prove it.
11. **Inert rendering.** Every string from files, agents or users is put in the page with
    `textContent` (or `setAttribute` on non-URL attributes); the assets contain no `innerHTML`,
    `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function` or string
    `setTimeout`.
12. **No external URLs.** Assets reference nothing outside the page's own origin (D-1).
13. **CLI.** `ms dashboard [PROJECT]` asks `DashOpen` and opens the URL with `open(1)`; `ms status
    --open` does the same after printing status; `ms init` in project mode opens the project's page
    (D-11). Inside an agent session each says the dashboard can't be opened from there.
14. **Parity.** Every clap subcommand of `ms` has a dashboard screen or an entry in the exemption
    list with its reason (L33-owned actions listed as exempt with reason naming L33).
15. **Docs.** Threat-model rows for the §8 L32 threats naming their tests; `ARI42.md` MCP-3, INJ-3,
    LOG-1, LOG-2, GW-2 evidence; the gate (`npm run build`) passes.

## Tests per criterion

| # | Tests |
|---|---|
| 1 | `crates/ms-dash/tests/http.rs::dash_open_reports_bound_port`, `crates/ms-dash/tests/http.rs::dash_open_fails_when_range_is_full`, `crates/ms-cli/tests/dashboard.rs::dashboard_opens_the_port_msd_bound` |
| 2 | `crates/ms-dash/tests/http.rs::dash_closes_when_idle`, `crates/ms-dash/tests/http.rs::dash_shutdown_drops_sessions` |
| 3 | `crates/ms-cli/tests/dashboard.rs::dash_refuses_agent_process_tree` (real fake-agent `claude` running `curl`), `crates/msd/src/dash.rs::conn_check_refuses_agent_other_uid_and_unknown`, `crates/msd/src/dash.rs::refused_connection_writes_blocked_receipt`, `crates/ms-dash/tests/http.rs::refused_connection_gets_no_bytes` |
| 4 | `crates/msd/src/daemon.rs::dash_open_refused_in_agent_session`, `crates/ms-dash/tests/http.rs::launch_token_single_use`, `crates/ms-dash/tests/http.rs::launch_token_expires` |
| 5 | `crates/ms-dash/tests/http.rs::session_cookie_attributes`, `crates/ms-dash/tests/http.rs::launch_token_single_use` |
| 6 | `crates/ms-dash/tests/http.rs::dash_rejects_foreign_host_header`, `crates/ms-dash/tests/http.rs::dash_rejects_cross_origin_post`, `crates/ms-dash/tests/http.rs::api_needs_cookie_and_csrf`, `crates/ms-dash/tests/http.rs::body_limit_and_methods` |
| 7 | `crates/ms-dash/tests/http.rs::dash_csp_on_every_response` |
| 8 | `crates/ms-dash/tests/http.rs::rate_limited_per_session` |
| 9 | `crates/ms-dash/tests/http.rs::api_views_round_trip`, `crates/msd/src/daemon/dash_data.rs::dashboard_views_from_records`, `crates/ms-dash/src/assets.rs::no_value_action_controls`; browser pass (PROOF, screenshots) |
| 10 | `crates/msd/src/daemon/dash_data.rs::dashboard_never_serves_a_canary`, `crates/ms-cli/tests/dashboard.rs::dashboard_end_to_end` (real `ms init` of a fixture with canary values, every API route fetched with curl from outside the agent tree) |
| 11 | `crates/ms-dash/src/assets.rs::dash_assets_have_no_html_sinks` |
| 12 | `crates/ms-dash/src/assets.rs::dash_assets_have_no_external_urls` |
| 13 | `crates/ms-cli/tests/dashboard.rs::dashboard_opens_the_port_msd_bound`, `crates/ms-cli/tests/dashboard.rs::dash_open_refused_in_agent_session_cli` |
| 14 | `crates/ms-cli/src/main.rs::dash_parity_covers_every_subcommand`, `crates/ms-dash/src/parity.rs::parity_routes_exist` |
| 15 | `scripts/threat_model_check.py` (gate), ARI-42 scan (gate) |

Every new test carries a `// protects=…; fails_when=…; no_claim=…` card.

## Out of scope (L33 or later)

- Show, Copy, Replace, Delete, Undo, rules edits, Stop/Start, Approve, Add project, Add secret,
  connect/disconnect, re-run checks, run scan from the page (L33).
- The reveal/copy rate limit (10 per 10 minutes) belongs to those actions (L33).
- `ms dev` (L34); the Project screen does not show its command until L34 lands.
- Vendored fonts (D-1). Remote access, more than one user, Linux.
