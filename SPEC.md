# site-docs-0-2-0

Bring the morsec website (`site/src/docs.html`, and the landing page's "Get started" block in `site/src/index.html`) up to the released 0.2.0. Today the site describes 0.1.0: `ms init` only creates the vault, and the quickstart is the manual add/import/rules/connect path.

Source of truth: the 0.2.0 CHANGELOG section, `docs/ONBOARDING.md`, and `ms <cmd> --help` of the released 0.2.0 binary. Nothing on the site may claim behaviour those don't.

## Acceptance
1. **Quickstart** is the 0.2.0 path, in a project folder:
   - `ms init`, with its summary and what to do for "Needs you", "In code" and git history;
   - `ms dev -- npm run dev`;
   - a new agent session;
   - a note for a new repo with no `.env` yet.

   The old manual path moves, intact, to a "Set up by hand" section.
2. **New sections:**
   - **Projects:** what `ms init` touches and skips, key names, `ms projects`, re-running, `ms undo`.
   - **Run your app:** `ms dev`, Touch ID per run, scope of the session, refusals, Node 24, the env-value residual.
   - **Dashboard:** the five screens, what it can do, Touch ID on value actions, loopback with a single-use link.
   - **Change or remove a key:** `ms set`, `ms rm`, `ms undo`.

   Each new section is linked from the sidebar, and its search works.
3. **Commands table:** `ms init` re-described; `ms set`, `ms rm`, `ms undo`, `ms projects`, `ms dev` and `ms dashboard` added; `ms status --open` mentioned.
4. **Corrections:**
   - the curl pin example is `--version 0.2.0`;
   - the threat count is the current 110;
   - Upgrading says `ms` and `msd` must be the same version;
   - Troubleshooting covers `ms dev` on Node < 24, `ms dev` refused inside an agent, keys from another morsec build, and `ms rm` refused while a `.env` refers to the key.
5. **Landing page** "Get started" shows `brew install`, `ms init`, `ms dev -- npm run dev`, `ms dashboard`. Copy still copies only the commands.
6. **Build and checks:**
   - `python3 site/build.py` builds; `site/public` is regenerated and committed.
   - Both pages render with no console errors at 1440px and 375px, in light and dark, with no horizontal scroll at 375px.
   - The site's CSP in `_headers` is unchanged.
   - `npm run build` is clean.
7. **Not in scope:** deploying to Cloudflare. That needs the user's Wrangler login and is a separate step after merge.
