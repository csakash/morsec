# morsec site

The marketing page and docs at https://morsec.motiontic.com, served as static files by Cloudflare
Workers Static Assets (worker `morsec-site`).

- `src/`: the pages (`index.html`, `docs.html`), `shared.css`, the figures (`figures.js`) and the
  hairline kernel (`kernel.js`, from `@lucasmarkes/hairline`, MIT), plus monochrome brand icons
  from Simple Icons (CC0).
- `static/`: `_headers` (security headers and CSP), `favicon.svg`, `404.html`, `robots.txt`.
- `public/`: the build output that gets deployed. Never edit it by hand.

Build and deploy (needs Python 3 and a Wrangler login with Workers write access):

```bash
python3 site/build.py
cd site && npx wrangler@4 deploy
```

`npx wrangler@4 dev --local --port 8791` serves `public/` with the real headers for a local check.
