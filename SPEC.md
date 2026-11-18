# landing-site

Publish the morsec marketing landing page and docs at https://morsec.motiontic.com.

- Static site under `site/`: sources in `site/src`, a dependency-free `site/build.py` that writes
  `site/public`, and `site/wrangler.jsonc` for Cloudflare Workers Static Assets with the custom
  domain `morsec.motiontic.com`.
- Pages: `/` (landing: hero with install tabs, animated hairline figures, how it works, security,
  numbers and booking call, get started, FAQ) and `/docs`. Light and dark, phone width without
  horizontal scroll. "Book a call" goes to https://cal.com/motiontic/morsec-discovery-call.
- Security headers: CSP with no third-party scripts except Cloudflare Web Analytics, fonts from
  Google Fonts only, no framing, HSTS, nosniff, strict referrer policy.
- No change to any crate, the gate or the release.
