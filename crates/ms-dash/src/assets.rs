//! The page: plain HTML, CSS and JavaScript embedded in msd. No npm, no build step, nothing
//! fetched at run time (design §6.3; fonts are system stacks, SPEC D-1).

/// `/`.
pub const INDEX_HTML: &str = include_str!("../assets/index.html");
/// `/dash.css`.
pub const DASH_CSS: &str = include_str!("../assets/dash.css");
/// `/dash.js`.
pub const DASH_JS: &str = include_str!("../assets/dash.js");
/// `/favicon.svg`.
pub const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

/// Every asset by path, with its content type.
pub const ASSETS: &[(&str, &str, &str)] = &[
    ("/", "text/html; charset=utf-8", INDEX_HTML),
    ("/index.html", "text/html; charset=utf-8", INDEX_HTML),
    ("/dash.css", "text/css; charset=utf-8", DASH_CSS),
    ("/dash.js", "text/javascript; charset=utf-8", DASH_JS),
    ("/favicon.svg", "image/svg+xml", FAVICON_SVG),
];

/// The asset at `path`: (content type, bytes).
pub fn get(path: &str) -> Option<(&'static str, &'static [u8])> {
    ASSETS
        .iter()
        .find(|(p, _, _)| *p == path)
        .map(|(_, t, b)| (*t, b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The asset text with `//` line comments and `/* */` comments removed, so a word in a
    /// comment neither hides nor fakes a finding. Rough on purpose: strings that contain `//` are
    /// rare in these files and are checked as code.
    fn code(s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("/*") {
            out.push_str(&rest[..i]);
            rest = rest[i + 2..].split_once("*/").map_or("", |(_, r)| r);
        }
        out.push_str(rest);
        out.lines()
            .map(|l| match l.trim_start().starts_with("//") {
                true => "",
                false => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // protects=design §6.3 and §8 (XSS through a crafted variable, file or project name): no
    // asset uses an HTML sink, so every string from a file, agent or user reaches the page only
    // through textContent; fails_when=innerHTML, outerHTML, insertAdjacentHTML, document.write,
    // eval, new Function, a string timer or a javascript: URL appears in any asset;
    // no_claim=the browser's own CSP enforcement (dash_csp_on_every_response pins the header)
    #[test]
    fn dash_assets_have_no_html_sinks() {
        for (path, _, body) in ASSETS {
            let c = code(body);
            for sink in [
                "innerHTML",
                "outerHTML",
                "insertAdjacentHTML",
                "document.write",
                "eval(",
                "new Function",
                "setTimeout('",
                "setTimeout(\"",
                "setInterval('",
                "setInterval(\"",
                "javascript:",
                "createContextualFragment",
                "srcdoc",
                "DOMParser",
            ] {
                assert!(!c.contains(sink), "{path} uses {sink}");
            }
        }
        // Inline script or style would need 'unsafe-inline', which the CSP doesn't grant.
        assert!(!INDEX_HTML.contains("<script>"), "inline script");
        assert!(!INDEX_HTML.contains("style="), "inline style");
        assert!(!INDEX_HTML.contains("<style"), "inline style");
        let html = INDEX_HTML.to_ascii_lowercase();
        for (i, _) in html.match_indices(" on") {
            let attr: String = html[i + 3..]
                .chars()
                .take_while(char::is_ascii_alphabetic)
                .collect();
            assert!(
                !html[i + 3 + attr.len()..].starts_with('='),
                "inline event handler on{attr}"
            );
        }
        // The one place text reaches the DOM is textContent.
        assert!(DASH_JS.contains("textContent"));
    }

    // protects=design §6.3 and §8 (assets fetch from the network), SPEC D-1: nothing in the page
    // points outside its own origin, fonts included (system stacks, no woff2);
    // fails_when=any asset holds http://, https://, a protocol-relative URL, @import, a url()
    // that is not data:, or a font file reference; no_claim=what the user's browser extensions do
    #[test]
    fn dash_assets_have_no_external_urls() {
        for (path, _, body) in ASSETS {
            let lower = body.to_ascii_lowercase();
            // SVG's xmlns names a namespace, it is never fetched.
            let lower = lower.replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
            for bad in [
                "http://", "https://", "@import", ".woff", ".ttf", ".otf", "ws://",
            ] {
                assert!(!lower.contains(bad), "{path} contains {bad}");
            }
            // CSS url() (the script's createObjectURL( is a different word).
            for (i, _) in lower
                .match_indices("url(")
                .filter(|(i, _)| !lower[..*i].ends_with(|c: char| c.is_ascii_alphanumeric()))
            {
                let rest = lower[i + 4..].trim_start_matches(['"', '\'', ' ']);
                assert!(rest.starts_with("data:"), "{path} has a non-data url()");
            }
            assert!(
                !lower.contains("\"//") && !lower.contains("'//"),
                "{path} has a protocol-relative URL"
            );
        }
        // The script talks to its own origin only: every fetch is a relative /api/ path.
        for (i, _) in DASH_JS.match_indices("fetch(") {
            let arg = DASH_JS[i + 6..].trim_start();
            assert!(
                arg.starts_with("'/api/") || arg.starts_with("path") || arg.starts_with("url"),
                "fetch with a non-relative argument: {}",
                &arg[..arg.len().min(40)]
            );
        }
    }

    // protects=SPEC D-3 and criterion 9: L32 renders no control for Show, Copy, Replace, Delete,
    // Undo or rule edits, and the script sends no POST but the session exchange;
    // fails_when=a button for a value action appears or the page posts anywhere else;
    // no_claim=L33's actions (they arrive with their own checks)
    #[test]
    fn no_value_action_controls() {
        let c = code(DASH_JS);
        for word in [
            "'Show'",
            "'Copy'",
            "'Replace'",
            "'Delete'",
            "'Undo'",
            "/reveal",
            "/copy",
            "/replace",
            "/delete",
            "/undo",
        ] {
            assert!(!c.contains(word), "dash.js has {word}");
        }
        let posts = c.matches("method: 'POST'").count();
        assert_eq!(posts, 1, "only POST /api/session");
        assert!(c.contains("'/api/session'"));
    }
}
