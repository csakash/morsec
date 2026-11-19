//! The page: plain HTML, CSS and JavaScript embedded in msd, and the landing page's fonts
//! (vendored woff2, SIL OFL 1.1, L33 SPEC D-1). No npm, no build step, nothing fetched at run time
//! (design §6.3).

/// `/`.
pub const INDEX_HTML: &str = include_str!("../assets/index.html");
/// `/dash.css`.
pub const DASH_CSS: &str = include_str!("../assets/dash.css");
/// `/dash.js`.
pub const DASH_JS: &str = include_str!("../assets/dash.js");
/// `/favicon.svg`.
pub const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

/// A vendored font or licence file: (file name, content type, bytes, SHA-256 hex).
pub type FontFile = (&'static str, &'static str, &'static [u8], &'static str);

const WOFF2: &str = "font/woff2";
const TEXT: &str = "text/plain; charset=utf-8";

/// The fonts and their licences, served at `/fonts/<name>`. The hashes are the ones
/// `assets/fonts/SOURCES.txt` records for the files downloaded from fonts.gstatic.com and
/// github.com/google/fonts; `fonts_are_pinned` checks the bytes against them.
pub const FONTS: &[FontFile] = &[
    (
        "archivo-latin-var.woff2",
        WOFF2,
        include_bytes!("../assets/fonts/archivo-latin-var.woff2"),
        "4c98b9d490d1698ec95f2ff17a6c7d0e72691864c0c5d7bc2a2c161b45afe5ad",
    ),
    (
        "instrument-serif-latin-400.woff2",
        WOFF2,
        include_bytes!("../assets/fonts/instrument-serif-latin-400.woff2"),
        "60c06664b5a95c7de6cc3e00d1f9034d78bd1e40b564016b241674449a067d4d",
    ),
    (
        "instrument-serif-latin-400-italic.woff2",
        WOFF2,
        include_bytes!("../assets/fonts/instrument-serif-latin-400-italic.woff2"),
        "6ee678c33f388dd7ba59700ebea635deb98821baafd817b09891f7927177f702",
    ),
    (
        "ibm-plex-mono-latin-400.woff2",
        WOFF2,
        include_bytes!("../assets/fonts/ibm-plex-mono-latin-400.woff2"),
        "52de70091213c9eab340e2a7ac59e7b6b2b94e089bf69ef38479b22cfde4274c",
    ),
    (
        "ibm-plex-mono-latin-500.woff2",
        WOFF2,
        include_bytes!("../assets/fonts/ibm-plex-mono-latin-500.woff2"),
        "f17f51948d10b67d907393ccbac551912f2c2bd2c5af19be3aabe2f456f8fe54",
    ),
    (
        "OFL-Archivo.txt",
        TEXT,
        include_bytes!("../assets/fonts/OFL-Archivo.txt"),
        "108b4e57c9c796d3d38d0428ca7ee39de47ad93187302718d9b2d8864b9b716b",
    ),
    (
        "OFL-InstrumentSerif.txt",
        TEXT,
        include_bytes!("../assets/fonts/OFL-InstrumentSerif.txt"),
        "129ed7618959716959f2941fdd5b49e0ad6e6c1d78726761786a00253d865521",
    ),
    (
        "OFL-IBMPlexMono.txt",
        TEXT,
        include_bytes!("../assets/fonts/OFL-IBMPlexMono.txt"),
        "7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da",
    ),
];

/// The page's own files by path, with their content types.
pub const ASSETS: &[(&str, &str, &str)] = &[
    ("/", "text/html; charset=utf-8", INDEX_HTML),
    ("/index.html", "text/html; charset=utf-8", INDEX_HTML),
    ("/dash.css", "text/css; charset=utf-8", DASH_CSS),
    ("/dash.js", "text/javascript; charset=utf-8", DASH_JS),
    ("/favicon.svg", "image/svg+xml", FAVICON_SVG),
];

/// The asset at `path`: (content type, bytes).
pub fn get(path: &str) -> Option<(&'static str, &'static [u8])> {
    if let Some(name) = path.strip_prefix("/fonts/") {
        return FONTS
            .iter()
            .find(|(n, _, _, _)| *n == name)
            .map(|(_, t, b, _)| (*t, *b));
    }
    ASSETS
        .iter()
        .find(|(p, _, _)| *p == path)
        .map(|(_, t, b)| (*t, b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

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

    /// CSS rule blocks as (prelude, body, enclosing at-rule preludes), comments removed.
    fn css_blocks(css: &str) -> Vec<(String, String, Vec<String>)> {
        let c = code(css);
        let mut out = Vec::new();
        let mut stack: Vec<String> = Vec::new();
        let mut buf = String::new();
        let mut body_of: Option<String> = None;
        for ch in c.chars() {
            match ch {
                '{' => {
                    let pre = buf.trim().to_owned();
                    buf.clear();
                    if pre.starts_with('@') && !pre.starts_with("@font-face") {
                        stack.push(pre);
                    } else {
                        body_of = Some(pre);
                    }
                }
                '}' => {
                    if let Some(pre) = body_of.take() {
                        out.push((pre, buf.trim().to_owned(), stack.clone()));
                    } else {
                        stack.pop();
                    }
                    buf.clear();
                }
                _ => buf.push(ch),
            }
        }
        out
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

    // protects=design §6.3 and §8 (assets fetch from the network), L33 SPEC D-1: nothing in the
    // page points outside its own origin; the only url() are the vendored fonts under /fonts/;
    // fails_when=any page asset holds http://, https://, a protocol-relative URL, @import, or a
    // url() that is neither data: nor /fonts/<a vendored woff2>; no_claim=the licence texts
    // (they name their authors' sites and are plain text) and the user's browser extensions
    #[test]
    fn dash_assets_have_no_external_urls() {
        let vendored: Vec<String> = FONTS
            .iter()
            .filter(|(n, _, _, _)| n.ends_with(".woff2"))
            .map(|(n, _, _, _)| format!("/fonts/{n}"))
            .collect();
        for (path, _, body) in ASSETS {
            let lower = body.to_ascii_lowercase();
            // SVG's xmlns names a namespace, it is never fetched.
            let lower = lower.replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
            for bad in ["http://", "https://", "@import", ".ttf", ".otf", "ws://"] {
                assert!(!lower.contains(bad), "{path} contains {bad}");
            }
            // CSS url() (the script's createObjectURL( is a different word).
            for (i, _) in lower
                .match_indices("url(")
                .filter(|(i, _)| !lower[..*i].ends_with(|c: char| c.is_ascii_alphanumeric()))
            {
                let rest = lower[i + 4..].trim_start_matches(['"', '\'', ' ']);
                let target: String = rest
                    .chars()
                    .take_while(|c| !matches!(c, '\'' | '"' | ')'))
                    .collect();
                assert!(
                    target.starts_with("data:") || vendored.contains(&target),
                    "{path} has url({target})"
                );
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

    // protects=L33 SPEC D-1 and GW-2: the vendored fonts and licences are exactly the files
    // SOURCES.txt records (downloaded from the landing page's sources), by SHA-256;
    // fails_when=a font or licence file changes, or SOURCES.txt no longer lists its hash;
    // no_claim=the files' upstream provenance beyond the URLs recorded
    #[test]
    fn fonts_are_pinned() {
        let sources = include_str!("../assets/fonts/SOURCES.txt");
        assert_eq!(FONTS.len(), 8, "five fonts and three licences");
        for (name, _, bytes, sha) in FONTS {
            assert_eq!(&hex::encode(Sha256::digest(bytes)), sha, "{name} changed");
            assert!(
                sources.contains(&format!("{sha}  {name}")),
                "SOURCES.txt does not pin {name}"
            );
        }
        for (name, _, bytes, _) in FONTS.iter().filter(|f| f.0.ends_with(".woff2")) {
            assert!(bytes.starts_with(b"wOF2"), "{name} is not woff2");
            assert!(
                sources.contains("https://fonts.gstatic.com/s/"),
                "{name}: no gstatic source"
            );
        }
        assert!(sources.contains("raw.githubusercontent.com/google/fonts/"));
    }

    // protects=L33 SPEC D-1 (SIL OFL 1.1 travels with the fonts): each family's licence is
    // vendored, is the OFL 1.1, is served as text and is linked from the page's footer;
    // fails_when=a licence is missing, not OFL, served with another type, or not linked;
    // no_claim=the SBOM entry (packaging test_sbom_lists_fonts)
    #[test]
    fn fonts_have_licences() {
        for (lic, family) in [
            ("OFL-Archivo.txt", "Archivo"),
            ("OFL-InstrumentSerif.txt", "Instrument Serif"),
            ("OFL-IBMPlexMono.txt", "Plex"),
        ] {
            let (ctype, bytes) = get(&format!("/fonts/{lic}")).expect(lic);
            assert_eq!(ctype, "text/plain; charset=utf-8");
            let text = std::str::from_utf8(bytes).unwrap();
            assert!(text.contains("SIL Open Font License, Version 1.1"), "{lic}");
            assert!(text.contains(family), "{lic} names {family}");
            assert!(
                INDEX_HTML.contains(&format!("href=\"/fonts/{lic}\"")),
                "footer links {lic}"
            );
        }
        for (name, ctype, _, _) in FONTS.iter().filter(|f| f.0.ends_with(".woff2")) {
            assert_eq!(*ctype, "font/woff2", "{name}");
            assert!(get(&format!("/fonts/{name}")).is_some());
        }
        assert!(
            get("/fonts/SOURCES.txt").is_none(),
            "only fonts and licences"
        );
        assert!(get("/fonts/../dash.js").is_none());
    }

    // protects=L33 SPEC D-1: every @font-face points at a vendored file with font-display: swap,
    // each vendored woff2 is used, and the families the CSS names are the landing page's;
    // fails_when=a face refers to another file, lacks swap, or a vendored font is unused;
    // no_claim=how the browser renders them (browser QA)
    #[test]
    fn font_faces_use_only_vendored_files() {
        let faces: Vec<_> = css_blocks(DASH_CSS)
            .into_iter()
            .filter(|(p, _, _)| p == "@font-face")
            .collect();
        assert_eq!(faces.len(), 5);
        for (_, body, _) in &faces {
            assert!(body.contains("font-display: swap"), "{body}");
            let url = body
                .split("url('")
                .nth(1)
                .and_then(|r| r.split('\'').next());
            let url = url.expect("a url('…')");
            let name = url.strip_prefix("/fonts/").expect("under /fonts/");
            assert!(
                FONTS
                    .iter()
                    .any(|(n, t, _, _)| *n == name && *t == "font/woff2"),
                "{name}"
            );
        }
        for (name, _, _, _) in FONTS.iter().filter(|f| f.0.ends_with(".woff2")) {
            assert!(
                faces.iter().any(|(_, b, _)| b.contains(name)),
                "{name} unused"
            );
        }
        for fam in ["\"Archivo\"", "\"Instrument Serif\"", "\"IBM Plex Mono\""] {
            assert!(DASH_CSS.contains(fam), "{fam}");
        }
    }

    // protects=L33 SPEC D-5.1 (the Projects grid painted a light block in dark mode): no grid
    // uses the "gap as border" trick, a background in --rule behind its cells; fails_when=any
    // rule that makes a grid sets background: var(--rule); no_claim=the rendering (browser QA
    // screenshots of 1, 2 and 5 cards in dark mode)
    #[test]
    fn css_has_no_gap_painted_grids() {
        let blocks = css_blocks(DASH_CSS);
        let grids: Vec<_> = blocks
            .iter()
            .filter(|(_, b, _)| b.contains("display: grid") || b.contains("grid-template"))
            .collect();
        assert!(grids.len() >= 4, "{}", grids.len());
        for (sel, body, _) in &grids {
            let b = body.replace(' ', "");
            assert!(
                !b.contains("background:var(--rule)")
                    && !b.contains("background-color:var(--rule)"),
                "{sel} paints its gaps"
            );
            assert!(!b.contains("gap:1px"), "{sel} uses 1px gaps as rules");
        }
    }

    // protects=L33 SPEC D-5.2 (the Home counts were cut off): every grid track can shrink to the
    // screen: each minmax() starts at 0 or min(100%, …), and no fixed track is wider than the
    // page; fails_when=a grid uses minmax(280px, 1fr), repeat(4, …) of fixed tracks, or a bare
    // pixel track; no_claim=flex layouts (min-width: 0 is checked by eye in browser QA)
    #[test]
    fn css_grids_shrink() {
        let mut seen = 0;
        for (sel, body, _) in css_blocks(DASH_CSS) {
            for decl in body.split(';') {
                let Some((prop, value)) = decl.split_once(':') else {
                    continue;
                };
                if prop.trim() != "grid-template-columns" {
                    continue;
                }
                seen += 1;
                let v = value.trim();
                let mut rest = v;
                while let Some(i) = rest.find("minmax(") {
                    let arg = rest[i + 7..].trim_start();
                    assert!(
                        arg.starts_with("0,") || arg.starts_with("min(100%,"),
                        "{sel}: {v}"
                    );
                    rest = &rest[i + 7..];
                }
                // Outside minmax(), no track is a length.
                let mut stripped = v.to_owned();
                while let Some(i) = stripped.find("minmax(") {
                    let mut depth = 0;
                    let mut close = stripped.len();
                    for (j, ch) in stripped[i..].char_indices() {
                        match ch {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    close = i + j + 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    stripped.replace_range(i..close, "T");
                }
                assert!(
                    !stripped.contains("px") && !stripped.contains("em"),
                    "{sel}: a fixed track in {v}"
                );
            }
        }
        assert!(seen >= 4);
    }

    // protects=L33 SPEC D-4 and criterion 3: every input is labelled by a <label for> and no
    // input has placeholder text; all controls are made by the one field() helper;
    // fails_when=placeholder appears, or an input/select/textarea is created outside field();
    // no_claim=screen-reader output (keyboard pass in browser QA)
    #[test]
    fn inputs_are_labelled_without_placeholders() {
        for (path, _, body) in ASSETS {
            assert!(
                !body.to_ascii_lowercase().contains("placeholder"),
                "{path} uses a placeholder"
            );
        }
        let c = code(DASH_JS);
        let start = c.find("function field(").expect("field() helper");
        let end = c[start..]
            .find("\n  }\n")
            .map(|e| start + e)
            .expect("end of field()");
        let helper = &c[start..end];
        assert!(helper.contains("createElement(tag)"));
        assert!(helper.contains("setAttribute('for'"));
        let outside = format!("{}{}", &c[..start], &c[end..]);
        for tag in ["input", "select", "textarea"] {
            for form in [format!("'{tag}'"), format!("\"{tag}\"")] {
                for (i, _) in outside.match_indices(&form) {
                    let before = outside[..i].trim_end();
                    assert!(
                        before.ends_with("field(")
                            || before.ends_with(',')
                            || before.ends_with("addEventListener("),
                        "{tag} made outside field(): …{}",
                        &outside[i.saturating_sub(40)..i + form.len()]
                    );
                }
                assert!(
                    !outside.contains(&format!("createElement({form})")),
                    "createElement({form}) outside field()"
                );
                assert!(
                    !outside.contains(&format!("el({form}")),
                    "el({form}) outside field()"
                );
            }
        }
        assert!(!INDEX_HTML.contains("<input"));
    }

    // protects=L33 SPEC D-4: hover styling only where hover exists, so touch screens don't keep
    // a stuck hover state; fails_when=a :hover rule sits outside @media (hover: hover);
    // no_claim=focus styling (one :focus-visible rule, checked by eye)
    #[test]
    fn hover_only_under_hover_media() {
        let mut n = 0;
        for (sel, _, at) in css_blocks(DASH_CSS) {
            if sel.contains(":hover") {
                n += 1;
                assert!(
                    at.iter()
                        .any(|a| a.replace(' ', "") == "@media(hover:hover)"),
                    "{sel} is outside @media (hover: hover)"
                );
            }
        }
        assert!(n > 0);
        assert!(
            DASH_CSS
                .contains(":focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }")
        );
    }

    // protects=L33 SPEC D-4: transitions name their properties (background-color, color,
    // border-color, opacity) and last at most 150 ms; fails_when=transition: all, another
    // property, or a longer duration appears; no_claim=animations (none exist)
    #[test]
    fn transitions_are_named_and_short() {
        let mut n = 0;
        for (sel, body, at) in css_blocks(DASH_CSS) {
            if at.iter().any(|a| a.contains("prefers-reduced-motion")) {
                continue;
            }
            for decl in body.split(';') {
                let Some((prop, value)) = decl.split_once(':') else {
                    continue;
                };
                let prop = prop.trim();
                if !prop.starts_with("transition") {
                    continue;
                }
                assert_eq!(prop, "transition", "{sel}");
                for part in value.split(',') {
                    n += 1;
                    let words: Vec<&str> = part.split_whitespace().collect();
                    assert!(
                        matches!(
                            words.first().copied(),
                            Some("background-color" | "color" | "border-color" | "opacity")
                        ),
                        "{sel}: {part}"
                    );
                    let ms: u32 = words
                        .iter()
                        .find_map(|w| w.strip_suffix("ms").and_then(|n| n.parse().ok()))
                        .unwrap_or_else(|| panic!("{sel}: duration in ms: {part}"));
                    assert!(ms <= 150, "{sel}: {part}");
                }
            }
        }
        assert!(n > 0);
        assert!(!DASH_CSS.contains("animation:") || DASH_CSS.contains("animation: none"));
    }

    // protects=L33 SPEC D-4: with prefers-reduced-motion: reduce, no transition or animation
    // runs; fails_when=the media block is missing or doesn't switch transitions off;
    // no_claim=scroll behaviour in every browser
    #[test]
    fn reduced_motion_respected() {
        let blocks = css_blocks(DASH_CSS);
        let reduce: Vec<_> = blocks
            .iter()
            .filter(|(_, _, at)| {
                at.iter()
                    .any(|a| a.contains("prefers-reduced-motion: reduce"))
            })
            .collect();
        assert!(!reduce.is_empty());
        assert!(
            reduce
                .iter()
                .any(|(s, b, _)| s.contains('*') && b.contains("transition: none !important"))
        );
    }

    // protects=L33 SPEC D-12, criterion 9, T-91: the page never keeps a value anywhere but the
    // one element it shows it in: no localStorage, sessionStorage, indexedDB, caches, cookies
    // written by script, console output, or history entries with data; fails_when=any of those
    // appears in the script; no_claim=the browser's own memory until garbage collection
    // (residual)
    #[test]
    fn dash_js_never_stores_values() {
        let c = code(DASH_JS);
        for bad in [
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "caches.",
            "document.cookie",
            "console.",
            "pushState",
            "postMessage",
            "BroadcastChannel",
            "navigator.sendBeacon",
            "window.name",
        ] {
            assert!(!c.contains(bad), "dash.js uses {bad}");
        }
        // The one history call drops the launch token from the address bar, with no state.
        for (i, _) in c.match_indices("history.") {
            assert!(
                c[i..].starts_with("history.replaceState(null, '', location.pathname"),
                "{}",
                &c[i..i + 60]
            );
        }
        // The shown value reaches the page only as textContent of the value box.
        assert!(c.contains("box.textContent = t;"));
        // Clipboard writes are the page's own commands, never a response field.
        for (i, _) in c.match_indices("clipboard.writeText(") {
            assert!(c[i..].starts_with("clipboard.writeText(command)"));
        }
    }

    // protects=L33 SPEC D-12, T-91: a shown value is cleared after 15 s, on blur, when the page
    // is hidden, on pagehide and on navigation, and its element can't be selected (Copy is the
    // way to copy); fails_when=any of these clears is missing, or the value box allows
    // selection; no_claim=that the browser frees the string (residual)
    #[test]
    fn reveal_is_cleared() {
        let c = code(DASH_JS);
        assert!(c.contains("setTimeout(hideValue, 15000)"));
        for ev in [
            "window.addEventListener('blur', hideValue)",
            "window.addEventListener('pagehide', hideValue)",
            "window.addEventListener('hashchange', hideValue)",
            "document.addEventListener('visibilitychange'",
        ] {
            assert!(c.contains(ev), "{ev}");
        }
        let start = c.find("function render()").expect("render");
        assert!(
            c[start..start + 200].contains("hideValue();"),
            "navigation hides"
        );
        let start = c.find("function signedOut(").expect("signedOut");
        assert!(c[start..start + 100].contains("hideValue();"));
        let css = code(DASH_CSS);
        let value = css
            .split("\n.value {")
            .nth(1)
            .or_else(|| css.split(".value {").nth(1))
            .expect(".value rule");
        let body = value.split('}').next().unwrap();
        assert!(body.contains("user-select: none"), "{body}");
        // The fields values are typed into are hidden and never autocompleted.
        let start = c.find("function secretField(").expect("secretField");
        let f = &c[start..start + 500];
        for attr in [
            "'type', 'password'",
            "'autocomplete', 'off'",
            "'spellcheck', 'false'",
        ] {
            assert!(f.contains(attr), "{attr}");
        }
        assert!(
            !c.contains("'form'"),
            "value fields are never inside a <form>"
        );
    }

    /// The `--name: #rrggbb` tokens of the first `:root` block (light) and of the dark one.
    fn tokens(dark: bool) -> std::collections::HashMap<String, (f64, f64, f64)> {
        let blocks = css_blocks(DASH_CSS);
        let body = blocks
            .iter()
            .find(|(sel, _, at)| {
                sel == ":root"
                    && at.iter().any(|a| a.contains("prefers-color-scheme: dark")) == dark
            })
            .map(|(_, b, _)| b.clone())
            .expect(":root");
        let mut out = std::collections::HashMap::new();
        for decl in body.split(';') {
            let Some((k, v)) = decl.split_once(':') else {
                continue;
            };
            let v = v.trim();
            if let Some(hex) = v.strip_prefix('#').filter(|h| h.len() == 6) {
                let c = |i: usize| f64::from(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
                out.insert(k.trim().to_owned(), (c(0), c(2), c(4)));
            }
        }
        out
    }

    fn luminance((r, g, b): (f64, f64, f64)) -> f64 {
        let f = |c: f64| {
            let c = c / 255.0;
            if c <= 0.039_28 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
    }

    fn contrast(a: (f64, f64, f64), b: (f64, f64, f64)) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    // protects=L33 review Q5 (WCAG AA for small text): in light and dark mode the text tokens
    // (ink, ink-2, muted, signal, deny) reach 4.5:1 on both paper backgrounds;
    // fails_when=a token is lightened below AA; no_claim=text over images (none)
    #[test]
    fn text_tokens_meet_aa_contrast() {
        for dark in [false, true] {
            let t = tokens(dark);
            for bg in ["--paper", "--paper-2"] {
                for fg in ["--ink", "--ink-2", "--muted", "--signal", "--deny"] {
                    let c = contrast(t[fg], t[bg]);
                    assert!(c >= 4.5, "{fg} on {bg} (dark={dark}): {c:.2}");
                }
            }
        }
    }

    // protects=L33 fix round 1 (reviews R1, R5, R6, Q2, Q4, Q13): a command is removed by the
    // words the view sends, "Delete anyway" follows the answer's code, Touch ID disables only
    // the screen's buttons (Stop stays usable), [hidden] really hides, the live region is for
    // screen readers only and is cleared on navigation, and the delete confirmation ignores
    // case; fails_when=any of these regresses; no_claim=the rendering (browser QA)
    #[test]
    fn dash_js_review_fixes() {
        let c = code(DASH_JS);
        assert!(c.contains("{ words: values[i] }") && c.contains("s.command_words"));
        assert!(!c.contains("x.split(' ')"));
        assert!(c.contains("dout.dataset.code === 'referenced'"));
        assert!(!c.contains("/refer/"));
        assert!(c.contains("document.querySelectorAll('main button')"));
        assert!(!c.contains("#state button"));
        assert!(DASH_CSS.contains("[hidden] { display: none !important; }"));
        assert!(INDEX_HTML.contains("class=\"vh\" id=\"live\""));
        let start = c.find("async function render()").unwrap();
        assert!(c[start..start + 200].contains("live.textContent = '';"));
        assert!(c.contains(".toLowerCase() !== last.toLowerCase()"));
    }

    // protects=L33 fix round 2 (re-review F1, F5, SR1, QA P1, P2, P3, P5, P6, P10): a visible
    // result after every action that redraws (approve, deny, dismiss, add key, rules) and next
    // to Stop/Start; a whole-project Undo lands on Projects with its result; anything that is
    // not morsec's own request is shown open; the disclosure has a marker; the Undo confirm is
    // a row of its own; the nav fits at 375 px; messages keep "morsec" lowercase and end with
    // a full stop; Home's counts are a ruled row, frames only for the pending card and
    // failures; fails_when=any of these regresses; no_claim=the rendering (browser QA)
    #[test]
    fn dash_js_round_2_fixes() {
        let c = code(DASH_JS);
        for anchor in ["'needs', r", "'addkey', r", "'rules', r"] {
            assert!(c.contains(&format!("rerender({anchor})")), "{anchor}");
        }
        assert!(c.contains("showFlash();"));
        assert!(c.contains("stateNote = { text: 'Stopped."));
        assert!(c.contains("stateNote = { text: 'Started with Touch ID.'"));
        assert!(
            c.contains("'#/projects')"),
            "whole-project undo goes to Projects"
        );
        assert!(c.contains("if (p.expand) d.open = true;"));
        assert!(c.contains("'confirmrow'"));
        assert!(c.contains("if (!/^morsec\\b/.test(t))"));
        let i = c.find("del.appendChild(dout);").unwrap();
        assert!(c[i..].contains("del.appendChild(extra);"));
        assert!(DASH_CSS.contains("details > summary::before"));
        assert!(DASH_CSS.contains("@media (max-width: 440px)"));
        assert!(DASH_CSS.contains(".box { border-top: 1px solid var(--faint);"));
        assert!(DASH_CSS.contains(".box.warn { border: 1px solid var(--deny);"));
        assert!(DASH_CSS.contains(".box.focus { border: 1px solid var(--signal);"));
        assert!(DASH_CSS.contains("h1.keyname") && DASH_CSS.contains("overflow-wrap: anywhere; }"));
    }

    // protects=L33 fix round 3 (V1, V2, V3, V5, G3): a new result clears the others; Stop and
    // Start report in the page, not in the sticky header; Run scan shows only the Scanning box;
    // paths break only after "/" (no overflow-wrap: anywhere but on the key heading); the Undo
    // confirm row stacks on a phone; fails_when=any of these regresses; no_claim=the rendering
    // (browser QA)
    #[test]
    fn dash_js_round_3_fixes() {
        let c = code(DASH_JS);
        assert!(c.contains("function clearResults("));
        assert!(c.contains("clearResults(out);"));
        assert!(!c.contains("stateBox.appendChild(txt('span', (stateNote.err"));
        assert!(c.contains("msg.textContent = ''; msg.className = 'muted'; poll();"));
        assert!(c.contains("slashed(txt('p', null, ''), w.detail)"));
        for line in DASH_CSS
            .lines()
            .filter(|l| l.contains("overflow-wrap: anywhere"))
        {
            assert!(
                ["h1.keyname", ".cmd", "ol.argv", ".chips", "user-select"]
                    .iter()
                    .any(|ok| line.contains(ok))
                    || line
                        .trim_start()
                        .starts_with("padding: 0 var(--s-3); border"),
                "{line}"
            );
        }
        assert!(DASH_CSS.contains(".confirmrow td { display: block; }"));
    }
}
