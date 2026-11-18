//! The project's name (design §4.4).
//!
//! `slug(basename(root))`: lowercase, every run of characters outside `a-z0-9` becomes `-`,
//! trimmed of `-`, cut to 40 bytes; prefixed with `p-` if it would not start with `a-z0-9`
//! (it always does after trimming, so in practice only the empty case is special: `project`).
//! A different root already using the slug gets `-` and the first 6 hex of
//! `sha256(canonical root)`, so re-running gives the same name.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Longest slug before a collision suffix.
pub const MAX_SLUG: usize = 40;

/// The slug of one path segment.
pub fn slug(name: &str) -> String {
    let mut s = String::new();
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.is_empty() && !s.ends_with('-') {
            s.push('-');
        }
    }
    let mut s: String = s.trim_end_matches('-').chars().take(MAX_SLUG).collect();
    while s.ends_with('-') {
        s.pop();
    }
    if s.is_empty() {
        return "project".to_owned();
    }
    if !s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        s.insert_str(0, "p-");
    }
    s
}

/// `<slug>-<first 6 hex of sha256(root)>`.
pub fn suffixed(base: &str, root: &Path) -> String {
    let h = Sha256::digest(root.as_os_str().as_encoded_bytes());
    format!("{base}-{}", &hex::encode(h)[..6])
}

/// The slug for `root`, given the projects already recorded as `(slug, root)`: the plain slug of
/// the root's last segment, or the suffixed one when another root has it.
pub fn choose<'a>(root: &Path, existing: impl IntoIterator<Item = (&'a str, &'a Path)>) -> String {
    let base = slug(
        &root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    let existing: Vec<(&str, &Path)> = existing.into_iter().collect();
    match existing.iter().find(|(s, _)| *s == base) {
        Some((_, r)) if *r != root => suffixed(&base, root),
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=design §4.4 slug rules: lowercase, runs of other characters become one '-',
    // trimmed, 40-byte cap, empty → "project"; every slug is a valid key-name segment;
    // fails_when=a slug has uppercase, '_', '/', a leading or trailing '-', or is too long;
    // no_claim=display names (shown through terminal_safe by the CLI)
    #[test]
    fn slug_rules() {
        for (name, want) in [
            ("shop", "shop"),
            ("My Shop_App", "my-shop-app"),
            ("--x--", "x"),
            ("日本", "project"),
            ("", "project"),
            ("A.B.C", "a-b-c"),
            ("café", "caf"),
        ] {
            assert_eq!(slug(name), want, "{name}");
        }
        let long = slug(&"a".repeat(100));
        assert_eq!(long.len(), MAX_SLUG);
        let trimmed = slug(&format!("{}-b", "a".repeat(39)));
        assert!(!trimmed.ends_with('-'), "{trimmed}");
        for s in [long, trimmed, slug("x y z")] {
            assert!(ms_core::KeyName::new(&format!("{s}/var")).is_ok(), "{s}");
        }
    }

    // protects=design §4.4 collisions: a second root with the same basename gets a deterministic
    // 6-hex suffix; the same root keeps its plain slug on re-run; fails_when=two roots share a
    // slug or a re-run renames a project; no_claim=moved-project detection (out of scope, L31)
    #[test]
    fn collision_suffix() {
        let a = Path::new("/Users/me/code/shop");
        let b = Path::new("/Users/me/old/shop");
        assert_eq!(choose(a, []), "shop");
        assert_eq!(choose(a, [("shop", a)]), "shop");
        let sb = choose(b, [("shop", a)]);
        assert!(sb.starts_with("shop-") && sb.len() == 11, "{sb}");
        assert_eq!(sb, choose(b, [("shop", a)]));
        assert_ne!(sb, suffixed("shop", a));
    }
}
