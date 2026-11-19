//! Commands the page offers to copy (SPEC D-16, D-17, T-100): built by msd, every variable part
//! single-quoted, and refused outright when a part holds a control, bidi or invisible character
//! (a newline would end the command; a bidi override would make the shown text lie).

/// `s` as one POSIX shell word in single quotes (`'` written as `'\''`); `None` when it holds a
/// control, bidi or invisible character.
pub fn quote(s: &str) -> Option<String> {
    if s.chars()
        .any(|c| c.is_control() || ms_approve::render::is_invisible_or_bidi(c))
    {
        return None;
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Some(out)
}

/// `cd '<dir>' && <rest>`, or `None` when the folder can't be quoted safely.
pub fn in_folder(dir: &str, rest: &str) -> Option<String> {
    Some(format!("cd {} && {rest}", quote(dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=T-100: a folder name with a quote, $(…), backticks or a semicolon stays one inert
    // word; newlines, other controls and bidi overrides are refused; fails_when=the quoted word
    // can end the quoting or the command; no_claim=other shells than POSIX sh/zsh/bash
    #[test]
    fn quoting_is_inert() {
        assert_eq!(quote("/a b").unwrap(), "'/a b'");
        assert_eq!(quote("it's").unwrap(), "'it'\\''s'");
        assert_eq!(quote("$(rm -rf ~)`x`;y").unwrap(), "'$(rm -rf ~)`x`;y'");
        for bad in ["a\nb", "a\rb", "a\u{202e}b", "a\u{200b}b", "a\u{1b}[2Jb"] {
            assert_eq!(quote(bad), None, "{bad:?}");
        }
        assert_eq!(
            in_folder("/Users/me/shop", "ms init").unwrap(),
            "cd '/Users/me/shop' && ms init"
        );
    }
}
