//! Changed lines between two texts, for showing a plan before it is applied.
//!
//! Only changed lines are returned (no context), so lines morsec doesn't touch, which may hold
//! the user's own values, are never printed.

/// Most lines diffed on each side; bigger files are summarised.
pub const MAX_LINES: usize = 4000;

/// One changed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line<'a> {
    /// Removed: (1-based line number in the old text, text).
    Removed(usize, &'a str),
    /// Added: (1-based line number in the new text, text).
    Added(usize, &'a str),
}

/// The changed lines, in order; `None` when a side has more than [`MAX_LINES`] lines.
pub fn changed_lines<'a>(old: &'a str, new: &'a str) -> Option<Vec<Line<'a>>> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    if a.len() > MAX_LINES || b.len() > MAX_LINES {
        return None;
    }
    // Trim the common prefix and suffix, then LCS on the middle.
    let mut pre = 0;
    while pre < a.len() && pre < b.len() && a[pre] == b[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < a.len() - pre && suf < b.len() - pre && a[a.len() - 1 - suf] == b[b.len() - 1 - suf]
    {
        suf += 1;
    }
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let (n, m) = (am.len(), bm.len());
    let mut lcs = vec![0u32; (n + 1) * (m + 1)];
    let idx = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[idx(i, j)] = if am[i] == bm[j] {
                lcs[idx(i + 1, j + 1)] + 1
            } else {
                lcs[idx(i + 1, j)].max(lcs[idx(i, j + 1)])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && am[i] == bm[j] {
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[idx(i, j + 1)] >= lcs[idx(i + 1, j)]) {
            out.push(Line::Added(pre + j + 1, bm[j]));
            j += 1;
        } else {
            out.push(Line::Removed(pre + i + 1, am[i]));
            i += 1;
        }
    }
    Some(out)
}

/// Drops line pairs whose only change is a trailing comma (an entry added after them), so a
/// line morsec didn't change is not shown.
pub fn significant(lines: Vec<Line<'_>>) -> Vec<Line<'_>> {
    let text = |l: &Line<'_>| match l {
        Line::Removed(_, t) | Line::Added(_, t) => t.trim_end_matches(',').to_owned(),
    };
    let mut keep = vec![true; lines.len()];
    for i in 0..lines.len() {
        if !keep[i] || !matches!(lines[i], Line::Removed(..)) {
            continue;
        }
        if let Some(j) = (0..lines.len()).find(|&j| {
            keep[j] && matches!(lines[j], Line::Added(..)) && text(&lines[j]) == text(&lines[i])
        }) {
            keep[i] = false;
            keep[j] = false;
        }
    }
    lines
        .into_iter()
        .zip(keep)
        .filter_map(|(l, k)| k.then_some(l))
        .collect()
}

/// A settings line for display: keys and non-string values as they are, and a string value only
/// when `safe` says morsec wrote it. Anything else becomes `"…"`, so a user's own value (a token
/// in an env entry or a hook command) never reaches the terminal, or an agent's transcript.
pub fn redact(line: &str, safe: &dyn Fn(&str) -> bool) -> String {
    let b = line.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < b.len() && b[i] != b'"' {
            i += if b[i] == b'\\' { 2 } else { 1 };
        }
        let end = (i + 1).min(b.len());
        i = end;
        let lit = &line[start..end];
        let is_key = line[end..].trim_start().starts_with(':');
        let shown = is_key
            || super::json::parse(lit)
                .ok()
                .and_then(|v| v.as_str().map(safe))
                .unwrap_or(false);
        out.push_str(&line[last..start]);
        out.push_str(if shown { lit } else { "\"…\"" });
        last = end;
    }
    out.push_str(&line[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=the plan preview never shows a user's own string values: comma-only changes are
    // hidden and unknown string values are redacted, keys kept; fails_when=a value morsec didn't
    // write is printed
    #[test]
    fn preview_hides_user_values() {
        let old = "{\n  \"env\": {\n    \"OPENAI_API_KEY\": \"sk-live-SECRET\"\n  }\n}\n";
        let new = "{\n  \"env\": {\n    \"OPENAI_API_KEY\": \"sk-live-SECRET\",\n    \"MORSEC_CONNECTED\": \"claude-code\"\n  }\n}\n";
        let lines = significant(changed_lines(old, new).unwrap());
        assert_eq!(
            lines,
            vec![Line::Added(4, "    \"MORSEC_CONNECTED\": \"claude-code\"")]
        );
        let safe = |s: &str| s == "claude-code";
        assert_eq!(
            redact("    \"MORSEC_CONNECTED\": \"claude-code\",", &safe),
            "    \"MORSEC_CONNECTED\": \"claude-code\","
        );
        assert_eq!(
            redact("    \"K\": \"sk-\\\"live\",", &safe),
            "    \"K\": \"…\","
        );
        assert_eq!(redact("      \"echo tok\",", &safe), "      \"…\",");
        assert_eq!(redact("    \"port\": 4101,", &safe), "    \"port\": 4101,");
        assert_eq!(redact("\"unterminated", &safe), "\"…\"");
    }

    #[test]
    fn only_changed_lines() {
        let old = "{\n  \"a\": 1,\n  \"secret\": \"keep\"\n}\n";
        let new = "{\n  \"a\": 2,\n  \"secret\": \"keep\",\n  \"b\": 3\n}\n";
        let d = changed_lines(old, new).unwrap();
        // The unchanged first line is never shown.
        assert!(
            !d.iter()
                .any(|l| matches!(l, Line::Added(1, _) | Line::Removed(1, _)))
        );
        assert!(d.contains(&Line::Removed(2, "  \"a\": 1,")));
        assert!(d.contains(&Line::Added(2, "  \"a\": 2,")));
        assert!(d.contains(&Line::Added(4, "  \"b\": 3")));
        assert_eq!(changed_lines("x", "x").unwrap(), vec![]);
        assert_eq!(changed_lines("", "a\nb").unwrap().len(), 2);
    }
}
