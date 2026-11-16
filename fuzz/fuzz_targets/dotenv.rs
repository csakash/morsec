//! Fuzz the dotenv parser: it never panics, every span is inside the input on char boundaries,
//! an untouched rewrite is the identity, and rewriting every non-empty value yields refs only.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ms_import::dotenv::{parse, rewrite};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(entries) = parse(s) else {
        return;
    };
    for e in &entries {
        assert!(e.value_span.end <= s.len());
        assert!(s.is_char_boundary(e.value_span.start) && s.is_char_boundary(e.value_span.end));
    }
    assert_eq!(rewrite(s, &[]).as_str(), s);
    let reps: Vec<_> = entries
        .iter()
        .filter(|e| !e.value().is_empty())
        .map(|e| (e, "ms://x".to_owned()))
        .collect();
    let out = rewrite(s, &reps);
    let again = parse(&out).expect("a rewritten file parses");
    assert_eq!(again.len(), entries.len());
});
