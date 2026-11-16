//! Shared pieces for the `fuzz_*` property tests (hardening loop, SPEC D1–D3).
//!
//! morsec fuzzes with proptest on stable rather than cargo-fuzz on nightly, so every target runs
//! in the local gate. To get close to what a coverage-guided fuzzer's corpus gives, a target mixes
//! grammar-aware generators with [`mutated`] seeds from a committed corpus directory.
//!
//! - [`config`]: the case count comes from `MORSEC_FUZZ_CASES` (default: the target's own small
//!   count), so `cargo test` stays fast, the gate's fuzz step runs more, and a long local session
//!   is the same test with a large number.
//! - [`seeds`] / [`corpus`]: every file in `fuzz/corpus/<name>` (or any directory), sorted by name. An empty or missing corpus panics:
//!   a target must never silently lose its seeds.
//! - [`mutated`]: a seed with up to eight byte-level edits (flip, insert, delete, duplicate,
//!   splice from another seed, truncate, insert a dictionary token).
//!
//! Dev-only: used as a dev-dependency, never linked into `ms` or `msd`.

use std::path::Path;

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::Config;

/// Environment variable that sets the number of cases for every `fuzz_*` test.
pub const CASES_VAR: &str = "MORSEC_FUZZ_CASES";

/// The case count: `MORSEC_FUZZ_CASES` when it is a positive integer, else `default`.
pub fn cases(default: u32) -> u32 {
    parse_cases(std::env::var(CASES_VAR).ok().as_deref(), default)
}

fn parse_cases(v: Option<&str>, default: u32) -> u32 {
    v.and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

/// A proptest config with [`cases`] cases. Failures are persisted next to the test source (the
/// proptest default), and those files are committed as regression seeds.
pub fn config(default: u32) -> Config {
    Config {
        cases: cases(default),
        // Shrinking a long session's failure should not take longer than finding it.
        max_shrink_iters: 4096,
        ..Config::default()
    }
}

/// Reads every regular file in `dir` (sorted by name) as one seed.
///
/// # Panics
/// If the directory is missing, unreadable or holds no files.
pub fn corpus(dir: impl AsRef<Path>) -> Vec<Vec<u8>> {
    let dir = dir.as_ref();
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("fuzz corpus {} unreadable: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    names.sort();
    let seeds: Vec<Vec<u8>> = names
        .iter()
        .map(|p| std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .collect();
    assert!(!seeds.is_empty(), "fuzz corpus {} is empty", dir.display());
    seeds
}

/// The committed seed corpus `fuzz/corpus/<name>` at the workspace root (L24 owns `fuzz/`), shared
/// by the stable `fuzz_*` proptests and the nightly cargo-fuzz harnesses in `fuzz/`.
///
/// # Panics
/// As [`corpus`].
pub fn seeds(name: &str) -> Vec<Vec<u8>> {
    corpus(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus")
            .join(name),
    )
}

/// One byte-level edit.
#[derive(Debug, Clone)]
enum Edit {
    Flip(Index, u8),
    Set(Index, u8),
    Insert(Index, Vec<u8>),
    Delete(Index, usize),
    Duplicate(Index, usize),
    Splice(Index, Index, Index, usize),
    Truncate(Index),
    Token(Index, Index),
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<Index>(), 0u8..8).prop_map(|(i, b)| Edit::Flip(i, b)),
        (any::<Index>(), any::<u8>()).prop_map(|(i, b)| Edit::Set(i, b)),
        (any::<Index>(), prop::collection::vec(any::<u8>(), 1..8))
            .prop_map(|(i, v)| Edit::Insert(i, v)),
        (any::<Index>(), 1usize..16).prop_map(|(i, n)| Edit::Delete(i, n)),
        (any::<Index>(), 1usize..32).prop_map(|(i, n)| Edit::Duplicate(i, n)),
        (any::<Index>(), any::<Index>(), any::<Index>(), 1usize..64)
            .prop_map(|(a, b, c, n)| Edit::Splice(a, b, c, n)),
        any::<Index>().prop_map(Edit::Truncate),
        (any::<Index>(), any::<Index>()).prop_map(|(i, t)| Edit::Token(i, t)),
    ]
}

/// Position in `0..=len` from an index.
fn at(i: &Index, len: usize) -> usize {
    i.index(len + 1)
}

fn apply(mut buf: Vec<u8>, edits: &[Edit], seeds: &[Vec<u8>], dict: &[&[u8]]) -> Vec<u8> {
    for e in edits {
        match e {
            Edit::Flip(i, bit) if !buf.is_empty() => {
                let p = i.index(buf.len());
                buf[p] ^= 1 << bit;
            }
            Edit::Set(i, b) if !buf.is_empty() => {
                let p = i.index(buf.len());
                buf[p] = *b;
            }
            Edit::Insert(i, v) => {
                let p = at(i, buf.len());
                buf.splice(p..p, v.iter().copied());
            }
            Edit::Delete(i, n) if !buf.is_empty() => {
                let p = i.index(buf.len());
                let end = (p + n).min(buf.len());
                buf.drain(p..end);
            }
            Edit::Duplicate(i, n) if !buf.is_empty() => {
                let p = i.index(buf.len());
                let end = (p + n).min(buf.len());
                let chunk = buf[p..end].to_vec();
                buf.splice(end..end, chunk);
            }
            Edit::Splice(dst, which, src, n) => {
                let other = &seeds[which.index(seeds.len())];
                if !other.is_empty() {
                    let s = src.index(other.len());
                    let end = (s + n).min(other.len());
                    let p = at(dst, buf.len());
                    buf.splice(p..p, other[s..end].iter().copied());
                }
            }
            Edit::Truncate(i) => {
                let p = at(i, buf.len());
                buf.truncate(p);
            }
            Edit::Token(i, t) if !dict.is_empty() => {
                let tok = dict[t.index(dict.len())];
                let p = at(i, buf.len());
                buf.splice(p..p, tok.iter().copied());
            }
            _ => {}
        }
    }
    buf
}

/// A seed from `seeds`, unchanged or with up to eight byte-level edits. `dict` holds tokens worth
/// inserting whole (keywords, delimiters, placeholders); it may be empty.
///
/// # Panics
/// If `seeds` is empty.
pub fn mutated(
    seeds: Vec<Vec<u8>>,
    dict: &'static [&'static [u8]],
) -> impl Strategy<Value = Vec<u8>> {
    assert!(!seeds.is_empty(), "mutated() needs at least one seed");
    let seeds = std::sync::Arc::new(seeds);
    (any::<Index>(), prop::collection::vec(edit(), 0..8)).prop_map(move |(pick, edits)| {
        let base = seeds[pick.index(seeds.len())].clone();
        apply(base, &edits, &seeds, dict)
    })
}

/// [`mutated`], made into a `String` (invalid UTF-8 replaced), for parsers that take `&str`.
pub fn mutated_str(
    seeds: Vec<Vec<u8>>,
    dict: &'static [&'static [u8]],
) -> impl Strategy<Value = String> {
    mutated(seeds, dict).prop_map(|b| String::from_utf8_lossy(&b).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    // protects=the case count follows MORSEC_FUZZ_CASES and falls back on bad values;
    // fails_when=a bad value is used or a good one ignored; no_claim=proptest itself
    #[test]
    fn cases_from_env() {
        assert_eq!(parse_cases(Some(" 40 "), 7), 40);
        assert_eq!(parse_cases(Some("0"), 7), 7);
        assert_eq!(parse_cases(Some("lots"), 7), 7);
        assert_eq!(parse_cases(None, 7), 7);
    }

    // protects=mutation never panics, including on an empty seed, and no edits is the identity;
    // fails_when=apply panics or changes an unedited seed; no_claim=fuzzing power
    #[test]
    fn mutation_is_total() {
        let seeds = vec![b"KEY=value\n".to_vec(), Vec::new(), b"x".to_vec()];
        let s = mutated(seeds.clone(), &[b"=", b"\n"]);
        let mut runner = TestRunner::deterministic();
        for _ in 0..2000 {
            let _ = s.new_tree(&mut runner).unwrap().current();
        }
        // With no edits a seed comes back unchanged.
        assert_eq!(apply(b"abc".to_vec(), &[], &seeds, &[]), b"abc");
    }

    // protects=a corpus directory loads every file, sorted; fails_when=a file is skipped or an
    // empty corpus is accepted; no_claim=the committed corpora (each target reads its own)
    #[test]
    fn corpus_loads_and_refuses_empty() {
        let d = tempfile_dir();
        std::fs::write(d.join("b"), b"2").unwrap();
        std::fs::write(d.join("a"), b"1").unwrap();
        assert_eq!(corpus(&d), vec![b"1".to_vec(), b"2".to_vec()]);
        let empty = d.join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(std::panic::catch_unwind(|| corpus(&empty)).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ms-fuzz-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
