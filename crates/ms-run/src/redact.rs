//! Output redaction for run mode (SPEC D10).
//!
//! [`Patterns`] holds every form a value can take in output: raw, and for values of at least
//! [`ms_scan::MIN_VALUE_LEN`] bytes also JSON-escaped, URL-encoded, hex and base64/base64url at
//! every alignment (the same encoders `ms scan` uses). One Aho–Corasick automaton finds every
//! occurrence, overlapping ones included, and the union of the matched spans is replaced with
//! `[redacted ms://<key>]`.
//!
//! [`StreamRedactor`] works on a byte stream that arrives in arbitrary chunks. It holds back the
//! last `longest pattern − 1` bytes of what it has seen, so a value split across two (or more)
//! chunks is matched once the rest arrives; [`StreamRedactor::finish`] flushes the tail. A
//! redacted span that might still grow (an overlapping value could continue past the held-back
//! tail) is held too, up to [`MAX_HOLD`] bytes.
//!
//! Residual (ARI42 GW-1): the automaton's own tables are not zeroized when dropped; every buffer
//! this module allocates that may hold value bytes is.

use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
use ms_core::KeyName;
use zeroize::Zeroizing;

/// Most bytes held back while a redacted span may still grow. Beyond this the span is emitted
/// as redacted and the stream moves on.
pub const MAX_HOLD: usize = 64 * 1024;

/// The forms of a set of values to redact.
pub struct Patterns {
    ac: Option<AhoCorasick>,
    /// Pattern index → index into `labels`.
    owner: Vec<usize>,
    /// Replacement text per key.
    labels: Vec<Vec<u8>>,
    max_len: usize,
    /// The automaton could not be built: emit nothing but a notice (fail closed).
    failed: bool,
}

impl std::fmt::Debug for Patterns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Patterns")
            .field("patterns", &self.owner.len())
            .field("keys", &self.labels.len())
            .finish_non_exhaustive()
    }
}

/// Collects values, then builds [`Patterns`].
#[derive(Default)]
pub struct PatternsBuilder {
    pats: Vec<Zeroizing<Vec<u8>>>,
    owner: Vec<usize>,
    labels: Vec<Vec<u8>>,
}

impl std::fmt::Debug for PatternsBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternsBuilder")
            .field("patterns", &self.pats.len())
            .finish_non_exhaustive()
    }
}

impl PatternsBuilder {
    /// Adds `value` (and its encodings) as `key`. An empty value adds nothing.
    pub fn add(&mut self, key: &KeyName, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        let label = format!("[redacted ms://{key}]").into_bytes();
        let idx = match self.labels.iter().position(|l| *l == label) {
            Some(i) => i,
            None => {
                self.labels.push(label);
                self.labels.len() - 1
            }
        };
        self.push(idx, value);
        let mut needles = ms_scan::Needles::new();
        if needles.add(0, value) {
            for (_, p) in needles.patterns() {
                self.push(idx, p);
            }
        }
    }

    fn push(&mut self, owner: usize, p: &[u8]) {
        if !self.pats.iter().any(|q| q[..] == *p) {
            self.pats.push(Zeroizing::new(p.to_vec()));
            self.owner.push(owner);
        }
    }

    /// Builds the automaton.
    pub fn build(self) -> Patterns {
        let max_len = self.pats.iter().map(|p| p.len()).max().unwrap_or(0);
        let ac = if self.pats.is_empty() {
            None
        } else {
            // Building fails only past the automaton's size limits, far beyond a few keys'
            // patterns. If it ever does, fail closed: everything is replaced (see `redact_all`).
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(self.pats.iter().map(|p| &p[..]))
                .ok()
        };
        Patterns {
            failed: ac.is_none() && !self.pats.is_empty(),
            ac,
            owner: self.owner,
            labels: self.labels,
            max_len,
        }
    }
}

impl Patterns {
    /// Starts a builder.
    pub fn builder() -> PatternsBuilder {
        PatternsBuilder::default()
    }

    /// No patterns: output passes through.
    pub fn empty() -> Self {
        PatternsBuilder::default().build()
    }

    /// Redacts a complete buffer in one go.
    pub fn redact_all(self: &Arc<Self>, data: &[u8]) -> Vec<u8> {
        let mut r = StreamRedactor::new(self.clone());
        let mut out = r.push(data);
        out.extend(r.finish());
        out
    }

    /// Merged `(start, end, label)` spans of every occurrence in `buf`, sorted.
    fn spans(&self, buf: &[u8]) -> Vec<(usize, usize, usize)> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut raw: Vec<(usize, usize, usize)> = ac
            .find_overlapping_iter(buf)
            .map(|m| (m.start(), m.end(), self.owner[m.pattern().as_usize()]))
            .collect();
        raw.sort_unstable();
        let mut merged: Vec<(usize, usize, usize)> = Vec::with_capacity(raw.len());
        for (s, e, k) in raw {
            match merged.last_mut() {
                Some(last) if s < last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e, k)),
            }
        }
        merged
    }
}

/// Redacts one output stream, chunk by chunk.
pub struct StreamRedactor {
    pats: Arc<Patterns>,
    carry: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for StreamRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamRedactor")
            .field("held", &self.carry.len())
            .finish_non_exhaustive()
    }
}

/// What a redactor that could not build its automaton emits instead of output.
const FAILED: &[u8] = b"[redacted: morsec could not set up output redaction]\n";

impl StreamRedactor {
    /// A redactor for `pats`.
    pub fn new(pats: Arc<Patterns>) -> Self {
        Self {
            pats,
            carry: Zeroizing::new(Vec::new()),
        }
    }

    /// Feeds a chunk; returns the bytes that are safe to emit now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.pats.failed {
            return Vec::new();
        }
        if self.pats.ac.is_none() {
            return chunk.to_vec();
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(self.carry.len() + chunk.len()));
        buf.extend_from_slice(&self.carry);
        buf.extend_from_slice(chunk);
        self.process(&buf, false)
    }

    /// Ends the stream; returns what was held back, redacted.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.pats.failed {
            return FAILED.to_vec();
        }
        let buf = std::mem::replace(&mut self.carry, Zeroizing::new(Vec::new()));
        self.process(&buf, true)
    }

    fn process(&mut self, buf: &[u8], eof: bool) -> Vec<u8> {
        let hold = if eof {
            0
        } else {
            self.pats.max_len.saturating_sub(1)
        };
        // Any occurrence starting before `cut` lies wholly inside `buf`, so it has been seen.
        let cut = buf.len().saturating_sub(hold);
        let mut out = Vec::with_capacity(buf.len());
        let mut pos = 0;
        let mut keep_from = None;
        for (s, e, k) in self.pats.spans(buf) {
            if s >= cut {
                break;
            }
            // A span reaching into the held-back tail may still grow when more bytes come (an
            // overlapping occurrence starting there). Hold it, unless that would hold too much.
            if !eof && e > cut && buf.len() - s <= MAX_HOLD {
                keep_from = Some(s);
                break;
            }
            out.extend_from_slice(&buf[pos..s]);
            out.extend_from_slice(&self.pats.labels[k]);
            pos = e;
        }
        let split = match keep_from {
            Some(s) => {
                out.extend_from_slice(&buf[pos..s]);
                s
            }
            None => {
                let split = pos.max(cut);
                out.extend_from_slice(&buf[pos..split]);
                split
            }
        };
        self.carry = Zeroizing::new(buf[split..].to_vec());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use proptest::prelude::*;

    const SECRET: &str = "sk_live/REDACT+ME=9f2c:1a";

    fn pats(values: &[(&str, &[u8])]) -> Arc<Patterns> {
        let mut b = Patterns::builder();
        for (k, v) in values {
            b.add(&KeyName::new(k).unwrap(), v);
        }
        Arc::new(b.build())
    }

    fn feed(p: &Arc<Patterns>, chunks: &[&[u8]]) -> Vec<u8> {
        let mut r = StreamRedactor::new(p.clone());
        let mut out = Vec::new();
        for c in chunks {
            out.extend(r.push(c));
        }
        out.extend(r.finish());
        out
    }

    fn contains(h: &[u8], n: &[u8]) -> bool {
        h.windows(n.len()).any(|w| w == n)
    }

    fn encodings(v: &[u8]) -> Vec<Vec<u8>> {
        vec![
            v.to_vec(),
            STANDARD.encode(v).into_bytes(),
            URL_SAFE_NO_PAD.encode(v).into_bytes(),
            hex::encode(v).into_bytes(),
            hex::encode_upper(v).into_bytes(),
            v.iter()
                .map(|&b| {
                    if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect::<String>()
                .into_bytes(),
        ]
    }

    // protects=the value and each encoding is redacted when split across two chunks at every
    // byte offset; fails_when=any split leaks the value or an encoding; no_claim=encodings other
    // than raw, base64, base64url, hex and URL
    #[test]
    fn split_at_every_offset() {
        let p = pats(&[("stripe/live", SECRET.as_bytes())]);
        for enc in encodings(SECRET.as_bytes()) {
            let text = [b"before ".as_slice(), &enc, b" after"].concat();
            for i in 0..=text.len() {
                let out = feed(&p, &[&text[..i], &text[i..]]);
                assert!(
                    !contains(&out, &enc),
                    "split {i} leaked {:?}",
                    String::from_utf8_lossy(&enc)
                );
                assert!(contains(&out, b"[redacted ms://stripe/live]"), "split {i}");
                assert!(
                    out.starts_with(b"before ") && out.ends_with(b" after"),
                    "split {i}"
                );
            }
        }
    }

    // protects=a value spread over three or more chunks (one byte at a time) is redacted;
    // fails_when=it leaks; no_claim=-
    #[test]
    fn split_into_single_bytes() {
        let p = pats(&[("k", SECRET.as_bytes())]);
        let text = format!("x{SECRET}y{SECRET}z");
        let chunks: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        let out = feed(&p, &chunks);
        assert_eq!(out, b"x[redacted ms://k]y[redacted ms://k]z");
    }

    // protects=overlapping and back-to-back values are covered by one redaction span, so no
    // tail of the second value survives; fails_when=bytes of either value remain;
    // no_claim=values that are substrings of ordinary output (that output is redacted too)
    #[test]
    fn overlapping_values() {
        let a = b"AAAAbbbbCCCC";
        let b = b"CCCCddddEEEE";
        let p = pats(&[("a", a), ("b", b)]);
        let out = feed(&p, &[b"<AAAAbbbbCC", b"CCddddEEEE>"]);
        assert_eq!(out, b"<[redacted ms://a]>");
        let out = feed(&p, &[b"AAAAbbbbCCCCAAAAbbbbCCCC"]);
        assert_eq!(out, b"[redacted ms://a][redacted ms://a]");
    }

    // protects=a short value (under 8 bytes) is still redacted raw; empty patterns pass output
    // through; fails_when=the short value leaks or clean output changes; no_claim=encodings of
    // short values (too short to match safely)
    #[test]
    fn short_and_empty() {
        let p = pats(&[("s", b"pw1")]);
        assert_eq!(feed(&p, &[b"a pw", b"1 b"]), b"a [redacted ms://s] b");
        let none = Arc::new(Patterns::empty());
        assert_eq!(feed(&none, &[b"hello ", b"world"]), b"hello world");
    }

    // protects=memory stays bounded on adversarial output (a value's repetition that keeps a
    // span growing): the held tail never exceeds MAX_HOLD plus a chunk; fails_when=the carry
    // grows with the input; no_claim=-
    #[test]
    fn hold_is_bounded() {
        let p = pats(&[("r", b"aaaaaaaa")]);
        let mut r = StreamRedactor::new(p);
        let chunk = vec![b'a'; 4096];
        let mut out = Vec::new();
        for _ in 0..200 {
            out.extend(r.push(&chunk));
            assert!(r.carry.len() <= MAX_HOLD + chunk.len());
        }
        out.extend(r.finish());
        assert!(!contains(&out, b"aaaaaaaa"));
    }

    proptest! {
        // protects=for random output around a value and random chunking, no chunk boundary
        // lets the value or an encoding through, and text without values is unchanged;
        // fails_when=any leak or alteration; no_claim=-
        #[test]
        fn random_chunking(
            pre in "[ -~]{0,40}",
            post in "[ -~]{0,40}",
            cuts in prop::collection::vec(0usize..200, 0..8),
            which in 0usize..6,
        ) {
            let p = pats(&[("k", SECRET.as_bytes())]);
            let enc = encodings(SECRET.as_bytes()).swap_remove(which);
            let text = [pre.as_bytes(), &enc, post.as_bytes()].concat();
            let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c % (text.len() + 1)).collect();
            cuts.sort_unstable();
            let mut chunks = Vec::new();
            let mut last = 0;
            for c in cuts {
                chunks.push(&text[last..c]);
                last = c;
            }
            chunks.push(&text[last..]);
            let out = feed(&p, &chunks);
            prop_assert!(!contains(&out, &enc));
            prop_assert!(!contains(&out, SECRET.as_bytes()));
            let plain = [pre.as_bytes(), post.as_bytes()].concat();
            let clean = feed(&p, &[&plain[..plain.len() / 2], &plain[plain.len() / 2..]]);
            prop_assert_eq!(clean, plain);
        }
    }
}
