//! Finds secret values in agent transcripts (L09, `ms scan`).
//!
//! [`Needles`] turns each value into the byte strings it can appear as in a transcript: raw,
//! JSON-escaped, URL-encoded, hex, and base64/base64url at every byte alignment (so a value
//! inside a larger base64 blob is found too). [`scan_reader`] streams a file through them in
//! fixed-size chunks and reports `(line, key, encoding)`, never the bytes that matched.
//!
//! This runs inside msd: the values never leave the daemon. Every buffer that holds a value, an
//! encoding of one, or file bytes that may contain one is zeroized when dropped.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use memchr::memmem;
use zeroize::Zeroizing;

/// Values shorter than this are not scanned: they would match all over a transcript.
pub const MIN_VALUE_LEN: usize = 8;
/// Bytes read per step. Memory per scan stays near this whatever the file size.
pub const CHUNK: usize = 1 << 20;
/// Distinct hits kept per file.
pub const MAX_HITS_PER_FILE: usize = 1000;
/// Deepest directory level walked under a root.
pub const MAX_DEPTH: usize = 32;

/// How a value appeared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// As is.
    Raw,
    /// Inside a JSON string, with escapes.
    Json,
    /// Percent-encoded.
    Url,
    /// Hex, either case.
    Hex,
    /// Standard base64, any alignment, with or without padding.
    Base64,
    /// URL-safe base64, any alignment, with or without padding.
    Base64Url,
}

impl Encoding {
    /// Short name for output.
    pub fn label(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Json => "json-escaped",
            Encoding::Url => "url-encoded",
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
            Encoding::Base64Url => "base64url",
        }
    }
}

struct Needle {
    key: usize,
    encoding: Encoding,
    bytes: Zeroizing<Vec<u8>>,
}

/// The byte strings to look for. `Debug` shows counts only.
#[derive(Default)]
pub struct Needles {
    list: Vec<Needle>,
    max_len: usize,
}

impl std::fmt::Debug for Needles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Needles")
            .field("count", &self.list.len())
            .finish_non_exhaustive()
    }
}

fn url_encode(value: &[u8], upper: bool) -> Zeroizing<Vec<u8>> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() * 3));
    for &b in value {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(digits[usize::from(b >> 4)]);
            out.push(digits[usize::from(b & 0xf)]);
        }
    }
    out
}

/// The base64 characters fully determined by `value` when it starts `shift` bytes into a
/// larger encoded blob (shift 0, 1 or 2); characters that also depend on the unknown bytes
/// around it are dropped. Padding is never part of the result, so padded and unpadded forms
/// both match.
fn base64_core(value: &[u8], shift: usize, url: bool) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; shift]);
    buf.extend_from_slice(value);
    let enc = Zeroizing::new(if url {
        URL_SAFE_NO_PAD.encode(&buf[..])
    } else {
        STANDARD_NO_PAD.encode(&buf[..])
    });
    let total_bits = 8 * buf.len();
    let start = (8 * shift).div_ceil(6);
    let end = total_bits / 6;
    Zeroizing::new(enc.as_bytes()[start..end.max(start)].to_vec())
}

impl Needles {
    /// No needles.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every encoding of `value`, reported as `key`. Returns false (and adds nothing)
    /// when the value is shorter than [`MIN_VALUE_LEN`].
    pub fn add(&mut self, key: usize, value: &[u8]) -> bool {
        if value.len() < MIN_VALUE_LEN {
            return false;
        }
        let mut cands: Vec<(Encoding, Zeroizing<Vec<u8>>)> =
            vec![(Encoding::Raw, Zeroizing::new(value.to_vec()))];
        if let Ok(s) = std::str::from_utf8(value)
            && let Ok(j) = serde_json::to_string(s).map(Zeroizing::new)
        {
            let inner = &j.as_bytes()[1..j.len() - 1];
            cands.push((Encoding::Json, Zeroizing::new(inner.to_vec())));
        }
        cands.push((Encoding::Url, url_encode(value, true)));
        cands.push((Encoding::Url, url_encode(value, false)));
        cands.push((
            Encoding::Hex,
            Zeroizing::new(Zeroizing::new(hex::encode(value)).as_bytes().to_vec()),
        ));
        cands.push((
            Encoding::Hex,
            Zeroizing::new(Zeroizing::new(hex::encode_upper(value)).as_bytes().to_vec()),
        ));
        for shift in 0..3 {
            cands.push((Encoding::Base64, base64_core(value, shift, false)));
        }
        for shift in 0..3 {
            cands.push((Encoding::Base64Url, base64_core(value, shift, true)));
        }
        for (encoding, bytes) in cands {
            if bytes.len() < MIN_VALUE_LEN
                || self
                    .list
                    .iter()
                    .any(|n| n.key == key && n.bytes[..] == bytes[..])
            {
                continue;
            }
            self.max_len = self.max_len.max(bytes.len());
            self.list.push(Needle {
                key,
                encoding,
                bytes,
            });
        }
        true
    }

    /// True when nothing would be searched.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Number of byte strings searched.
    pub fn len(&self) -> usize {
        self.list.len()
    }
}

/// One match: where, which key, which form. Never the matched bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hit {
    /// 1-based line number.
    pub line: u64,
    /// The key index given to [`Needles::add`].
    pub key: usize,
    /// How the value appeared.
    pub encoding: Encoding,
}

/// The result of scanning one stream.
#[derive(Debug, Clone, Default)]
pub struct StreamScan {
    /// Distinct hits in line order, at most [`MAX_HITS_PER_FILE`].
    pub hits: Vec<Hit>,
    /// Bytes read.
    pub bytes: u64,
    /// False when `stop` cut the scan short.
    pub complete: bool,
}

fn read_full(r: &mut impl Read, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while !buf.is_empty() {
        match r.read(buf) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                buf = &mut buf[k..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Streams `r` through the needles in [`CHUNK`]-sized steps. `stop` is asked before each step;
/// returning true ends the scan with `complete: false`.
pub fn scan_reader(
    needles: &Needles,
    mut r: impl Read,
    stop: &mut dyn FnMut() -> bool,
) -> io::Result<StreamScan> {
    let mut out = StreamScan {
        complete: true,
        ..StreamScan::default()
    };
    if needles.is_empty() {
        return Ok(out);
    }
    let finders: Vec<memmem::Finder<'_>> = needles
        .list
        .iter()
        .map(|n| memmem::Finder::new(&n.bytes[..]))
        .collect();
    let keep = needles.max_len.saturating_sub(1);
    // Capacity is reserved once, so the buffer never reallocates and leaves a copy behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(CHUNK + keep));
    let mut searched = 0usize;
    let mut line_base: u64 = 1;
    let mut hits = BTreeSet::new();
    loop {
        if stop() {
            out.complete = false;
            break;
        }
        let old = buf.len();
        buf.resize(old + CHUNK, 0);
        let n = read_full(&mut r, &mut buf[old..])?;
        buf.truncate(old + n);
        if n == 0 {
            break;
        }
        out.bytes += n as u64;
        let newlines: Vec<usize> = memchr::memchr_iter(b'\n', &buf[..]).collect();
        for (needle, finder) in needles.list.iter().zip(&finders) {
            for start in finder.find_iter(&buf[..]) {
                // Wholly inside the overlap: already found in the previous step.
                if start + needle.bytes.len() <= searched {
                    continue;
                }
                if hits.len() >= MAX_HITS_PER_FILE {
                    break;
                }
                let line = line_base + newlines.partition_point(|&p| p < start) as u64;
                hits.insert(Hit {
                    line,
                    key: needle.key,
                    encoding: needle.encoding,
                });
            }
        }
        let tail = buf.len().saturating_sub(keep);
        line_base += newlines.partition_point(|&p| p < tail) as u64;
        buf.copy_within(tail.., 0);
        let kept = buf.len() - tail;
        buf.truncate(kept);
        searched = kept;
    }
    out.hits = hits.into_iter().collect();
    Ok(out)
}

/// Every hit in an in-memory buffer (tests and small captures).
pub fn find_in(needles: &Needles, haystack: &[u8]) -> Vec<Hit> {
    scan_reader(needles, haystack, &mut || false)
        .map(|s| s.hits)
        .unwrap_or_default()
}

/// Opens `path` only if it is a regular file: never through a symlink, and never blocking on a
/// FIFO swapped in after the walk looked at it.
pub fn open_regular(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(f)
}

/// The transcript files under some roots.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    /// Regular `*.jsonl` / `*.json` files, sorted.
    pub files: Vec<PathBuf>,
    /// Things worth telling the user (unreadable directories, the file cap).
    pub notes: Vec<String>,
    /// True when `max_files` stopped the walk.
    pub truncated: bool,
}

fn is_transcript(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("jsonl" | "json")
    )
}

/// Lists transcript files under `roots`. Symlinks are never followed (a link could point the
/// daemon anywhere); a missing root is skipped.
pub fn transcript_files(roots: &[PathBuf], max_files: usize) -> Walk {
    let mut w = Walk::default();
    let mut unreadable = 0usize;
    for root in roots {
        match std::fs::symlink_metadata(root) {
            Ok(m) if m.is_dir() => {}
            _ => continue,
        }
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            for e in entries.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                let p = e.path();
                if ft.is_dir() {
                    if depth < MAX_DEPTH {
                        stack.push((p, depth + 1));
                    }
                } else if ft.is_file() && is_transcript(&p) {
                    if w.files.len() >= max_files {
                        w.truncated = true;
                        break;
                    }
                    w.files.push(p);
                }
            }
            if w.truncated {
                break;
            }
        }
    }
    if unreadable > 0 {
        w.notes
            .push(format!("{unreadable} directories could not be read"));
    }
    if w.truncated {
        w.notes.push(format!(
            "stopped at {max_files} files; the rest were not scanned"
        ));
    }
    w.files.sort();
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const V: &[u8] = b"sk_test_CANARY/+\"x9";

    fn one(v: &[u8]) -> Needles {
        let mut n = Needles::new();
        assert!(n.add(0, v));
        n
    }

    fn found(n: &Needles, hay: &[u8]) -> BTreeSet<Encoding> {
        find_in(n, hay).into_iter().map(|h| h.encoding).collect()
    }

    // protects=INJ-5 each encoding of a value is found and labelled; fails_when=an encoding is
    // missed; no_claim=compressed or split values (SPEC D-6)
    #[test]
    fn every_encoding_is_found() {
        let n = one(V);
        let s = std::str::from_utf8(V).unwrap();
        let cases: Vec<(Vec<u8>, Encoding)> = vec![
            (V.to_vec(), Encoding::Raw),
            (serde_json::to_vec(s).unwrap(), Encoding::Json),
            (url_encode(V, true).to_vec(), Encoding::Url),
            (url_encode(V, false).to_vec(), Encoding::Url),
            (hex::encode(V).into_bytes(), Encoding::Hex),
            (hex::encode_upper(V).into_bytes(), Encoding::Hex),
            (
                base64::engine::general_purpose::STANDARD
                    .encode(V)
                    .into_bytes(),
                Encoding::Base64,
            ),
            (
                base64::engine::general_purpose::URL_SAFE
                    .encode(V)
                    .into_bytes(),
                Encoding::Base64Url,
            ),
        ];
        for (text, enc) in cases {
            let mut hay = b"{\"x\":\"prefix ".to_vec();
            hay.extend_from_slice(&text);
            hay.extend_from_slice(b" suffix\"}\n");
            let got = found(&n, &hay);
            // Where url-safe and standard base64 coincide the needle is kept once, as base64.
            let ok = got.contains(&enc) || (enc == Encoding::Base64Url && got.contains(&Encoding::Base64));
            assert!(
                ok,
                "{enc:?} not found in {:?}",
                String::from_utf8_lossy(&hay)
            );
        }
        assert!(find_in(&n, b"nothing to see here\n").is_empty());
    }

    proptest! {
        // protects=a value inside a larger base64 blob is found at any byte offset;
        // fails_when=an alignment is missed
        #[test]
        fn base64_at_any_offset(
            v in proptest::collection::vec(any::<u8>(), 8..64),
            pre in proptest::collection::vec(any::<u8>(), 0..7),
            post in proptest::collection::vec(any::<u8>(), 0..7),
        ) {
            let n = one(&v);
            let mut blob = pre.clone();
            blob.extend_from_slice(&v);
            blob.extend_from_slice(&post);
            for (url, enc) in [(false, Encoding::Base64), (true, Encoding::Base64Url)] {
                let text = if url {
                    base64::engine::general_purpose::URL_SAFE.encode(&blob)
                } else {
                    base64::engine::general_purpose::STANDARD.encode(&blob)
                };
                let hits = found(&n, text.as_bytes());
                // url-safe and standard base64 coincide for some values; either label is right.
                prop_assert!(
                    hits.contains(&enc) || hits.contains(&Encoding::Base64) || hits.contains(&Encoding::Base64Url),
                    "{enc:?} missed"
                );
            }
        }
    }

    // protects=line numbers stay right and a value straddling a chunk boundary is found once;
    // fails_when=a boundary match is missed, duplicated or misnumbered
    #[test]
    fn chunk_boundaries_and_line_numbers() {
        let n = one(V);
        let mut hay = Vec::new();
        for _ in 0..3 {
            hay.extend_from_slice(b"line\n");
        }
        // Pad so V starts 5 bytes before the first chunk boundary.
        let pad = CHUNK - hay.len() - 5;
        hay.extend(std::iter::repeat_n(b'a', pad));
        hay.extend_from_slice(V); // line 4, crosses the boundary
        hay.extend_from_slice(b"\n\n");
        hay.extend_from_slice(V); // line 6
        hay.push(b'\n');
        let hits = find_in(&n, &hay);
        let raw: Vec<u64> = hits
            .iter()
            .filter(|h| h.encoding == Encoding::Raw)
            .map(|h| h.line)
            .collect();
        assert_eq!(raw, vec![4, 6]);
    }

    // protects=values too short to scan are refused, and Debug never shows needle bytes;
    // fails_when=a short value is searched or bytes appear in Debug
    #[test]
    fn short_values_and_debug() {
        let mut n = Needles::new();
        assert!(!n.add(0, b"1234567"));
        assert!(n.is_empty());
        assert!(n.add(1, V));
        let dbg = format!("{n:?}");
        assert!(!dbg.contains("CANARY"), "{dbg}");
    }

    // protects=stop() cuts a scan short and says so; fails_when=an incomplete scan reports
    // complete
    #[test]
    fn stop_marks_incomplete() {
        let n = one(V);
        let r = scan_reader(&n, &b"abc"[..], &mut || true).unwrap();
        assert!(!r.complete);
    }

    // protects=the walk never follows symlinks, skips non-transcripts, caps files; fails_when=a
    // linked file or directory is listed
    #[test]
    fn walk_rules() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("projects");
        std::fs::create_dir_all(root.join("p/sub")).unwrap();
        std::fs::write(root.join("p/a.jsonl"), "x").unwrap();
        std::fs::write(root.join("p/sub/b.json"), "x").unwrap();
        std::fs::write(root.join("p/c.txt"), "x").unwrap();
        let outside = d.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.jsonl"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("p/link")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.jsonl"), root.join("p/l.jsonl")).unwrap();
        let w = transcript_files(&[root.clone(), d.path().join("missing")], 100);
        let names: Vec<_> = w
            .files
            .iter()
            .map(|p| p.strip_prefix(&root).unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            vec![PathBuf::from("p/a.jsonl"), PathBuf::from("p/sub/b.json")]
        );
        let w = transcript_files(&[root], 1);
        assert!(w.truncated && w.files.len() == 1);
        assert!(open_regular(&d.path().join("projects/p/l.jsonl")).is_err());
    }
}
