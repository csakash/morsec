//! Undo an import (L33 SPEC D-21, design §6.7): write a key's value back into the env file line
//! `ms init` replaced with its ref, in the line's original quote style.
//!
//! The record names the file relative to the project root; a tampered record, a symlink swap or
//! an edited file must not make Undo write a value anywhere else (T-94). So:
//!
//! - the root is opened as a directory (`O_DIRECTORY | O_NOFOLLOW`) and the recorded path is
//!   walked component by component with `openat(O_NOFOLLOW)`: no `..`, no absolute path, no
//!   symlink at any level;
//! - the file must be a regular file owned by the user with one link, read bounded as
//!   `ms-import` reads env files;
//! - the recorded line must still hold exactly `VAR=ms://<key>` in the recorded quote style;
//! - the value is encoded for that quote style by [`encode`], which checks it parses back to
//!   exactly the value through `ms-import`'s dotenv parser; a value that can't be written in the
//!   style (a newline unquoted, a `'` in single quotes) is skipped and listed;
//! - each file is rewritten once, atomically: a temp file in the same directory through the
//!   directory fd, mode kept, `fsync`, `renameat`, after checking the file is still the one read
//!   (device, inode and bytes).
//!
//! Any check failing skips that line, with the reason; the other lines go ahead.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use ms_core::KeyName;
use ms_import::dotenv::{self, MAX_ENV_FILE_BYTES};
use rustix::fs::{AtFlags, FileType, Mode as FsMode, OFlags};
use zeroize::Zeroizing;

use crate::record::{Quote, check_rel};

/// One recorded line to restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRef {
    /// Variable name.
    pub var: String,
    /// 1-based line.
    pub line: u64,
    /// The key whose ref the line holds.
    pub key: KeyName,
    /// How the value was quoted.
    pub quote: Quote,
}

/// (device, inode, mode) of a file that was read.
type FileId = (u64, u64, u32);

/// Gives a key's value for Undo (from the vault), or why it can't.
pub type ValueFn<'a> = &'a mut dyn FnMut(&KeyName) -> Result<Zeroizing<Vec<u8>>, String>;

/// Why lines were skipped when the whole file is refused.
fn all(n: usize, why: &str) -> Vec<Result<(), String>> {
    vec![Err(why.to_owned()); n]
}

fn to_dotenv(q: Quote) -> dotenv::Quote {
    match q {
        Quote::None => dotenv::Quote::None,
        Quote::Single => dotenv::Quote::Single,
        Quote::Double => dotenv::Quote::Double,
        Quote::Backtick => dotenv::Quote::Backtick,
    }
}

fn quote_char(q: Quote) -> &'static str {
    match q {
        Quote::None => "",
        Quote::Single => "'",
        Quote::Double => "\"",
        Quote::Backtick => "`",
    }
}

/// `value` written for quote style `q` (without the quotes), or `None` when it can't be: it is
/// not UTF-8, or it would not parse back to exactly `value` (a newline in an unquoted value, a
/// `'` in a single-quoted one, a `$` or ` #` a loader would read differently). The check parses
/// a probe line with `ms-import`'s dotenv parser, so what is written is what loaders read.
pub fn encode(value: &[u8], q: Quote) -> Option<Zeroizing<String>> {
    let text = std::str::from_utf8(value).ok()?;
    if text.is_empty() {
        return None;
    }
    let mut enc = Zeroizing::new(String::with_capacity(text.len() * 2));
    match q {
        Quote::Double => {
            for c in text.chars() {
                match c {
                    '\\' => enc.push_str("\\\\"),
                    '"' => enc.push_str("\\\""),
                    '\n' => enc.push_str("\\n"),
                    '\r' => enc.push_str("\\r"),
                    '\t' => enc.push_str("\\t"),
                    '$' => enc.push_str("\\$"),
                    c => enc.push(c),
                }
            }
        }
        _ => enc.push_str(text),
    }
    let qc = quote_char(q);
    let mut probe = Zeroizing::new(String::with_capacity(enc.len() + 8));
    probe.push_str("V=");
    probe.push_str(qc);
    probe.push_str(&enc);
    probe.push_str(qc);
    probe.push('\n');
    let entries = dotenv::parse(&probe).ok()?;
    let [e] = entries.as_slice() else {
        return None;
    };
    let ok = e.name == "V"
        && e.quote == to_dotenv(q)
        && !e.interpolated
        && !e.inline_comment
        && e.value() == value
        && e.value_span.end == probe.len() - 1;
    ok.then_some(enc)
}

fn errno_reason(e: rustix::io::Errno, what: &str) -> String {
    if e == rustix::io::Errno::PERM {
        "macOS did not let morsec write here".to_owned()
    } else if e == rustix::io::Errno::LOOP || e == rustix::io::Errno::NOTDIR {
        format!("{what} is a link or not a folder now; morsec does not follow links")
    } else if e == rustix::io::Errno::NOENT {
        format!("{what} is gone")
    } else {
        format!("{what} could not be opened ({e})")
    }
}

/// Opens the folder that holds `rel` (walked from `root`, no links) and returns it with the
/// file name.
fn open_parent<'a>(root: &Path, rel: &'a str) -> Result<(OwnedFd, &'a str), String> {
    let flags = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC;
    let mut dir = rustix::fs::open(root, flags, FsMode::empty())
        .map_err(|e| errno_reason(e, "the project folder"))?;
    let mut parts: Vec<&str> = rel.split('/').collect();
    let name = parts.pop().unwrap_or_default();
    for p in parts {
        if p.is_empty() || p == "." || p == ".." {
            return Err("the recorded path is not inside the project".into());
        }
        dir = rustix::fs::openat(&dir, p, flags, FsMode::empty())
            .map_err(|e| errno_reason(e, &format!("the folder {p}")))?;
    }
    if name.is_empty() || name == "." || name == ".." {
        return Err("the recorded path is not inside the project".into());
    }
    Ok((dir, name))
}

/// Opens and reads `name` in `dir` with every check: regular file, owned by `owner_uid`, one
/// link, at most the env-file limit. Returns the bytes and (dev, ino, mode).
fn read_checked(
    dir: &OwnedFd,
    name: &str,
    owner_uid: u32,
) -> Result<(Zeroizing<Vec<u8>>, FileId), String> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        FsMode::empty(),
    )
    .map_err(|e| errno_reason(e, "the file"))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| errno_reason(e, "the file"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err("it is not a regular file".into());
    }
    if st.st_uid != owner_uid {
        return Err("the file belongs to another user".into());
    }
    if st.st_nlink != 1 {
        return Err("the file has more than one name (a hard link)".into());
    }
    let mut f = std::fs::File::from(fd);
    let mut buf = Zeroizing::new(Vec::new());
    (&mut f)
        .take(MAX_ENV_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("the file could not be read ({e})"))?;
    if buf.len() > MAX_ENV_FILE_BYTES {
        return Err("the file is over 1 MiB".into());
    }
    #[allow(clippy::unnecessary_cast)]
    let id = (
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_mode as u32 & 0o7777,
    );
    Ok((buf, id))
}

/// Writes `bytes` to `name` in `dir` through a temp file and `renameat`, after checking `name`
/// is still the file read (`id`, and the same bytes `was`).
fn replace_atomically(
    dir: &OwnedFd,
    name: &str,
    id: FileId,
    was: &[u8],
    bytes: &[u8],
    owner_uid: u32,
) -> Result<(), String> {
    let tag = ms_approve::token::random_bytes::<6>()
        .map_err(|e| format!("no randomness for a temp file ({e})"))?;
    let tmp = format!(".ms-undo-{}", hex::encode(tag));
    let fd = rustix::fs::openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FsMode::from_raw_mode(0o600),
    )
    .map_err(|e| errno_reason(e, "a temp file next to it"))?;
    let cleanup = |dir: &OwnedFd| {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
    };
    let mut f = std::fs::File::from(fd);
    let written = f
        .write_all(bytes)
        .and_then(|()| rustix::fs::fchmod(&f, FsMode::from_raw_mode(id.2 as _)).map_err(Into::into))
        .and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written {
        cleanup(dir);
        return Err(format!("the new file could not be written ({e})"));
    }
    // Still the file that was read, right before the rename.
    let same = read_checked(dir, name, owner_uid)
        .ok()
        .is_some_and(|(now, nid)| nid == id && now.as_slice() == was);
    if !same {
        cleanup(dir);
        return Err("the file changed while morsec was writing it; run Undo again".into());
    }
    if let Err(e) = rustix::fs::renameat(dir, tmp.as_str(), dir, name) {
        cleanup(dir);
        return Err(errno_reason(e, "the file"));
    }
    let _ = rustix::fs::fsync(dir);
    Ok(())
}

/// Restores `lines` of the file `rel` under `root` (the record's canonical root), owned by
/// `owner_uid`. `value` gives each key's value (from the vault). Returns one result per line, in
/// order: `Ok` when the value is back, `Err(reason)` when the line was left as it was.
pub fn undo_file(
    root: &Path,
    rel: &str,
    lines: &[LineRef],
    owner_uid: u32,
    value: ValueFn<'_>,
) -> Vec<Result<(), String>> {
    if check_rel(rel).is_err() {
        return all(lines.len(), "the recorded path is not inside the project");
    }
    let (dir, name) = match open_parent(root, rel) {
        Ok(x) => x,
        Err(why) => return all(lines.len(), &why),
    };
    let (raw, id) = match read_checked(&dir, name, owner_uid) {
        Ok(x) => x,
        Err(why) => return all(lines.len(), &why),
    };
    let Ok(src) = std::str::from_utf8(&raw) else {
        return all(lines.len(), "the file is not UTF-8 text");
    };
    let Ok(entries) = dotenv::parse(src) else {
        return all(
            lines.len(),
            "the file no longer parses as a .env file; fix it, then run Undo again",
        );
    };
    let mut out = Vec::with_capacity(lines.len());
    let mut repl: Vec<(&dotenv::Entry, String)> = Vec::new();
    let mut held: Vec<Zeroizing<String>> = Vec::new();
    let mut pending: Vec<usize> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let want = format!("ms://{}", l.key);
        let raw_want = format!("{q}{want}{q}", q = quote_char(l.quote));
        let found = entries.iter().find(|e| {
            e.line as u64 == l.line
                && e.name == l.var
                && e.quote == to_dotenv(l.quote)
                && !e.interpolated
                && e.value() == want.as_bytes()
                && src.get(e.value_span.clone()) == Some(raw_want.as_str())
        });
        let Some(e) = found else {
            out.push(Err(format!(
                "line {} no longer holds {}={raw_want}",
                l.line, l.var
            )));
            continue;
        };
        let v = match value(&l.key) {
            Ok(v) => v,
            Err(why) => {
                out.push(Err(why));
                continue;
            }
        };
        let Some(enc) = encode(&v, l.quote) else {
            out.push(Err(format!(
                "the value can't be written {} (a line break, a quote or a $ sign the file's format would read differently); put it back by hand",
                match l.quote {
                    Quote::None => "without quotes",
                    Quote::Single => "in single quotes",
                    Quote::Double => "in double quotes",
                    Quote::Backtick => "in backticks",
                }
            )));
            continue;
        };
        // `rewrite` takes owned text; keep the zeroizing copy alive alongside it.
        repl.push((e, enc.as_str().to_owned()));
        held.push(enc);
        pending.push(i);
        out.push(Ok(()));
    }
    if repl.is_empty() {
        return out;
    }
    let new = dotenv::rewrite(src, &repl);
    for (_, s) in &mut repl {
        zeroize::Zeroize::zeroize(s);
    }
    drop(held);
    if let Err(why) = replace_atomically(&dir, name, id, &raw, new.as_bytes(), owner_uid) {
        for i in pending {
            out[i] = Err(why.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const V: &str = concat!("sk_live_", "UNDO_CANARY_9");

    fn uid(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().uid()
    }

    fn line(var: &str, n: u64, key: &str, q: Quote) -> LineRef {
        LineRef {
            var: var.into(),
            line: n,
            key: KeyName::new(key).unwrap(),
            quote: q,
        }
    }

    fn vals(key: &KeyName) -> Result<Zeroizing<Vec<u8>>, String> {
        match key.as_str() {
            "shop/a" => Ok(Zeroizing::new(V.as_bytes().to_vec())),
            "shop/multi" => Ok(Zeroizing::new(b"line1\nline2".to_vec())),
            "shop/q" => Ok(Zeroizing::new(b"it's".to_vec())),
            _ => Err("not in the vault".into()),
        }
    }

    fn root() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(d.path()).unwrap().join("shop");
        std::fs::create_dir(&r).unwrap();
        (d, r)
    }

    // protects=T-94: a symlink in place of the recorded file, or of a folder on its path, is
    // never followed: the lines are skipped and the link's target is unchanged;
    // fails_when=Undo writes through a link at any level; no_claim=races faster than the
    // per-component openat (each level is checked on the fd it opens)
    #[test]
    fn undo_refuses_symlink_swap() {
        let (_d, r) = root();
        let outside = r.parent().unwrap().join("outside.env");
        std::fs::write(&outside, "A=ms://shop/a\n").unwrap();
        std::os::unix::fs::symlink(&outside, r.join(".env")).unwrap();
        let res = undo_file(
            &r,
            ".env",
            &[line("A", 1, "shop/a", Quote::None)],
            uid(&r),
            &mut vals,
        );
        assert!(res[0].is_err(), "{res:?}");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "A=ms://shop/a\n"
        );

        let real = r.parent().unwrap().join("realdir");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join(".env"), "A=ms://shop/a\n").unwrap();
        std::os::unix::fs::symlink(&real, r.join("sub")).unwrap();
        let res = undo_file(
            &r,
            "sub/.env",
            &[line("A", 1, "shop/a", Quote::None)],
            uid(&r),
            &mut vals,
        );
        assert!(res[0].as_ref().unwrap_err().contains("link"), "{res:?}");
        assert_eq!(
            std::fs::read_to_string(real.join(".env")).unwrap(),
            "A=ms://shop/a\n"
        );
    }

    // protects=T-94: a recorded path that leaves the root (`..`, absolute, empty parts) is
    // refused before anything is opened; fails_when=a record can point Undo outside its project;
    // no_claim=-
    #[test]
    fn undo_stays_inside_root() {
        let (_d, r) = root();
        let outside = r.parent().unwrap().join(".env");
        std::fs::write(&outside, "A=ms://shop/a\n").unwrap();
        for rel in [
            "../.env",
            "/etc/hosts",
            "a//.env",
            "./.env",
            "",
            "sub/../../.env",
        ] {
            let res = undo_file(
                &r,
                rel,
                &[line("A", 1, "shop/a", Quote::None)],
                uid(&r),
                &mut vals,
            );
            assert!(res[0].is_err(), "{rel}");
        }
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "A=ms://shop/a\n"
        );
    }

    // protects=SPEC D-21 and T-94: only a line that still holds exactly VAR=ms://<key> in its
    // recorded quote style, at its recorded line, gets the value; an edited, moved or
    // re-quoted line is skipped with the reason, and every other byte of the file is kept;
    // fails_when=a changed line is overwritten or another byte changes; no_claim=-
    #[test]
    fn undo_only_writes_exact_ref_line() {
        let (_d, r) = root();
        let env = r.join(".env");
        std::fs::write(
            &env,
            "# keep me\nA=ms://shop/a\nexport B = \"ms://shop/a\"  # c\nC=ms://shop/other\nD='ms://shop/a'\nE=ms://shop/a\n",
        )
        .unwrap();
        let lines = [
            line("A", 2, "shop/a", Quote::None),
            line("B", 3, "shop/a", Quote::Double),
            line("C", 4, "shop/a", Quote::None),
            line("D", 5, "shop/a", Quote::Double),
            line("E", 9, "shop/a", Quote::None),
            line("X", 6, "shop/a", Quote::None),
        ];
        let res = undo_file(&r, ".env", &lines, uid(&r), &mut vals);
        assert!(res[0].is_ok() && res[1].is_ok(), "{res:?}");
        for (i, r) in res.iter().enumerate().skip(2) {
            assert!(r.is_err(), "line {i}: {res:?}");
        }
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            format!(
                "# keep me\nA={V}\nexport B = \"{V}\"  # c\nC=ms://shop/other\nD='ms://shop/a'\nE=ms://shop/a\n"
            )
        );
        // A value that can't be written in the style is skipped, the file untouched.
        std::fs::write(&env, "M=ms://shop/multi\nQ='ms://shop/q'\n").unwrap();
        let res = undo_file(
            &r,
            ".env",
            &[
                line("M", 1, "shop/multi", Quote::None),
                line("Q", 2, "shop/q", Quote::Single),
            ],
            uid(&r),
            &mut vals,
        );
        assert!(res.iter().all(Result::is_err), "{res:?}");
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            "M=ms://shop/multi\nQ='ms://shop/q'\n"
        );
    }

    // protects=T-94: each file is rewritten once through a temp file and a rename (a reader of
    // the old file sees it whole; no temp file stays), its mode kept; a file with a second hard
    // link, or of another owner, is refused; fails_when=the file is written in place, the mode
    // changes, a temp file is left, or a hard-linked file is written; no_claim=power loss between
    // fsync and rename (the old file stays)
    #[test]
    fn undo_is_atomic_per_file() {
        let (_d, r) = root();
        let env = r.join(".env");
        std::fs::write(&env, "A=ms://shop/a\nB=keep\n").unwrap();
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut old = std::fs::File::open(&env).unwrap();
        let ino = std::fs::metadata(&env).unwrap().ino();
        let res = undo_file(
            &r,
            ".env",
            &[line("A", 1, "shop/a", Quote::None)],
            uid(&r),
            &mut vals,
        );
        assert!(res[0].is_ok(), "{res:?}");
        let m = std::fs::metadata(&env).unwrap();
        assert_ne!(m.ino(), ino, "replaced by rename, not written in place");
        assert_eq!(m.permissions().mode() & 0o777, 0o640);
        let mut was = String::new();
        old.read_to_string(&mut was).unwrap();
        assert_eq!(was, "A=ms://shop/a\nB=keep\n", "the old file is whole");
        let names: Vec<_> = std::fs::read_dir(&r)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [".env"], "no temp file left");

        std::fs::write(&env, "A=ms://shop/a\n").unwrap();
        std::fs::hard_link(&env, r.join("other")).unwrap();
        let res = undo_file(
            &r,
            ".env",
            &[line("A", 1, "shop/a", Quote::None)],
            uid(&r),
            &mut vals,
        );
        assert!(res[0].as_ref().unwrap_err().contains("hard link"));
        std::fs::remove_file(r.join("other")).unwrap();
        let res = undo_file(
            &r,
            ".env",
            &[line("A", 1, "shop/a", Quote::None)],
            uid(&r) + 1,
            &mut vals,
        );
        assert!(res[0].as_ref().unwrap_err().contains("another user"));
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "A=ms://shop/a\n");
    }

    fn quote() -> impl Strategy<Value = Quote> {
        prop_oneof![
            Just(Quote::None),
            Just(Quote::Single),
            Just(Quote::Double),
            Just(Quote::Backtick)
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        // protects=SPEC D-21: what Undo writes parses back, through ms-import's dotenv parser,
        // to exactly the value, in the recorded quote style, inside a real file with other lines
        // around it; double quotes can carry any text; fails_when=a written value reads back
        // differently or breaks the lines around it; no_claim=other dotenv loaders' quirks
        #[test]
        fn undo_round_trips_with_parser(
            v in "[ -~\n\t\u{e9}\u{1f600}]{1,40}",
            q in quote(),
        ) {
            if q == Quote::Double {
                prop_assert!(encode(v.as_bytes(), q).is_some(), "{v:?}");
            }
            if let Some(enc) = encode(v.as_bytes(), q) {
                let qc = quote_char(q);
                let src = format!("BEFORE=1\nX={qc}ms://k/x{qc}\nAFTER=2\n");
                let entries = dotenv::parse(&src).unwrap();
                let x = entries.iter().find(|e| e.name == "X").unwrap();
                let out = dotenv::rewrite(&src, &[(x, enc.as_str().to_owned())]);
                let back = dotenv::parse(&out).unwrap();
                prop_assert_eq!(back.len(), 3);
                let x = back.iter().find(|e| e.name == "X").unwrap();
                prop_assert_eq!(x.value(), v.as_bytes());
                prop_assert_eq!(x.quote, to_dotenv(q));
                prop_assert_eq!(back[2].value(), b"2");
            }
        }
    }
}
