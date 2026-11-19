//! Reading a `.env` safely, storing its secrets, and rewriting it atomically.
//!
//! Order matters: every key is stored first, and the file is replaced only after all of them
//! succeed, so a failure leaves the file exactly as it was. No plaintext copy is written: the
//! temp file holds the rewritten text (references and kept non-secrets) and replaces the
//! original with one `rename`.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ms_core::{KeyMeta, KeyName, SecretBytes};
use zeroize::{Zeroize, Zeroizing};

use crate::dotenv::{self, Entry, MAX_ENV_FILE_BYTES};
use crate::plan::Plan;
use crate::{Error, KeyStore};

/// A `.env` read into zeroizing memory and parsed. `Debug` leaves out the file text.
pub struct EnvFile {
    path: PathBuf,
    shown: String,
    src: Zeroizing<String>,
    entries: Vec<Entry>,
    dev: u64,
    ino: u64,
    mode: u32,
}

impl std::fmt::Debug for EnvFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvFile")
            .field("path", &self.path)
            .field("src", &format_args!("[redacted; {} bytes]", self.src.len()))
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

/// What [`commit`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    /// Keys stored, in order.
    pub stored: Vec<KeyName>,
    /// Values replaced by references in the file.
    pub rewritten: usize,
}

struct Snapshot {
    bytes: Zeroizing<Vec<u8>>,
    dev: u64,
    ino: u64,
    mode: u32,
}

/// Opens `path` without following a symlink and reads at most [`MAX_ENV_FILE_BYTES`].
fn snapshot(path: &Path, shown: &str) -> Result<Snapshot, Error> {
    let lmeta = fs::symlink_metadata(path).map_err(|e| Error::io(format!("reading {shown}"), e))?;
    if lmeta.file_type().is_symlink() {
        return Err(Error::Refused(format!(
            "{shown} is a symlink. Import the file it points to instead"
        )));
    }
    if !lmeta.is_file() {
        return Err(Error::Refused(format!("{shown} is not a regular file")));
    }
    let mut f = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::io(format!("opening {shown}"), e))?;
    let meta = f
        .metadata()
        .map_err(|e| Error::io(format!("reading {shown}"), e))?;
    if !meta.is_file() || meta.dev() != lmeta.dev() || meta.ino() != lmeta.ino() {
        return Err(Error::Refused(format!(
            "{shown} changed while it was being opened. Run the import again"
        )));
    }
    if meta.nlink() > 1 {
        return Err(Error::Refused(format!(
            "{shown} has {} hard links. Rewriting it would leave the plaintext in the others; \
             remove the extra links first",
            meta.nlink()
        )));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut f)
        .take(MAX_ENV_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(format!("reading {shown}"), e))?;
    if bytes.len() > MAX_ENV_FILE_BYTES {
        return Err(Error::Refused(format!(
            "{shown} is larger than {} bytes; that is not a .env file",
            MAX_ENV_FILE_BYTES
        )));
    }
    Ok(Snapshot {
        bytes,
        dev: meta.dev(),
        ino: meta.ino(),
        mode: meta.mode(),
    })
}

impl EnvFile {
    /// Reads and parses `path`. `shown` is how the path is printed in messages.
    pub fn read(path: &Path, shown: &str) -> Result<EnvFile, Error> {
        let mut snap = snapshot(path, shown)?;
        let bytes = std::mem::take(&mut *snap.bytes);
        let src = match String::from_utf8(bytes) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => {
                e.into_bytes().zeroize();
                return Err(Error::Refused(format!("{shown} is not UTF-8 text")));
            }
        };
        let entries = dotenv::parse(&src).map_err(|source| Error::Parse {
            path: shown.to_owned(),
            source,
        })?;
        Ok(EnvFile {
            path: path.to_owned(),
            shown: shown.to_owned(),
            src,
            entries,
            dev: snap.dev,
            ino: snap.ino,
            mode: snap.mode,
        })
    }

    /// Parsed entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The path as given.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn dir(&self) -> PathBuf {
        match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_owned(),
            _ => PathBuf::from("."),
        }
    }
}

fn list(names: &[KeyName]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names
            .iter()
            .map(KeyName::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Stores every `import` row's value in `store`, then rewrites the file with references.
///
/// Fails closed: if any store call fails, or the file changed since it was read, the file is
/// left exactly as it was and the error names the keys that were already stored.
pub fn commit(
    file: &EnvFile,
    plan: &Plan,
    store: &dyn KeyStore,
    now_unix_ms: u64,
) -> Result<Committed, Error> {
    let mut stored = Vec::new();
    for row in plan.imports() {
        let (Some(key), Some(mode), Some(tier)) = (&row.key, row.mode, row.tier) else {
            unreachable!("import rows carry key, mode and tier");
        };
        let value = SecretBytes::new(file.entries[row.entry].value().to_vec());
        let meta = KeyMeta {
            name: key.clone(),
            mode,
            tier,
            created_unix_ms: now_unix_ms,
        };
        if let Err(e) = store.put(key, value, meta) {
            let msg = match e {
                Error::Store(m) => m,
                other => other.to_string(),
            };
            return Err(Error::Store(format!(
                "storing {key} failed: {msg}. Stopped before changing {}; keys already stored: {}",
                file.shown,
                list(&stored)
            )));
        }
        stored.push(key.clone());
    }

    let refs: Vec<(&Entry, String)> = plan
        .rows
        .iter()
        .filter(|r| r.action.rewrites())
        .filter_map(|r| {
            r.key
                .as_ref()
                .map(|k| (&file.entries[r.entry], format!("ms://{k}")))
        })
        .collect();
    let rewritten = refs.len();
    let new_text = dotenv::rewrite(&file.src, &refs);

    let fail = |what: String| {
        Error::Refused(format!(
            "{what}. {} was not changed; keys already stored: {}",
            file.shown,
            list(&stored)
        ))
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".ms-import-")
        .suffix(".tmp")
        .tempfile_in(file.dir())
        .map_err(|e| fail(format!("creating a temp file next to {}: {e}", file.shown)))?;
    tmp.write_all(new_text.as_bytes())
        .and_then(|()| {
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(file.mode & 0o7777))
        })
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| fail(format!("writing the temp file: {e}")))?;

    // The file must be the one we read, unchanged, right before it is replaced.
    let now = snapshot(&file.path, &file.shown).map_err(|e| fail(e.to_string()))?;
    if now.dev != file.dev || now.ino != file.ino || now.bytes.as_slice() != file.src.as_bytes() {
        return Err(fail(format!(
            "{} changed while importing. Run the import again",
            file.shown
        )));
    }
    drop(now);

    tmp.persist(&file.path)
        .map_err(|e| fail(format!("replacing {}: {}", file.shown, e.error)))?;
    // Make the rename durable. The file is already replaced, so a failure here is not undone.
    if let Ok(d) = File::open(file.dir()) {
        let _ = d.sync_all();
    }
    Ok(Committed { stored, rewritten })
}

/// Number of commits, on any branch, that touched `path`; `None` outside a git repository or
/// when git is unavailable. Runs git without a pager, fsmonitor or signature checks, with no
/// transport at all (`protocol.allow=never`, `GIT_NO_LAZY_FETCH`: a partial clone's missing
/// object would otherwise run the promisor remote's `uploadpack` or `core.sshCommand`, L35
/// security review S1), no replace objects and no system config, so a repository's config
/// (agent-writable) can't make it run other programs. msd runs this for the dashboard's Add
/// project, outside every sandbox.
pub fn git_history(path: &Path) -> Option<usize> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path.file_name()?;
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "log.showSignature=false",
            "-c",
            "core.pager=cat",
            "-c",
            "protocol.allow=never",
            "--no-replace-objects",
            "log",
            "--all",
            "--no-color",
            "--format=%h",
            "--",
        ])
        .arg(name)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_SSH_COMMAND")
        .env_remove("GIT_SSH")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::plan::{Options, plan};
    use ms_vault::VaultExt;
    use ms_vault::memory::MemoryVault;
    use std::cell::Cell;

    const CANARY: &str = "sk_live_CANARY7f3a9cQ2w8e5r1t6y0u4i";

    fn env_text() -> String {
        format!(
            "# app\nexport STRIPE_SECRET_KEY=\"{CANARY}\"\nPORT=3000\n\
             DATABASE_URL=postgres://app:CANARYpw9x@db.prod.example.com/app\n\
             SESSION_SECRET='CANARYsess'\nDUP={CANARY}\n"
        )
    }

    fn setup(text: &str, mode: u32) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".env");
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        (d, p)
    }

    fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
        let mut hits = Vec::new();
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                hits.extend(files_containing(&p, needle));
            } else if fs::read(&p)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
            {
                hits.push(p);
            }
        }
        hits
    }

    // protects=after import the file holds only refs (non-secrets untouched), every value is in
    // the vault, the file mode is kept, and no file in the directory contains a canary;
    // fails_when=a value survives on disk, a temp or backup file is left, or a ref is wrong;
    // no_claim=the Keychain backend (L01) or swap/core dumps
    #[test]
    fn import_leaves_only_refs() {
        let (d, p) = setup(&env_text(), 0o640);
        let f = EnvFile::read(&p, ".env").unwrap();
        let v = MemoryVault::new();
        let pl = plan(Catalog::builtin(), f.entries(), &[], &Options::default()).unwrap();
        let done = commit(&f, &pl, &v, 1).unwrap();
        assert_eq!(done.rewritten, 4);
        assert_eq!(
            done.stored.iter().map(KeyName::as_str).collect::<Vec<_>>(),
            ["stripe/production", "pg/production", "env/session-secret"]
        );
        let out = fs::read_to_string(&p).unwrap();
        assert_eq!(
            out,
            "# app\nexport STRIPE_SECRET_KEY=\"ms://stripe/production\"\nPORT=3000\n\
             DATABASE_URL=ms://pg/production\n\
             SESSION_SECRET='ms://env/session-secret'\nDUP=ms://stripe/production\n"
        );
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(files_containing(d.path(), b"CANARY").is_empty());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "temp file left");
        let k = KeyName::new("stripe/production").unwrap();
        assert_eq!(v.read_with(&k, |b| b.to_vec()).unwrap(), CANARY.as_bytes());
        let pg = KeyName::new("pg/production").unwrap();
        assert!(v.read_with(&pg, |b| b.starts_with(b"postgres://")).unwrap());
    }

    struct FailSecond {
        inner: MemoryVault,
        calls: Cell<u32>,
    }
    impl KeyStore for FailSecond {
        fn list(&self) -> Result<Vec<KeyMeta>, Error> {
            KeyStore::list(&self.inner)
        }
        fn put(&self, n: &KeyName, v: SecretBytes, m: KeyMeta) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == 2 {
                return Err(Error::Store("daemon went away".into()));
            }
            KeyStore::put(&self.inner, n, v, m)
        }
    }

    // protects=Debug of a read file shows no value; fails_when=the file text is printed
    #[test]
    fn envfile_debug_redacted() {
        let (_d, p) = setup(&env_text(), 0o600);
        let f = EnvFile::read(&p, ".env").unwrap();
        let dbg = format!("{f:?} {f:#?}");
        assert!(!dbg.contains("CANARY"), "{dbg}");
        assert!(dbg.contains("redacted"), "{dbg}");
    }

    // protects=a store failure part-way leaves the file byte-identical and names stored keys;
    // fails_when=the file changes or the message hides what was stored; no_claim=rollback of the
    // stored key (there is no delete over IPC; the message tells the user)
    #[test]
    fn store_failure_leaves_file() {
        let text = env_text();
        let (d, p) = setup(&text, 0o600);
        let f = EnvFile::read(&p, ".env").unwrap();
        let pl = plan(Catalog::builtin(), f.entries(), &[], &Options::default()).unwrap();
        let s = FailSecond {
            inner: MemoryVault::new(),
            calls: Cell::new(0),
        };
        let err = commit(&f, &pl, &s, 1).unwrap_err().to_string();
        assert!(
            err.contains("storing pg/production failed: daemon went away"),
            "{err}"
        );
        assert!(
            err.contains("keys already stored: stripe/production"),
            "{err}"
        );
        assert!(!err.contains("CANARY"));
        assert_eq!(fs::read_to_string(&p).unwrap(), text);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    struct Tamper<'a>(&'a Path);
    impl KeyStore for Tamper<'_> {
        fn list(&self) -> Result<Vec<KeyMeta>, Error> {
            Ok(vec![])
        }
        fn put(&self, _: &KeyName, _: SecretBytes, _: KeyMeta) -> Result<(), Error> {
            fs::write(self.0, "NEW_SECRET=written-meanwhile\n").unwrap();
            Ok(())
        }
    }

    // protects=a file changed between read and replace is not overwritten; fails_when=the
    // concurrent edit is lost; no_claim=a change in the instant between the check and rename
    #[test]
    fn concurrent_change_aborts() {
        let (d, p) = setup(&env_text(), 0o600);
        let f = EnvFile::read(&p, ".env").unwrap();
        let pl = plan(Catalog::builtin(), f.entries(), &[], &Options::default()).unwrap();
        let err = commit(&f, &pl, &Tamper(&p), 1).unwrap_err().to_string();
        assert!(err.contains("changed while importing"), "{err}");
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "NEW_SECRET=written-meanwhile\n"
        );
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "temp file left");
    }

    // protects=symlinks, hard-linked files, directories, oversized and non-UTF-8 files and parse
    // errors are refused before anything is stored; fails_when=one is read or imported;
    // no_claim=other special files (FIFOs are refused as non-regular by the same check)
    #[test]
    fn refusals() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.env");
        fs::write(&real, "A_KEY=x\n").unwrap();
        let link = d.path().join(".env");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            EnvFile::read(&link, ".env")
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        let hard = d.path().join("hard.env");
        fs::hard_link(&real, &hard).unwrap();
        assert!(
            EnvFile::read(&hard, "hard.env")
                .unwrap_err()
                .to_string()
                .contains("hard links")
        );
        assert!(
            EnvFile::read(d.path(), "dir")
                .unwrap_err()
                .to_string()
                .contains("not a regular file")
        );
        let big = d.path().join("big.env");
        fs::write(&big, vec![b'#'; MAX_ENV_FILE_BYTES + 1]).unwrap();
        assert!(
            EnvFile::read(&big, "big.env")
                .unwrap_err()
                .to_string()
                .contains("larger")
        );
        let bin = d.path().join("bin.env");
        fs::write(&bin, b"A=\xff\xfe\n").unwrap();
        assert!(
            EnvFile::read(&bin, "bin.env")
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
        let bad = d.path().join("bad.env");
        fs::write(&bad, "A=\"sk_live_CANARY\n").unwrap();
        let e = EnvFile::read(&bad, "bad.env").unwrap_err().to_string();
        assert!(e.contains("line 1") && !e.contains("CANARY"), "{e}");
    }

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?}");
    }

    // protects=a .env that was ever committed is detected (even after removal), and an
    // uncommitted one or a non-repo is not; fails_when=either is misreported; no_claim=remote
    // history that is not in the local clone
    #[test]
    fn git_history_detects_commits() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".env");
        fs::write(&p, "A=1\n").unwrap();
        assert_eq!(git_history(&p), None, "not a repo");
        git(d.path(), &["init", "-q"]);
        assert_eq!(git_history(&p), Some(0));
        git(d.path(), &["add", ".env"]);
        git(d.path(), &["commit", "-q", "-m", "oops"]);
        git(d.path(), &["rm", "-q", "--cached", ".env"]);
        git(d.path(), &["commit", "-q", "-m", "remove"]);
        assert_eq!(git_history(&p), Some(2));
    }

    // protects=L35 security review S1 / T-110: an agent-writable repository made a partial
    // clone with a missing tree and a promisor remote whose uploadpack (or core.sshCommand) is a
    // command can't make git_history run it: no transport, no lazy fetch; fails_when=the marker
    // file appears; no_claim=git versions without GIT_NO_LAZY_FETCH (protocol.allow=never covers
    // them)
    #[test]
    fn git_history_runs_no_configured_program() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("r");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join(".env"), "A=1\n").unwrap();
        git(&repo, &["add", ".env"]);
        git(&repo, &["commit", "-q", "-m", "one"]);
        let tree = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["rev-parse", "HEAD^{tree}"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let tree = tree.trim();
        fs::remove_file(repo.join(".git/objects").join(&tree[..2]).join(&tree[2..])).unwrap();
        let marker = d.path().join("PWNED");
        let mut cfg = fs::read_to_string(repo.join(".git/config")).unwrap();
        cfg = cfg.replace("repositoryformatversion = 0", "repositoryformatversion = 1");
        cfg.push_str(&format!(
            "[extensions]\n\tpartialClone = origin\n[remote \"origin\"]\n\turl = {}\n\tpromisor = true\n\tuploadpack = touch '{}' && false\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[core]\n\tsshCommand = touch '{}' && false\n",
            d.path().join("nowhere").display(),
            marker.display(),
            marker.display()
        ));
        fs::write(repo.join(".git/config"), cfg).unwrap();
        let _ = git_history(&repo.join(".env"));
        assert!(!marker.exists(), "git ran a configured program");
        // The same repository under plain `git log` does run it (the test's setup is live).
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["log", "--all", "--format=%h", "--", ".env"])
            .env_remove("GIT_NO_LAZY_FETCH")
            .output();
        assert!(
            marker.exists(),
            "the fixture no longer triggers a lazy fetch"
        );
    }
}
