//! The deep scan (design §4.5).
//!
//! The root is opened as a directory fd and every child with `openat` + `O_NOFOLLOW`, so a
//! symlink is never followed, not even a directory swapped for a symlink between `readdir` and
//! `openat` (the open fails and the entry is skipped). A directory on another device (a mount
//! point) is never entered. Dependency and build directories are skipped by name. Budgets stop a
//! huge tree: entries visited, wall time, file sizes and the number of source files read.
//!
//! What it finds:
//! - **env files** (`.env`, `.env.*`, `*.env`, `.dev.vars`, `.envrc`): paths only; the importer
//!   reads them itself (`ms_import::envfile::EnvFile::read`, `O_NOFOLLOW`).
//! - **example files** (`.env.example`, `.sample`, `.template`, `.dist`, `*.example`): variable
//!   names only, never imported.
//! - **code findings**: values in source files that start with a catalog prefix
//!   (`Catalog::match_prefix`). Reported as file, line, provider and a masked form; never stored,
//!   never rewritten.
//!
//! Every path opened is recorded in [`Scan::opened`] (the audit SPEC criterion 1 reads).

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ms_import::catalog::Catalog;
use rustix::fs::{AtFlags, Dir, FileType, Mode as FsMode, OFlags};
use zeroize::Zeroizing;

use crate::Error;

/// Directories never entered.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "bower_components",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".output",
    ".vercel",
    ".netlify",
    ".wrangler",
    ".turbo",
    ".cache",
    ".parcel-cache",
    "coverage",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".terraform",
    ".gradle",
    "Pods",
    "DerivedData",
    ".idea",
    ".vscode",
];

/// Source extensions searched for keys written into code.
pub const SOURCE_EXTS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "mjs", "cjs", "py", "rb", "go", "rs", "java", "kt", "swift", "php",
    "cs", "json", "yaml", "yml", "toml",
];

/// The scan's limits (design §4.5). Parameters so tests can make them small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// Directory entries visited.
    pub max_entries: u64,
    /// Wall time.
    pub max_time: Duration,
    /// Largest env file taken.
    pub max_env_bytes: u64,
    /// Largest source file read.
    pub max_source_bytes: u64,
    /// Most source files read.
    pub max_source_files: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            max_time: Duration::from_secs(10),
            max_env_bytes: 1 << 20,
            max_source_bytes: 512 << 10,
            max_source_files: 5_000,
        }
    }
}

/// What a file is to the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Imported.
    Env,
    /// Read for variable names only.
    Example,
    /// Searched for keys written into code.
    Source,
}

/// Classifies a file name. `None`: not looked at.
pub fn classify(name: &str) -> Option<Kind> {
    let lower = name.to_ascii_lowercase();
    let example = [".example", ".sample", ".template", ".dist"];
    if example.iter().any(|e| lower.ends_with(e))
        && (lower.starts_with(".env") || lower.ends_with(".example"))
    {
        return Some(Kind::Example);
    }
    if lower == ".env"
        || lower.starts_with(".env.")
        || (lower.ends_with(".env") && lower.len() > 4)
        || lower == ".dev.vars"
        || lower == ".envrc"
    {
        return Some(Kind::Env);
    }
    let ext = lower.rsplit_once('.').map(|(_, e)| e)?;
    SOURCE_EXTS.contains(&ext).then_some(Kind::Source)
}

/// A key written into a source file. Never the value: the catalog prefix and the length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFinding {
    /// Path relative to the root.
    pub path: String,
    /// 1-based line.
    pub line: usize,
    /// Catalog provider id.
    pub provider: String,
    /// `sk_live_… (107 bytes)`.
    pub masked: String,
}

/// An example file and the variable names it lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// Path relative to the root.
    pub path: String,
    /// Variable names.
    pub vars: Vec<String>,
}

/// What the walk found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// Env files, relative to the root, sorted (shallow first, then by name).
    pub env_files: Vec<String>,
    /// Example files.
    pub examples: Vec<Example>,
    /// Keys written into code.
    pub findings: Vec<CodeFinding>,
    /// Entries visited.
    pub entries: u64,
    /// A budget stopped the walk.
    pub stopped_early: bool,
    /// Which budget, for the summary.
    pub stop_reason: Option<String>,
    /// Wall time, ms.
    pub elapsed_ms: u64,
    /// Files skipped for size (relative paths).
    pub too_large: Vec<String>,
    /// Directories not entered because they are on another device (relative paths).
    pub other_device: Vec<String>,
    /// Every path opened, relative to the root (`.` for the root): the audit.
    pub opened: Vec<String>,
}

/// A test hook run before each `openat`.
type OpenHook<'c> = Box<dyn Fn(&Path) + 'c>;

/// The scan with its test hook.
pub struct Walker<'c> {
    catalog: &'c Catalog,
    budgets: Budgets,
    /// Called with the relative path right before each `openat` (tests swap a directory for a
    /// symlink here).
    before_open: Option<OpenHook<'c>>,
}

impl std::fmt::Debug for Walker<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walker")
            .field("budgets", &self.budgets)
            .finish_non_exhaustive()
    }
}

fn sys(context: String) -> impl FnOnce(rustix::io::Errno) -> Error {
    move |e| Error::io(context, std::io::Error::from_raw_os_error(e.raw_os_error()))
}

impl<'c> Walker<'c> {
    /// A walker with `budgets`.
    pub fn new(catalog: &'c Catalog, budgets: Budgets) -> Self {
        Self {
            catalog,
            budgets,
            before_open: None,
        }
    }

    /// Test hook: `f(relative path)` runs right before each `openat`.
    pub fn before_open(mut self, f: impl Fn(&Path) + 'c) -> Self {
        self.before_open = Some(Box::new(f));
        self
    }

    /// Walks `root` (absolute, canonical; the caller checked it with
    /// [`crate::mode::refused_root`]).
    pub fn walk(&self, root: &Path) -> Result<Scan, Error> {
        let start = Instant::now();
        let mut scan = Scan::default();
        let root_fd = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            FsMode::empty(),
        )
        .map_err(sys(format!("opening {}", root.display())))?;
        scan.opened.push(".".to_owned());
        let dev = rustix::fs::fstat(&root_fd)
            .map_err(sys(format!("reading {}", root.display())))?
            .st_dev;
        let mut stack: Vec<(OwnedFd, PathBuf)> = vec![(root_fd, PathBuf::new())];
        let mut sources_read = 0u64;
        'outer: while let Some((fd, rel)) = stack.pop() {
            let Ok(dir) = Dir::read_from(&fd) else {
                continue;
            };
            let mut children: Vec<(String, FileType)> = Vec::new();
            for entry in dir {
                let Ok(entry) = entry else { break };
                let Ok(name) = entry.file_name().to_str() else {
                    continue;
                };
                if name == "." || name == ".." {
                    continue;
                }
                scan.entries += 1;
                if scan.entries > self.budgets.max_entries {
                    scan.stopped_early = true;
                    scan.stop_reason = Some(format!(
                        "after {} files and folders",
                        self.budgets.max_entries
                    ));
                    break 'outer;
                }
                if start.elapsed() > self.budgets.max_time {
                    scan.stopped_early = true;
                    scan.stop_reason = Some(format!(
                        "after {} s",
                        self.budgets.max_time.as_secs().max(1)
                    ));
                    break 'outer;
                }
                children.push((name.to_owned(), entry.file_type()));
            }
            children.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, ft) in children {
                let child_rel = rel.join(&name);
                let shown = child_rel.to_string_lossy().into_owned();
                let ft = if ft == FileType::Unknown {
                    match rustix::fs::statat(&fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                        Ok(st) => FileType::from_raw_mode(st.st_mode),
                        Err(_) => continue,
                    }
                } else {
                    ft
                };
                match ft {
                    // Never followed.
                    FileType::Symlink => {}
                    FileType::Directory => {
                        if SKIP_DIRS.contains(&name.as_str()) {
                            continue;
                        }
                        if let Some(f) = &self.before_open {
                            f(&child_rel);
                        }
                        // O_NOFOLLOW + O_DIRECTORY: a symlink swapped in since readdir fails.
                        let Ok(child) = rustix::fs::openat(
                            &fd,
                            name.as_str(),
                            OFlags::RDONLY
                                | OFlags::DIRECTORY
                                | OFlags::NOFOLLOW
                                | OFlags::CLOEXEC
                                | OFlags::NONBLOCK,
                            FsMode::empty(),
                        ) else {
                            continue;
                        };
                        scan.opened.push(shown.clone());
                        let Ok(st) = rustix::fs::fstat(&child) else {
                            continue;
                        };
                        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                            continue;
                        }
                        if st.st_dev != dev {
                            scan.other_device.push(shown);
                            continue;
                        }
                        stack.push((child, child_rel));
                    }
                    FileType::RegularFile => {
                        let Some(kind) = classify(&name) else {
                            continue;
                        };
                        self.file(&fd, &name, &child_rel, kind, &mut scan, &mut sources_read);
                    }
                    _ => {}
                }
            }
        }
        scan.env_files.sort_by(|a, b| {
            let depth = |p: &str| p.matches('/').count();
            depth(a).cmp(&depth(b)).then_with(|| a.cmp(b))
        });
        scan.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(scan)
    }

    fn file(
        &self,
        dir: &OwnedFd,
        name: &str,
        rel: &Path,
        kind: Kind,
        scan: &mut Scan,
        sources_read: &mut u64,
    ) {
        let shown = rel.to_string_lossy().into_owned();
        let limit = match kind {
            Kind::Env => {
                // Paths only: the importer opens it itself, without following a symlink.
                match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
                        if u64::try_from(st.st_size).unwrap_or(u64::MAX)
                            > self.budgets.max_env_bytes
                        {
                            scan.too_large.push(shown);
                        } else {
                            scan.env_files.push(shown);
                        }
                    }
                    _ => {}
                }
                return;
            }
            Kind::Example => self.budgets.max_env_bytes,
            Kind::Source => {
                if *sources_read >= self.budgets.max_source_files {
                    if !scan.stopped_early {
                        scan.stop_reason.get_or_insert_with(|| {
                            format!(
                                "source files: only the first {} were searched",
                                self.budgets.max_source_files
                            )
                        });
                    }
                    return;
                }
                self.budgets.max_source_bytes
            }
        };
        if let Some(f) = &self.before_open {
            f(rel);
        }
        let Ok(fd) = rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            FsMode::empty(),
        ) else {
            return;
        };
        scan.opened.push(shown.clone());
        let Some(bytes) = read_regular(&fd, limit) else {
            scan.too_large.push(shown);
            return;
        };
        match kind {
            Kind::Example => {
                if let Ok(text) = std::str::from_utf8(&bytes)
                    && let Ok(entries) = ms_import::dotenv::parse(text)
                {
                    scan.examples.push(Example {
                        path: shown,
                        vars: entries.into_iter().map(|e| e.name.clone()).collect(),
                    });
                }
            }
            Kind::Source => {
                *sources_read += 1;
                scan.findings
                    .extend(find_keys(self.catalog, &shown, &bytes));
            }
            Kind::Env => {}
        }
    }
}

/// Reads a regular file of at most `limit` bytes into zeroizing memory; `None` for anything
/// else or anything larger.
fn read_regular(fd: &OwnedFd, limit: u64) -> Option<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let st = rustix::fs::fstat(fd).ok()?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || u64::try_from(st.st_size).unwrap_or(u64::MAX) > limit
    {
        return None;
    }
    let mut f = std::fs::File::from(fd.as_fd().try_clone_to_owned().ok()?);
    let mut buf = Zeroizing::new(Vec::new());
    (&mut f).take(limit + 1).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 <= limit).then_some(buf)
}

/// Code findings in one source file: tokens that start with a catalog value prefix. The masked
/// form shows only the catalog prefix and the length.
pub fn find_keys(catalog: &Catalog, path: &str, bytes: &[u8]) -> Vec<CodeFinding> {
    // `=` and `:` end a token, so `KEY=sk_live_…` and `key: sk_live_…` are found too.
    let token = |b: u8| b.is_ascii_alphanumeric() || b"_-./+".contains(&b);
    let mut out = Vec::new();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let mut j = 0;
        while j < line.len() {
            if !token(line[j]) {
                j += 1;
                continue;
            }
            let start = j;
            while j < line.len() && token(line[j]) {
                j += 1;
            }
            let tok = &line[start..j];
            if let Some((p, pre)) = catalog.match_prefix(tok) {
                out.push(CodeFinding {
                    path: path.to_owned(),
                    line: i + 1,
                    provider: p.id.clone(),
                    masked: format!("{}… ({} bytes)", pre.prefix, tok.len()),
                });
                break;
            }
        }
    }
    out
}

/// Walks `root` with the default budgets.
pub fn walk(catalog: &Catalog, root: &Path) -> Result<Scan, Error> {
    Walker::new(catalog, Budgets::default()).walk(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    const CANARY: &str = concat!("sk_live_", "WALKCANARY0123456789abcdefABCDEF");

    fn cat() -> &'static Catalog {
        Catalog::builtin()
    }

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        for dir in ["apps/web", "node_modules/x", "src", "outside", "proj"] {
            std::fs::create_dir_all(p.join(dir)).unwrap();
        }
        std::fs::write(p.join(".env"), "A=1\n").unwrap();
        std::fs::write(p.join("apps/web/.env"), "A=1\n").unwrap();
        std::fs::write(p.join(".env.production"), "A=1\n").unwrap();
        std::fs::write(p.join(".env.example"), "STRIPE_SECRET_KEY=\nAPP_FLAG=\n").unwrap();
        std::fs::write(p.join("node_modules/x/.env"), format!("K={CANARY}\n")).unwrap();
        std::fs::write(
            p.join("src/stripe.ts"),
            format!("import x\n\n// key\nconst k = \"{CANARY}\";\n"),
        )
        .unwrap();
        d
    }

    // protects=design §4.5 classification: env, example and source names are told apart, and an
    // example file is never an env file; fails_when=.env.example is imported or .env.local is
    // missed; no_claim=content-based detection
    #[test]
    fn file_classification() {
        for (n, k) in [
            (".env", Some(Kind::Env)),
            (".env.local", Some(Kind::Env)),
            (".env.production", Some(Kind::Env)),
            ("prod.env", Some(Kind::Env)),
            (".dev.vars", Some(Kind::Env)),
            (".envrc", Some(Kind::Env)),
            (".env.example", Some(Kind::Example)),
            (".env.sample", Some(Kind::Example)),
            (".env.template", Some(Kind::Example)),
            (".env.dist", Some(Kind::Example)),
            ("config.example", Some(Kind::Example)),
            ("stripe.ts", Some(Kind::Source)),
            ("a.json", Some(Kind::Source)),
            ("README.md", None),
            (".env-cmdrc", None),
            ("Makefile", None),
        ] {
            assert_eq!(classify(n), k, "{n}");
        }
    }

    // protects=design §4.5: the walk finds the three real env files, reads the example for names
    // only, reports the source canary as a masked code finding, and never enters node_modules or
    // any other listed directory; fails_when=a skipped directory is opened or the canary appears
    // in the scan result; no_claim=-
    #[test]
    fn scan_skips_dependency_dirs() {
        let d = tree();
        for s in SKIP_DIRS {
            std::fs::create_dir_all(d.path().join("proj").join(s)).unwrap();
            std::fs::write(d.path().join("proj").join(s).join(".env"), "A=1\n").unwrap();
        }
        let scan = walk(cat(), d.path()).unwrap();
        assert_eq!(
            scan.env_files,
            vec![".env", ".env.production", "apps/web/.env"],
            "{scan:?}"
        );
        assert!(
            scan.opened
                .iter()
                .all(|p| !SKIP_DIRS.iter().any(|s| p.split('/').any(|seg| seg == *s))),
            "{:?}",
            scan.opened
        );
        assert_eq!(scan.examples.len(), 1);
        assert_eq!(scan.examples[0].vars, vec!["STRIPE_SECRET_KEY", "APP_FLAG"]);
        assert_eq!(
            scan.findings,
            vec![CodeFinding {
                path: "src/stripe.ts".into(),
                line: 4,
                provider: "stripe".into(),
                masked: format!("sk_live_… ({} bytes)", CANARY.len()),
            }]
        );
        assert!(!format!("{scan:?}").contains(CANARY));
        assert!(!scan.stopped_early);
    }

    // protects=design §4.5 code findings: a key after `=`, `:` or a quote is found with its line
    // and a masked form holding only the catalog prefix and the length; plain text and refs are
    // not findings; fails_when=a key next to `=` is missed or any value byte past the prefix is
    // in the finding; no_claim=keys of providers the catalog doesn't know
    #[test]
    fn code_findings_are_masked() {
        let text = format!("a\nSTRIPE={CANARY}\nk: {CANARY}\nx = 'ms://shop/k'\nplain sk_live_\n");
        let f = find_keys(cat(), "c.yml", text.as_bytes());
        assert_eq!(f.iter().map(|f| f.line).collect::<Vec<_>>(), vec![2, 3]);
        for x in &f {
            assert_eq!(x.masked, format!("sk_live_… ({} bytes)", CANARY.len()));
            assert!(!format!("{x:?}").contains(&CANARY[8..]));
        }
    }

    // protects=design §4.5 symlinks: a symlinked env file, a symlinked directory and a directory
    // swapped for a symlink between readdir and openat are never followed, and nothing outside
    // the root is opened; fails_when=a path through a symlink is listed or opened;
    // no_claim=hard links (the importer refuses those)
    #[test]
    fn scan_never_follows_symlinks() {
        let d = tree();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("deep")).unwrap();
        std::fs::write(outside.path().join(".env"), format!("K={CANARY}\n")).unwrap();
        std::fs::write(outside.path().join("deep/.env"), format!("K={CANARY}\n")).unwrap();
        std::fs::write(outside.path().join("deep/k.ts"), format!("\"{CANARY}\"\n")).unwrap();
        symlink(outside.path().join(".env"), d.path().join(".env.link")).unwrap();
        symlink(outside.path().join("deep"), d.path().join("linked")).unwrap();
        // The race: "swap" is a real directory at readdir time and a symlink at openat time.
        std::fs::create_dir(d.path().join("swap")).unwrap();
        let swapped = Cell::new(false);
        let root = d.path().to_path_buf();
        let target = outside.path().join("deep");
        let w = Walker::new(cat(), Budgets::default()).before_open(|rel| {
            if rel == Path::new("swap") && !swapped.get() {
                std::fs::remove_dir(root.join("swap")).unwrap();
                symlink(&target, root.join("swap")).unwrap();
                swapped.set(true);
            }
        });
        let scan = w.walk(d.path()).unwrap();
        assert!(swapped.get(), "the race hook never ran");
        assert_eq!(
            scan.env_files,
            vec![".env", ".env.production", "apps/web/.env"]
        );
        for p in &scan.opened {
            assert!(
                !p.starts_with("linked") && !p.starts_with("swap") && !p.contains(".env.link"),
                "opened through a symlink: {p}"
            );
        }
        assert_eq!(scan.findings.len(), 1, "{:?}", scan.findings);
    }

    // protects=design §4.5 budgets: the entry budget stops the walk with stopped_early and a
    // reason; the source-file budget caps reads; an env file over the size budget is not taken;
    // fails_when=the walk runs past a budget or reports a complete scan; no_claim=the 10 s wall
    // clock (same check, not timed here)
    #[test]
    fn scan_budget_stops_early() {
        let d = tree();
        for i in 0..50 {
            std::fs::write(d.path().join(format!("f{i}.txt")), "x").unwrap();
        }
        let b = Budgets {
            max_entries: 10,
            ..Budgets::default()
        };
        let scan = Walker::new(cat(), b).walk(d.path()).unwrap();
        assert!(scan.stopped_early);
        assert_eq!(scan.entries, 11);
        assert!(scan.stop_reason.as_deref().unwrap().contains("10"));

        let b = Budgets {
            max_source_files: 0,
            max_env_bytes: 2,
            ..Budgets::default()
        };
        let scan = Walker::new(cat(), b).walk(d.path()).unwrap();
        assert!(scan.findings.is_empty());
        assert!(scan.env_files.is_empty(), "{:?}", scan.env_files);
        assert!(scan.too_large.iter().any(|p| p == ".env"));
        assert!(scan.stop_reason.is_some());
        let b = Budgets {
            max_time: Duration::ZERO,
            ..Budgets::default()
        };
        let scan = Walker::new(cat(), b).walk(d.path()).unwrap();
        assert!(scan.stopped_early);
    }

    // protects=design §4.5 one device: a directory on another file system is opened only to read
    // its device and is never entered. Uses "/" and its /dev (devfs on macOS); when /dev is on
    // the same device this test says SKIPPED and checks nothing; fails_when=a path under the
    // other device is opened; no_claim=network mounts and firmlinks
    #[test]
    #[allow(clippy::print_stderr)]
    fn scan_stays_on_one_device() {
        use std::os::unix::fs::MetadataExt;
        let same =
            std::fs::metadata("/").unwrap().dev() == std::fs::metadata("/dev").unwrap().dev();
        if same {
            eprintln!("SKIPPED: /dev is on the same device as /, no second file system here");
            return;
        }
        let b = Budgets {
            max_entries: 200,
            max_source_files: 0,
            ..Budgets::default()
        };
        let scan = Walker::new(cat(), b).walk(Path::new("/")).unwrap();
        assert!(
            scan.other_device.iter().any(|p| p == "dev"),
            "{:?}",
            scan.other_device
        );
        assert!(!scan.opened.iter().any(|p| p.starts_with("dev/")));
    }
}
