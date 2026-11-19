//! `ms scan` inside msd (L09): search agent transcripts for vault values.
//!
//! The values never leave the daemon. msd picks the directories from its own environment (a
//! client names no path, SPEC D-2), builds every encoding of every value in zeroizing buffers
//! (`ms-scan`), streams each transcript through them, and answers with file, line, key name and
//! encoding only. One scan runs at a time; a scan stops at its time budget and says so.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ms_core::KeyName;
use ms_ipc::{ErrorCode, ResponseBody, ScanFinding};
use ms_scan::Needles;
use ms_vault::Vault;

/// How long one scan may read before it reports what it has (SPEC D-7). `ms` waits longer.
pub const SCAN_BUDGET: Duration = Duration::from_secs(240);
/// Most transcript files read in one scan.
pub const MAX_FILES: usize = 200_000;
/// Most findings returned.
pub const MAX_FINDINGS: usize = 1000;
/// Most bytes of file names in one report, so it stays well under the 1 MiB frame limit.
pub const MAX_FINDING_BYTES: usize = 512 * 1024;

static SCANNING: AtomicBool = AtomicBool::new(false);

struct Running;
impl Drop for Running {
    fn drop(&mut self) {
        SCANNING.store(false, Ordering::Release);
    }
}

/// The transcript directories, from msd's own environment: Claude Code
/// (`$CLAUDE_CONFIG_DIR/projects`, else `~/.claude/projects`) and Codex
/// (`$CODEX_HOME/sessions`, else `~/.codex/sessions`).
pub fn roots() -> Vec<PathBuf> {
    let env_dir = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let home = env_dir("HOME");
    let mut out = Vec::new();
    if let Some(d) =
        env_dir("CLAUDE_CONFIG_DIR").or_else(|| home.as_ref().map(|h| h.join(".claude")))
    {
        out.push(d.join("projects"));
    }
    if let Some(d) = env_dir("CODEX_HOME").or_else(|| home.as_ref().map(|h| h.join(".codex"))) {
        out.push(d.join("sessions"));
    }
    canonical(out)
}

/// These roots come from msd's own environment, not a client (SPEC D-2), so a root that is
/// itself a link (dotfile setups, an external disk) is resolved; links under it are never
/// followed (review R2).
fn canonical(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    roots
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .collect()
}

/// Runs a scan over `roots` for the values of `keys`. Blocking.
pub fn scan(
    vault: &dyn Vault,
    keys: Vec<KeyName>,
    roots: &[PathBuf],
    budget: Duration,
) -> ResponseBody {
    if SCANNING.swap(true, Ordering::AcqRel) {
        return ResponseBody::error(
            ErrorCode::Busy,
            "morsec: a scan is already running. Wait for it to finish and try again",
        );
    }
    let _running = Running;
    let deadline = Instant::now() + budget;

    let mut needles = Needles::new();
    let mut checked = Vec::new();
    let mut skipped_keys = Vec::new();
    let mut notes = Vec::new();
    let mut complete = true;
    for key in keys {
        // Built apart and merged only when the read succeeded, so a key index always names a key
        // in `checked`.
        let mut one = Needles::new();
        let mut added = false;
        let read = vault.with_secret(&key, &mut |v| added = one.add(checked.len(), v));
        match read {
            Ok(()) if added => {
                needles.append(one);
                checked.push(key);
            }
            Ok(()) => skipped_keys.push(key),
            Err(e) => {
                tracing::warn!(key = %key, error = %e, "scan: key could not be read");
                notes.push(format!(
                    "{key} could not be read from the vault, so it was not searched for"
                ));
                complete = false;
            }
        }
    }

    for r in roots {
        notes.push(match std::fs::symlink_metadata(r) {
            Ok(m) if m.is_dir() => format!("Searched {}.", r.display()),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                format!("{} could not be read, so it was not searched.", r.display())
            }
            _ => format!(
                "{} doesn't exist, so there was nothing to search there.",
                r.display()
            ),
        });
    }
    let walk = ms_scan::transcript_files(roots, MAX_FILES);
    notes.extend(walk.notes);
    complete &= !walk.truncated && walk.unreadable == 0 && walk.links == 0;

    let mut findings = Vec::new();
    let (mut files, mut bytes, mut unreadable) = (0u64, 0u64, 0u64);
    let mut capped = false;
    // Counted, not listed: one note per file could outgrow the reply frame (review N1).
    let mut over_cap = 0u64;
    if !needles.is_empty() {
        let mut name_bytes = 0usize;
        for (i, path) in walk.files.iter().enumerate() {
            if Instant::now() >= deadline {
                complete = false;
                notes.push(format!(
                    "stopped after {}s; {} files were not scanned",
                    budget.as_secs(),
                    walk.files.len() - i
                ));
                break;
            }
            let result = ms_scan::open_regular(path).and_then(|f| {
                ms_scan::scan_reader(&needles, f, &mut || Instant::now() >= deadline)
            });
            let s = match result {
                Ok(s) => s,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            files += 1;
            bytes += s.bytes;
            if !s.complete && Instant::now() < deadline {
                over_cap += 1;
            }
            complete &= s.complete;
            let file = path.to_string_lossy().into_owned();
            for h in s.hits {
                if findings.len() >= MAX_FINDINGS || name_bytes + file.len() > MAX_FINDING_BYTES {
                    if !capped {
                        capped = true;
                        complete = false;
                        notes.push(format!(
                            "the list stops at {} findings; fix these and scan again",
                            findings.len()
                        ));
                    }
                    break;
                }
                name_bytes += file.len();
                findings.push(ScanFinding {
                    file: file.clone(),
                    line: h.line,
                    key: checked[h.key].clone(),
                    encoding: h.encoding.label().to_owned(),
                });
            }
        }
    }
    if unreadable > 0 {
        complete = false;
        notes.push(format!("{unreadable} files could not be read"));
    }
    if over_cap > 0 {
        notes.push(format!(
            "{over_cap} files have more than {} matches each; only the first are listed",
            ms_scan::MAX_HITS_PER_FILE
        ));
    }
    drop(needles);
    tracing::info!(files, findings = findings.len(), complete, "scan finished");
    ResponseBody::ScanReport {
        findings,
        files_scanned: files,
        bytes_scanned: bytes,
        keys_checked: u32::try_from(checked.len()).unwrap_or(u32::MAX),
        skipped_keys,
        notes,
        complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{KeyMeta, Mode, SecretBytes, Tier};
    use ms_vault::memory::MemoryVault;

    const CANARY: &str = "sk_test_SCAN_CANARY_7f3e91";
    // SCANNING is process-wide; these tests take turns.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn vault() -> (MemoryVault, Vec<KeyName>) {
        let v = MemoryVault::new();
        let mut names = Vec::new();
        for (n, val) in [("stripe/test", CANARY), ("tiny/key", "short")] {
            let name = KeyName::new(n).unwrap();
            v.put(
                &name,
                SecretBytes::new(val.as_bytes().to_vec()),
                KeyMeta {
                    name: name.clone(),
                    mode: Mode::Swap,
                    tier: Tier::Test,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
            names.push(name);
        }
        (v, names)
    }

    // protects=INJ-5 the report locates a leak by file, line, key and encoding and carries no
    // value in any form; short keys are named as skipped; fails_when=a leak is missed or the
    // reply's JSON contains the value or an encoding of it
    #[test]
    fn report_has_location_not_value() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (v, keys) = vault();
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("projects");
        std::fs::create_dir_all(root.join("p")).unwrap();
        std::fs::write(
            root.join("p/s.jsonl"),
            format!("{{}}\n{{\"text\":\"key is {CANARY}\"}}\n"),
        )
        .unwrap();
        let r = scan(&v, keys, std::slice::from_ref(&root), SCAN_BUDGET);
        let json = serde_json::to_string(&r).unwrap();
        let mut n = Needles::new();
        n.add(0, CANARY.as_bytes());
        assert!(ms_scan::find_in(&n, json.as_bytes()).is_empty(), "{json}");
        match r {
            ResponseBody::ScanReport {
                findings,
                skipped_keys,
                complete,
                keys_checked,
                ..
            } => {
                assert!(complete);
                assert_eq!(keys_checked, 1);
                assert_eq!(skipped_keys, vec![KeyName::new("tiny/key").unwrap()]);
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].line, 2);
                assert_eq!(findings[0].key.as_str(), "stripe/test");
                assert_eq!(findings[0].encoding, "raw");
                assert!(findings[0].file.ends_with("p/s.jsonl"));
            }
            other => panic!("{other:?}"),
        }
    }

    // protects=one scan at a time, and a zero budget reports an incomplete scan;
    // fails_when=a second concurrent scan runs or an out-of-time scan claims complete
    #[test]
    fn busy_and_budget() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (v, keys) = vault();
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("projects");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.jsonl"), "x\n").unwrap();
        SCANNING.store(true, Ordering::Release);
        let r = scan(&v, keys.clone(), std::slice::from_ref(&root), SCAN_BUDGET);
        assert!(
            matches!(
                r,
                ResponseBody::Error {
                    code: ErrorCode::Busy,
                    ..
                }
            ),
            "{r:?}"
        );
        SCANNING.store(false, Ordering::Release);
        match scan(&v, keys, &[root], Duration::ZERO) {
            ResponseBody::ScanReport { complete, .. } => assert!(!complete),
            other => panic!("{other:?}"),
        }
    }

    // protects=review R1/R2: an unreadable directory makes the scan incomplete (ms scan exits 1,
    // never 0), and a transcript root that is itself a symlink is resolved and searched;
    // fails_when=either case reports a complete clean scan
    #[test]
    fn unreadable_dir_and_linked_root() {
        use std::os::unix::fs::PermissionsExt;
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (v, keys) = vault();
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("disk/projects");
        std::fs::create_dir_all(real.join("p")).unwrap();
        std::fs::write(real.join("p/s.jsonl"), format!("{CANARY}\n")).unwrap();
        let link = d.path().join("projects");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match scan(&v, keys.clone(), &canonical(vec![link]), SCAN_BUDGET) {
            ResponseBody::ScanReport {
                findings, complete, ..
            } => {
                assert!(complete);
                assert_eq!(findings.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        let locked = real.join("p");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = scan(&v, keys, std::slice::from_ref(&real), SCAN_BUDGET);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        match r {
            ResponseBody::ScanReport {
                findings,
                complete,
                notes,
                ..
            } => {
                assert!(findings.is_empty());
                assert!(!complete, "{notes:?}");
            }
            other => panic!("{other:?}"),
        }
    }
}
