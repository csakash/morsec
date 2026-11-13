//! The receipts store: append-only JSONL, hash-chained, every record HMAC'd with a vault key.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ms_core::{Error, KeyName, ReceiptEvent, ReceiptResult, Result, SessionId};
use ms_vault::Vault;

use crate::read::{list_files, parse_line, split_lines};
use crate::record::{
    Alert, AlertAction, Approval, Checkpoint, Entry, FORMAT_VERSION, GENESIS_PREV, HMAC_KEY_NAME,
    MIN_KEY_LEN, Rec, Receipt, file_name, hash_rec, line, mac_ok, mac_rec,
};
use crate::redact::{MAX_SHORT, MAX_TARGET, Redactor, clean, clean_argv};
use crate::verify::short_key;
use crate::{ReceiptId, ReceiptSink};

/// Store settings.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Start a new file once the current one reaches this size.
    pub max_file_bytes: u64,
    /// Write a checkpoint after every record whose seq is a multiple of this (at least 2).
    pub checkpoint_every: u64,
    /// `fsync` after every record. On by default: receipts are evidence.
    pub fsync: bool,
    /// LOG-2: blocked or denied attempts by one session that raise an alert.
    pub alert_threshold: u32,
    /// LOG-2: the window those attempts must fall in.
    pub alert_window_ms: u64,
    /// LOG-2: ask the daemon to stop the session when an alert fires.
    pub stop_session_on_alert: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 << 20,
            checkpoint_every: 1000,
            fsync: true,
            alert_threshold: 5,
            alert_window_ms: 10 * 60 * 1000,
            stop_session_on_alert: false,
        }
    }
}

/// Fields the frozen [`ReceiptEvent`] does not carry.
#[derive(Default)]
pub struct ReceiptDetail<'a> {
    /// The argv, before redaction (the store redacts it).
    pub argv: Option<Vec<String>>,
    /// Who approved.
    pub approval_by: Option<String>,
    /// How they approved (`touch_id`, `password`…).
    pub approval_method: Option<String>,
    /// Extra redaction for this record, typically a [`crate::ValueRedactor`] holding the value
    /// the broker just used.
    pub redactor: Option<&'a dyn Redactor>,
}

impl fmt::Debug for ReceiptDetail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // argv is unredacted here, so it is never printed.
        f.debug_struct("ReceiptDetail")
            .field("argv_len", &self.argv.as_ref().map(Vec::len))
            .field("has_redactor", &self.redactor.is_some())
            .finish_non_exhaustive()
    }
}

/// Called after an alert record is written (LOG-2). The daemon stops the session when
/// [`Alert::action`] is [`AlertAction::StopSession`].
pub trait AlertHandler: Send + Sync {
    /// Handles one alert. Runs outside the store lock, so it may append receipts.
    fn on_alert(&self, alert: &Alert);
}

struct Detector {
    threshold: u32,
    window_ms: u64,
    action: AlertAction,
    recent: HashMap<SessionId, VecDeque<(u64, u64)>>,
    /// After an alert, a session is not counted again until this time: one alert per window.
    quiet_until: HashMap<SessionId, u64>,
}

/// Most sessions tracked by the detector before idle ones are dropped.
const MAX_TRACKED_SESSIONS: usize = 4096;

impl Detector {
    /// Records a blocked or denied attempt; returns an alert when the threshold is reached.
    fn observe(&mut self, session: &SessionId, time: u64, seq: u64) -> Option<Alert> {
        if self.threshold == 0 {
            return None;
        }
        if self.recent.len() >= MAX_TRACKED_SESSIONS && !self.recent.contains_key(session) {
            let window = self.window_ms;
            self.recent.retain(|_, q| {
                q.back()
                    .is_some_and(|(t, _)| time.saturating_sub(*t) <= window)
            });
        }
        let q = self.recent.entry(session.clone()).or_default();
        q.push_back((time, seq));
        while q
            .front()
            .is_some_and(|(t, _)| time.saturating_sub(*t) > self.window_ms)
        {
            q.pop_front();
        }
        if q.len() < self.threshold as usize {
            return None;
        }
        let first_seq = q.front().map_or(seq, |(_, s)| *s);
        // One alert per window: the session is not counted again until the window has passed.
        q.clear();
        self.quiet_until
            .insert(session.clone(), time.saturating_add(self.window_ms));
        Some(Alert {
            session: session.clone(),
            blocked_count: self.threshold,
            window_ms: self.window_ms,
            first_seq,
            last_seq: seq,
            action: self.action,
        })
    }
}

struct State {
    file: File,
    file_bytes: u64,
    next_seq: u64,
    prev: [u8; 32],
    /// Set after a failed write: the file may hold a partial line, so nothing more is appended.
    broken: bool,
    detector: Detector,
}

/// The hash-chained, HMAC'd receipts store.
pub struct ReceiptStore {
    dir: PathBuf,
    vault: Arc<dyn Vault>,
    key: KeyName,
    cfg: StoreConfig,
    alert_handler: Option<Box<dyn AlertHandler>>,
    state: Mutex<State>,
}

impl fmt::Debug for ReceiptStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptStore")
            .field("dir", &self.dir)
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

fn fail(context: impl Into<String>, fix: &str) -> Error {
    Error::io(context, std::io::Error::other(fix.to_owned()))
}

/// Creates `dir` 0700, or checks an existing one: a real directory (not a symlink), owned by
/// this user, with no group or other access.
fn prepare_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.is_dir() {
                return Err(fail(
                    format!("receipts path {} is not a directory", dir.display()),
                    "move it aside; morsec creates the directory itself",
                ));
            }
            if m.mode() & 0o077 != 0 {
                return Err(fail(
                    format!(
                        "receipts directory {} is accessible to other users (mode {:o})",
                        dir.display(),
                        m.mode() & 0o777
                    ),
                    "fix it with: chmod 700 on that directory",
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::io(format!("creating {}", dir.display()), e)),
        Err(e) => Err(Error::io(format!("checking {}", dir.display()), e)),
    }
}

fn open_append(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(path)
        .map_err(|e| Error::io(format!("opening {}", path.display()), e))?;
    let m = f
        .metadata()
        .map_err(|e| Error::io(format!("checking {}", path.display()), e))?;
    if !m.is_file() || m.mode() & 0o077 != 0 {
        return Err(fail(
            format!(
                "receipts file {} is not a private regular file (mode {:o})",
                path.display(),
                m.mode() & 0o777
            ),
            "fix it with: chmod 600 on that file",
        ));
    }
    Ok(f)
}

/// `O_NOFOLLOW`, so a symlink planted at a receipts file name is refused, not followed.
#[cfg(target_os = "macos")]
const fn nofollow() -> i32 {
    0x0100
}
#[cfg(target_os = "linux")]
const fn nofollow() -> i32 {
    0o400000
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn nofollow() -> i32 {
    0
}

impl ReceiptStore {
    /// Opens (or creates) the store in `dir`.
    ///
    /// Fails closed when the receipts key is missing or short, the directory is not private,
    /// the last record's MAC is wrong, or the last line is incomplete.
    pub fn open(dir: impl Into<PathBuf>, vault: Arc<dyn Vault>, cfg: StoreConfig) -> Result<Self> {
        let dir = dir.into();
        if cfg.checkpoint_every < 2 {
            return Err(fail(
                "receipts checkpoint_every must be at least 2",
                "fix the store configuration",
            ));
        }
        let key = KeyName::new(HMAC_KEY_NAME)?;
        prepare_dir(&dir)?;

        let files = list_files(&dir)?;
        let mut next_seq = 1;
        let mut prev = GENESIS_PREV;
        // Resume from the newest file that has a record.
        let mut current: Option<PathBuf> = None;
        for f in files.iter().rev() {
            let bytes = fs::read(&f.path)
                .map_err(|e| Error::io(format!("reading {}", f.path.display()), e))?;
            let (lines, torn) = split_lines(&bytes);
            if torn {
                return Err(fail(
                    format!("the last receipt in {} is incomplete", f.path.display()),
                    "inspect it with: ms log --verify, then move that file aside",
                ));
            }
            let Some(last) = lines.last() else {
                // An empty newest file (crash right after rotation): reuse it if its name fits.
                if current.is_none() {
                    current = Some(f.path.clone());
                }
                continue;
            };
            let p = parse_line(last).map_err(|why| {
                fail(
                    format!(
                        "the last receipt in {} is unreadable ({why})",
                        f.path.display()
                    ),
                    "inspect it with: ms log --verify",
                )
            })?;
            let mut ok = None;
            vault.with_secret(&key, &mut |k| {
                ok = Some(k.len() >= MIN_KEY_LEN && mac_ok(k, p.raw, &p.mac));
            })?;
            match ok {
                Some(true) => {}
                Some(false) => {
                    return Err(fail(
                        format!(
                            "the last receipt in {} fails its MAC check (tampered, or the key changed)",
                            f.path.display()
                        ),
                        "inspect it with: ms log --verify",
                    ));
                }
                None => return Err(Error::NoSuchKey(HMAC_KEY_NAME.into())),
            }
            if p.rec.v != FORMAT_VERSION {
                return Err(fail(
                    format!("unknown receipt format version {}", p.rec.v),
                    "upgrade morsec",
                ));
            }
            next_seq = p.rec.seq + 1;
            prev = hash_rec(p.raw);
            if current.is_none() {
                current = Some(f.path.clone());
            }
            break;
        }
        // Even with no records yet, the key must be there and long enough.
        let mut key_ok = None;
        vault.with_secret(&key, &mut |k| key_ok = Some(k.len() >= MIN_KEY_LEN))?;
        if key_ok != Some(true) {
            return Err(short_key());
        }

        let path = match current {
            Some(p) => {
                let named = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(crate::record::parse_file_name);
                let empty = fs::metadata(&p).map_or(true, |m| m.len() == 0);
                // An empty newest file must be named for the next record.
                if !empty || named == Some(next_seq) {
                    p
                } else {
                    return Err(fail(
                        format!("receipts file {} is empty and misnamed", p.display()),
                        "move it aside",
                    ));
                }
            }
            None => dir.join(file_name(next_seq)),
        };
        let file = open_append(&path)?;
        let fmeta = file
            .metadata()
            .map_err(|e| Error::io("checking receipts file", e))?;
        // The file is ours (we just opened or created it), so the directory must be too.
        let dmeta = fs::metadata(&dir).map_err(|e| Error::io("checking receipts directory", e))?;
        if dmeta.uid() != fmeta.uid() {
            return Err(fail(
                format!(
                    "receipts directory {} belongs to another user",
                    dir.display()
                ),
                "use a directory owned by the user that runs msd",
            ));
        }
        let file_bytes = fmeta.len();
        let detector = Detector {
            threshold: cfg.alert_threshold,
            window_ms: cfg.alert_window_ms,
            action: if cfg.stop_session_on_alert {
                AlertAction::StopSession
            } else {
                AlertAction::None
            },
            recent: HashMap::new(),
            quiet_until: HashMap::new(),
        };
        Ok(Self {
            dir,
            vault,
            key,
            cfg,
            alert_handler: None,
            state: Mutex::new(State {
                file,
                file_bytes,
                next_seq,
                prev,
                broken: false,
                detector,
            }),
        })
    }

    /// Sets the LOG-2 alert handler.
    pub fn with_alert_handler(mut self, h: Box<dyn AlertHandler>) -> Self {
        self.alert_handler = Some(h);
        self
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Seq the next record will get.
    pub fn next_seq(&self) -> u64 {
        self.lock().next_seq
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic mid-append leaves `broken` set if the write failed; the state is otherwise sound.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Appends a receipt with the fields the frozen event lacks. Every agent-supplied string is
    /// redacted and capped before anything is written.
    pub fn append_detailed(
        &self,
        event: ReceiptEvent,
        detail: ReceiptDetail<'_>,
    ) -> Result<ReceiptId> {
        let extra = detail.redactor;
        let short = |s: Option<String>| s.map(|s| clean(&s, extra, MAX_SHORT));
        let mut session = event.session;
        if let ms_core::AgentKind::Other(name) = &session.agent {
            session.agent = ms_core::AgentKind::Other(clean(name, extra, MAX_SHORT));
        }
        let result = match event.result {
            ReceiptResult::Failed(m) => ReceiptResult::Failed(clean(&m, extra, MAX_SHORT)),
            r => r,
        };
        let approval = if event.approval_id.is_some()
            || detail.approval_by.is_some()
            || detail.approval_method.is_some()
        {
            Some(Approval {
                token_id: short(event.approval_id),
                by: short(detail.approval_by),
                method: short(detail.approval_method),
            })
        } else {
            None
        };
        let blocked = matches!(result, ReceiptResult::Blocked(_) | ReceiptResult::Denied);
        let receipt = Receipt {
            session: session.clone(),
            key: event.key,
            mechanism: event.mode,
            target: clean(&event.target, extra, MAX_TARGET),
            argv_hash: event.argv_hash.map(hex::encode),
            argv_redacted: detail.argv.as_deref().map(|a| clean_argv(a, extra)),
            rule_version: event.rule_version,
            approval,
            result,
        };
        let time = event.time_unix_ms;

        let mut st = self.lock();
        if st.broken {
            return Err(fail(
                "an earlier receipt write failed, so receipts are stopped",
                "restart the daemon after checking: ms log --verify",
            ));
        }
        if st.file_bytes >= self.cfg.max_file_bytes {
            self.rotate(&mut st, time)?;
        }
        let seq = self.write(&mut st, time, Entry::Receipt(receipt))?;
        if seq % self.cfg.checkpoint_every == 0 {
            self.checkpoint(&mut st, time)?;
        }
        let alert = if blocked {
            st.detector.observe(&session, time, seq)
        } else {
            None
        };
        if let Some(a) = &alert {
            self.write(&mut st, time, Entry::Alert(a.clone()))?;
        }
        drop(st);
        if let (Some(a), Some(h)) = (&alert, &self.alert_handler) {
            h.on_alert(a);
        }
        Ok(ReceiptId(seq))
    }

    fn checkpoint(&self, st: &mut State, time: u64) -> Result<()> {
        let c = Checkpoint {
            through_seq: st.next_seq - 1,
            head: hex::encode(st.prev),
        };
        self.write(st, time, Entry::Checkpoint(c)).map(drop)
    }

    fn rotate(&self, st: &mut State, time: u64) -> Result<()> {
        self.checkpoint(st, time)?;
        let path = self.dir.join(file_name(st.next_seq));
        if fs::symlink_metadata(&path).is_ok() {
            st.broken = true;
            return Err(fail(
                format!("receipts file {} already exists", path.display()),
                "inspect it with: ms log --verify",
            ));
        }
        st.file = open_append(&path)?;
        st.file_bytes = 0;
        Ok(())
    }

    /// Writes one record as a single line. Returns its seq.
    fn write(&self, st: &mut State, time: u64, entry: Entry) -> Result<u64> {
        let seq = st.next_seq;
        let rec = Rec {
            v: FORMAT_VERSION,
            seq,
            prev: hex::encode(st.prev),
            time_unix_ms: time,
            entry,
        };
        let json = serde_json::to_string(&rec)
            .map_err(|e| fail(format!("encoding receipt: {e}"), "report this as a bug"))?;
        let mut mac = None;
        self.vault.with_secret(&self.key, &mut |k| {
            mac = (k.len() >= MIN_KEY_LEN).then(|| mac_rec(k, json.as_bytes()));
        })?;
        let mac = mac.ok_or_else(short_key)?;
        let text = line(&json, &mac);
        let written = st.file.write_all(text.as_bytes()).and_then(|()| {
            if self.cfg.fsync {
                st.file.sync_data()
            } else {
                Ok(())
            }
        });
        if let Err(e) = written {
            st.broken = true;
            return Err(Error::io("writing receipt", e));
        }
        st.file_bytes += text.len() as u64;
        st.prev = hash_rec(json.as_bytes());
        st.next_seq += 1;
        Ok(seq)
    }
}

impl ReceiptSink for ReceiptStore {
    fn append(&self, event: ReceiptEvent) -> Result<ReceiptId> {
        self.append_detailed(event, ReceiptDetail::default())
    }
}

/// Permission bits of `path`, for tests and `ms doctor`.
pub fn mode_of(path: &Path) -> Result<u32> {
    fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .map_err(|e| Error::io(format!("checking {}", path.display()), e))
}
