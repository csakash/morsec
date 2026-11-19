//! The dashboard's Copy (L33 SPEC D-20): msd writes the pasteboard itself, so the value never
//! reaches the browser, and marks the entry so it stays on this Mac and out of clipboard
//! managers:
//!
//! 1. `prepareForNewContentsWithOptions: NSPasteboardContentsCurrentHostOnly` (no Universal
//!    Clipboard to other devices), then `clearContents`;
//! 2. the text as `public.utf8-plain-text`;
//! 3. empty data for `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` (the
//!    nspasteboard.org markers clipboard managers honour);
//! 4. remember `changeCount`; after 30 s clear the pasteboard only if `changeCount` is unchanged
//!    (the person copied something else meanwhile: leave it).
//!
//! The Objective-C calls are in [`ffi`] (the one module with `unsafe`). [`Clipboard`] is what
//! msd uses; tests and `msd --test-pasteboard-to` use [`Marked`] over a fake [`PasteboardApi`].

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "macos")]
mod ffi;

/// The text type.
pub const TEXT: &str = "public.utf8-plain-text";
/// Clipboard managers don't show or keep it.
pub const CONCEALED: &str = "org.nspasteboard.ConcealedType";
/// Clipboard managers don't keep it in their history.
pub const TRANSIENT: &str = "org.nspasteboard.TransientType";

/// The pasteboard calls Copy makes, one per Objective-C message.
pub trait PasteboardApi: Send + Sync {
    /// `prepareForNewContentsWithOptions: NSPasteboardContentsCurrentHostOnly` (this also
    /// clears the pasteboard; a later `clearContents` would reset the option, so Copy never
    /// calls it after this: review S1).
    fn prepare_current_host_only(&self) -> Result<(), String>;
    /// `clearContents`.
    fn clear_contents(&self) -> Result<(), String>;
    /// One `NSPasteboardItem` holding `value` as `kind` and empty data for every marker type,
    /// all set before `writeObjects:` puts it on the pasteboard (review N1).
    fn write_item(&self, value: &str, kind: &str, markers: &[&str]) -> Result<(), String>;
    /// `changeCount`.
    fn change_count(&self) -> Result<i64, String>;
}

/// What msd uses to copy.
pub trait Clipboard: Send + Sync {
    /// Writes `text` with the markers and returns the change count right after. On any error
    /// the pasteboard is cleared before the error is returned (review R3).
    fn write(&self, text: &str) -> Result<i64, String>;
    /// The change count now.
    fn change_count(&self) -> Result<i64, String>;
    /// Clears the pasteboard.
    fn clear(&self) -> Result<(), String>;
}

/// A [`Clipboard`] that writes through `P` with every marker.
#[derive(Debug)]
pub struct Marked<P>(pub P);

impl<P: PasteboardApi> Clipboard for Marked<P> {
    fn write(&self, text: &str) -> Result<i64, String> {
        let p = &self.0;
        p.prepare_current_host_only()?;
        let written = p
            .write_item(text, TEXT, &[CONCEALED, TRANSIENT])
            .and_then(|()| p.change_count());
        if written.is_err() {
            // Nothing half-written stays behind.
            let _ = p.clear_contents();
        }
        written
    }
    fn change_count(&self) -> Result<i64, String> {
        self.0.change_count()
    }
    fn clear(&self) -> Result<(), String> {
        self.0.clear_contents()
    }
}

/// No pasteboard (not macOS).
#[cfg_attr(target_os = "macos", allow(dead_code))]
#[derive(Debug, Default)]
pub struct Unavailable;

impl Clipboard for Unavailable {
    fn write(&self, _text: &str) -> Result<i64, String> {
        Err("no pasteboard on this system".into())
    }
    fn change_count(&self) -> Result<i64, String> {
        Err("no pasteboard on this system".into())
    }
    fn clear(&self) -> Result<(), String> {
        Ok(())
    }
}

/// The system pasteboard.
pub fn system() -> Arc<dyn Clipboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(Marked(ffi::General))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(Unavailable)
    }
}

/// The copy still waiting for its clear: (pasteboard, change count after the write). msd
/// clears it on shutdown when nothing was copied since (review N4).
static PENDING: std::sync::Mutex<Option<(Arc<dyn Clipboard>, i64)>> = std::sync::Mutex::new(None);

fn pending() -> std::sync::MutexGuard<'static, Option<(Arc<dyn Clipboard>, i64)>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Clears `cb` if its change count is still `count` (nothing else was copied since).
fn clear_if_unchanged(cb: &dyn Clipboard, count: i64) {
    match cb.change_count() {
        Ok(now) if now == count => {
            if let Err(e) = cb.clear() {
                tracing::warn!(error = %e, "could not clear the pasteboard");
            }
        }
        Ok(_) => tracing::info!("the pasteboard changed since Copy; left as it is"),
        Err(e) => tracing::warn!(error = %e, "could not read the pasteboard"),
    }
}

/// Writes `text` and clears the pasteboard after `after` if nothing else was copied since.
/// The clear runs on its own thread; the call returns once the text is on the pasteboard. If
/// the clear can't be scheduled, the pasteboard is cleared now and the copy reported as failed.
pub fn copy_then_clear(cb: Arc<dyn Clipboard>, text: &str, after: Duration) -> Result<(), String> {
    let count = cb.write(text)?;
    *pending() = Some((cb.clone(), count));
    let later = cb.clone();
    let spawned = std::thread::Builder::new()
        .name("pasteboard-clear".into())
        .spawn(move || {
            std::thread::sleep(after);
            clear_if_unchanged(&*later, count);
            let mut p = pending();
            if p.as_ref().is_some_and(|(_, c)| *c == count) {
                *p = None;
            }
        });
    if let Err(e) = spawned {
        clear_if_unchanged(&*cb, count);
        *pending() = None;
        return Err(format!(
            "could not schedule the clear, so the copy was cleared now: {e}"
        ));
    }
    Ok(())
}

/// msd is exiting: a copy still within its 30 s is cleared now if nothing was copied since
/// (review N4).
pub fn clear_pending_now() {
    if let Some((cb, count)) = pending().take() {
        clear_if_unchanged(&*cb, count);
    }
}

/// `msd --test-pasteboard-to FILE` (debug build with the memory vault only, like
/// `--test-open-to`): a pasteboard in memory that appends one JSON line per write and per clear
/// to `FILE`: `{len, sha256 (first 8 bytes, hex), markers, cleared}`. Never the value.
#[derive(Debug)]
pub struct FilePasteboard {
    path: PathBuf,
    state: Mutex<FileState>,
}

#[derive(Debug, Default)]
struct FileState {
    count: i64,
    pending: Option<(usize, String)>,
    markers: Vec<&'static str>,
    on_board: bool,
}

impl FilePasteboard {
    /// Appends to `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::default(),
        }
    }

    fn line(&self, v: &serde_json::Value) {
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{v}"));
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not write the test pasteboard file");
        }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, FileState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl PasteboardApi for FilePasteboard {
    fn prepare_current_host_only(&self) -> Result<(), String> {
        let mut st = self.st();
        st.count += 1;
        let cleared = std::mem::take(&mut st.on_board);
        st.markers = vec!["current-host-only"];
        drop(st);
        if cleared {
            self.line(&serde_json::json!({ "cleared": true }));
        }
        Ok(())
    }
    fn clear_contents(&self) -> Result<(), String> {
        let mut st = self.st();
        st.count += 1;
        st.markers.clear();
        let cleared = std::mem::take(&mut st.on_board);
        drop(st);
        if cleared {
            self.line(&serde_json::json!({ "cleared": true }));
        }
        Ok(())
    }
    fn write_item(&self, value: &str, kind: &str, markers: &[&str]) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        let mut st = self.st();
        if kind == TEXT {
            st.markers.push("text");
        }
        for m in markers {
            st.markers.push(match *m {
                CONCEALED => "concealed",
                TRANSIENT => "transient",
                _ => "other",
            });
        }
        let h = Sha256::digest(value.as_bytes());
        st.pending = Some((value.len(), hex::encode(&h[..8])));
        Ok(())
    }
    fn change_count(&self) -> Result<i64, String> {
        let mut st = self.st();
        if let Some((len, sha)) = st.pending.take() {
            let line = serde_json::json!({
                "len": len,
                "sha256": sha,
                "markers": st.markers,
                "cleared": false,
            });
            let n = st.count;
            st.on_board = true;
            drop(st);
            self.line(&line);
            return Ok(n);
        }
        Ok(st.count)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    /// Records every call; `bump` stands for another app copying.
    #[derive(Debug, Default)]
    pub struct Fake {
        pub calls: Mutex<Vec<String>>,
        pub count: Mutex<i64>,
        pub text: Mutex<Option<String>>,
        /// The options and marker types the current contents carry.
        pub markers: Mutex<Vec<String>>,
        pub fail_write: Mutex<bool>,
    }

    impl Fake {
        pub fn bump(&self) {
            *self.count.lock().unwrap() += 1;
            *self.text.lock().unwrap() = Some("something else".into());
        }
        pub fn text(&self) -> Option<String> {
            self.text.lock().unwrap().clone()
        }
    }

    impl PasteboardApi for Arc<Fake> {
        fn prepare_current_host_only(&self) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push("prepare:current-host-only".into());
            *self.count.lock().unwrap() += 1;
            *self.text.lock().unwrap() = None;
            *self.markers.lock().unwrap() = vec!["current-host-only".into()];
            Ok(())
        }
        fn clear_contents(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("clear".into());
            *self.count.lock().unwrap() += 1;
            *self.text.lock().unwrap() = None;
            // Like the real pasteboard, a clear resets the options prepare set (review S1).
            self.markers.lock().unwrap().clear();
            Ok(())
        }
        fn write_item(&self, value: &str, kind: &str, markers: &[&str]) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("item:{kind}+{}", markers.join("+")));
            if *self.fail_write.lock().unwrap() {
                // Simulates a half-done write: the text went on, then an error.
                *self.text.lock().unwrap() = Some(value.to_owned());
                return Err("injected write failure".into());
            }
            *self.text.lock().unwrap() = Some(value.to_owned());
            self.markers
                .lock()
                .unwrap()
                .extend(markers.iter().map(|m| (*m).to_owned()));
            Ok(())
        }
        fn change_count(&self) -> Result<i64, String> {
            Ok(*self.count.lock().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    const V: &str = concat!("sk_live_", "PASTE_CANARY_77");

    // protects=SPEC D-20, T-92, review S1 and N1: every Copy prepares the pasteboard for this
    // host only and then writes one item that already carries the text and the concealed and
    // transient markers; nothing clears the pasteboard after prepare (a clear would drop
    // current-host-only, letting the value reach Universal Clipboard); fails_when=a marker is
    // missing, a clear follows prepare, or the text is written before its markers;
    // no_claim=what a given clipboard manager does with the markers (manual check)
    #[test]
    fn pasteboard_markers_set() {
        let f = Arc::new(Fake::default());
        let cb = Marked(f.clone());
        cb.write(V).unwrap();
        assert_eq!(
            *f.calls.lock().unwrap(),
            [
                "prepare:current-host-only",
                "item:public.utf8-plain-text+org.nspasteboard.ConcealedType+org.nspasteboard.TransientType",
            ]
        );
        assert_eq!(f.text().as_deref(), Some(V));
        assert_eq!(
            *f.markers.lock().unwrap(),
            [
                "current-host-only",
                "org.nspasteboard.ConcealedType",
                "org.nspasteboard.TransientType"
            ]
        );
    }

    // protects=review R3: when the write fails part way, the pasteboard is cleared before the
    // error is returned, so a value never stays on it unmarked or unscheduled;
    // fails_when=a failed write leaves the text on the pasteboard; no_claim=-
    #[test]
    fn pasteboard_failed_write_leaves_nothing() {
        let f = Arc::new(Fake::default());
        *f.fail_write.lock().unwrap() = true;
        let e = copy_then_clear(Arc::new(Marked(f.clone())), V, Duration::from_secs(30));
        assert!(e.is_err());
        assert_eq!(f.text(), None, "cleared after the failure");
    }

    // protects=review N4: a copy still within its 30 s is cleared when msd exits, unless
    // something else was copied since; fails_when=an msd exit leaves the value on the
    // pasteboard; no_claim=msd being killed with SIGKILL (nothing runs then)
    #[test]
    fn pasteboard_cleared_on_shutdown() {
        let f = Arc::new(Fake::default());
        copy_then_clear(Arc::new(Marked(f.clone())), V, Duration::from_secs(60)).unwrap();
        clear_pending_now();
        assert_eq!(f.text(), None);
    }

    // protects=SPEC D-20 and T-92: the copied value is cleared after the delay (30 s in msd)
    // when nothing else was copied; fails_when=it stays on the pasteboard; no_claim=the real
    // pbpaste (manual check)
    #[test]
    fn pasteboard_cleared_after_30s() {
        assert_eq!(
            crate::daemon::dash_actions::CLEAR_AFTER,
            Duration::from_secs(30)
        );
        let f = Arc::new(Fake::default());
        copy_then_clear(Arc::new(Marked(f.clone())), V, Duration::from_millis(50)).unwrap();
        assert_eq!(f.text().as_deref(), Some(V));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(f.text(), None, "cleared");
    }

    // protects=SPEC D-20: when the person copied something else within the 30 s, msd leaves the
    // pasteboard alone; fails_when=msd clears someone else's copy; no_claim=-
    #[test]
    fn pasteboard_left_alone_when_changed() {
        let f = Arc::new(Fake::default());
        copy_then_clear(Arc::new(Marked(f.clone())), V, Duration::from_millis(80)).unwrap();
        f.bump();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(f.text().as_deref(), Some("something else"));
    }

    // protects=SPEC D-20: the test pasteboard file records length, a short hash, the markers and
    // the clear, never the value; fails_when=the value appears in the file; no_claim=-
    #[test]
    fn test_pasteboard_file_never_holds_the_value() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("paste.txt");
        let cb: Arc<dyn Clipboard> = Arc::new(Marked(FilePasteboard::new(path.clone())));
        copy_then_clear(cb, V, Duration::from_millis(30)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(V) && !text.contains("PASTE_CANARY"),
            "{text}"
        );
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["len"], V.len());
        assert_eq!(
            first["markers"],
            serde_json::json!(["current-host-only", "text", "concealed", "transient"])
        );
        assert!(text.lines().nth(1).unwrap().contains("\"cleared\":true"));
    }
}
