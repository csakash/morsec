//! The agent hint block (design §4.7, SDLC-4): a fixed template, only the slug filled in,
//! appended once to an existing `CLAUDE.md` / `AGENTS.md` at the project root. It never creates
//! either file, never writes through a symlink or a hard link, and keeps the file's mode. It gives
//! no permission; it only stops agents from "fixing" refs.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::Error;

/// Start marker.
pub const BEGIN: &str = "<!-- morsec:begin -->";
/// End marker.
pub const END: &str = "<!-- morsec:end -->";
/// Files the block goes into, when they exist.
pub const FILES: &[&str] = &["CLAUDE.md", "AGENTS.md"];
const MAX_BYTES: u64 = 1 << 20;

/// The block for project `slug` (a validated slug: `a-z0-9-`).
pub fn block(slug: &str) -> String {
    format!(
        "{BEGIN}\n## Secrets in this project\n\nValues in `.env` files that look like `ms://{slug}/...` are morsec references. Keep them as they are:\ndo not replace them with real keys or ask for the real values. Calls to the services they belong to\nwork as they are. If a call is blocked, ask the user to check the project with `ms projects {slug}`\nin their own terminal.\n{END}\n"
    )
}

/// Appends the block to each of [`FILES`] that exists at `root` as a regular file and doesn't
/// hold [`BEGIN`] yet. Returns the files written (relative to `root`).
pub fn apply(root: &Path, slug: &str) -> Result<Vec<String>, Error> {
    let mut written = Vec::new();
    for name in FILES {
        let path = root.join(name);
        let Ok(lmeta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !lmeta.file_type().is_file() || lmeta.nlink() > 1 || lmeta.len() > MAX_BYTES {
            continue;
        }
        let mut f = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|e| Error::io(format!("reading {name}"), e))?;
        let meta = f
            .metadata()
            .map_err(|e| Error::io(format!("reading {name}"), e))?;
        if meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() || !meta.is_file() {
            continue;
        }
        let mut text = Vec::new();
        (&mut f)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut text)
            .map_err(|e| Error::io(format!("reading {name}"), e))?;
        if text.len() as u64 > MAX_BYTES || text.windows(BEGIN.len()).any(|w| w == BEGIN.as_bytes())
        {
            continue;
        }
        let mut new = text.clone();
        if !new.is_empty() && !new.ends_with(b"\n") {
            new.push(b'\n');
        }
        if !new.is_empty() {
            new.push(b'\n');
        }
        new.extend_from_slice(block(slug).as_bytes());
        let mut tmp = tempfile::Builder::new()
            .prefix(".ms-hint-")
            .tempfile_in(root)
            .map_err(|e| Error::io(format!("writing {name}"), e))?;
        tmp.write_all(&new)
            .and_then(|()| {
                tmp.as_file()
                    .set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))
            })
            .and_then(|()| tmp.as_file().sync_all())
            .map_err(|e| Error::io(format!("writing {name}"), e))?;
        // Unchanged since it was read, right before the rename.
        match fs::symlink_metadata(&path) {
            Ok(m) if m.ino() == meta.ino() && m.len() == text.len() as u64 => {}
            _ => continue,
        }
        tmp.persist(&path)
            .map_err(|e| Error::io(format!("writing {name}"), e.error))?;
        written.push((*name).to_owned());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC criterion 8: the block is appended once to an existing CLAUDE.md (mode kept,
    // earlier text unchanged), a re-run doesn't duplicate it, a missing AGENTS.md is never
    // created, and a symlinked AGENTS.md is not written through; fails_when=the block appears
    // twice, a file is created, the mode changes or a link target changes; no_claim=removal on
    // Undo (L33)
    #[test]
    fn hint_block_once_never_creates() {
        let d = tempfile::tempdir().unwrap();
        let claude = d.path().join("CLAUDE.md");
        fs::write(&claude, "# Rules\nBe nice.").unwrap();
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(apply(d.path(), "shop").unwrap(), vec!["CLAUDE.md"]);
        let text = fs::read_to_string(&claude).unwrap();
        assert!(
            text.starts_with("# Rules\nBe nice.\n\n<!-- morsec:begin -->\n"),
            "{text}"
        );
        assert!(text.contains("ms://shop/...") && text.ends_with("<!-- morsec:end -->\n"));
        assert_eq!(
            fs::metadata(&claude).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(apply(d.path(), "shop").unwrap().is_empty());
        assert_eq!(fs::read_to_string(&claude).unwrap(), text);
        assert!(!d.path().join("AGENTS.md").exists());

        let target = d.path().join("elsewhere.md");
        fs::write(&target, "x\n").unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("AGENTS.md")).unwrap();
        assert!(apply(d.path(), "shop").unwrap().is_empty());
        assert_eq!(fs::read_to_string(&target).unwrap(), "x\n");
    }
}
