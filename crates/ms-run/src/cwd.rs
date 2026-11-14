//! The working directory must lie inside one of the key's project roots (SPEC D2).
//!
//! Both sides are compared after resolving symlinks, so a link inside a root that points
//! outside it doesn't pass, and `..` can't climb out. The check returns the canonical directory,
//! which is what the child is started in.

use std::path::{Path, PathBuf};

use crate::error::RunError;

/// Checks `cwd` against `roots` and returns its canonical form. `key` names the key in errors.
pub fn check(cwd: &Path, roots: &[PathBuf], key: &str) -> Result<PathBuf, RunError> {
    if roots.is_empty() {
        return Err(RunError::denied(format!(
            "morsec: {key} has no project roots, so it can't run commands anywhere. Add one from your own terminal: ms rules {key} --add-root <project dir>"
        )));
    }
    if !cwd.is_absolute() {
        return Err(RunError::invalid(
            "morsec: the working directory must be an absolute path",
        ));
    }
    let real = std::fs::canonicalize(cwd).map_err(|e| {
        RunError::invalid(format!(
            "morsec: the working directory {} can't be resolved: {e}",
            cwd.display()
        ))
    })?;
    if !real.is_dir() {
        return Err(RunError::invalid(format!(
            "morsec: {} is not a directory",
            real.display()
        )));
    }
    let inside = roots.iter().any(|r| {
        // A root that doesn't exist (yet) matches nothing.
        std::fs::canonicalize(r).is_ok_and(|root| real.starts_with(&root))
    });
    if inside {
        Ok(real)
    } else {
        Err(RunError::denied(format!(
            "morsec: {} is outside {key}'s project roots, so the command was refused. Run it from inside a project root, or add one from your own terminal: ms rules {key} --add-root <dir>",
            real.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RunErrorKind;

    // protects=cwd is limited to the key's roots after symlinks and `..` are resolved; a key
    // without roots runs nowhere; fails_when=a directory outside every root passes (directly,
    // via a symlink, via `..`, or as a sibling sharing a prefix); no_claim=TOCTOU between check
    // and spawn (a same-user rename; ARI42 OUT-4 residual)
    #[test]
    fn roots_are_enforced() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let app = base.join("app");
        let sub = app.join("src");
        let other = base.join("application");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&other, app.join("escape")).unwrap();
        let roots = vec![app.clone()];

        assert_eq!(check(&app, &roots, "k").unwrap(), app);
        assert_eq!(check(&sub, &roots, "k").unwrap(), sub);
        for bad in [
            other.clone(),
            base.clone(),
            app.join("escape"),
            sub.join("../../application"),
            PathBuf::from("/"),
        ] {
            let e = check(&bad, &roots, "k").unwrap_err();
            assert_eq!(e.kind, RunErrorKind::Denied, "{bad:?}: {e}");
        }
        let e = check(&app, &[], "k").unwrap_err();
        assert!(e.message.contains("--add-root"), "{e}");
        assert!(check(Path::new("rel"), &roots, "k").is_err());
        assert!(check(&app.join("missing"), &roots, "k").is_err());

        // A root given through a symlink still matches its real directory.
        let link = base.join("link-to-app");
        std::os::unix::fs::symlink(&app, &link).unwrap();
        assert_eq!(check(&sub, &[link], "k").unwrap(), sub);
    }
}
