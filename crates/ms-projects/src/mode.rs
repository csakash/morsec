//! Machine or project mode (design §4.1).
//!
//! ```text
//! root = git top level (from cwd), if any
//! if root is $HOME or / or none:
//!     root = cwd if cwd has a project marker, else none
//! if root is none, $HOME, /, an ancestor of $HOME, or inside ~/Library, /System,
//! /Applications, or a /Volumes/* root:
//!     MACHINE mode
//! else:
//!     PROJECT mode at root
//! ```
//!
//! A git repository whose top level is `$HOME` (a dotfiles repo) counts as no repository: that is
//! the case that would otherwise scan a whole home directory. Pure: the caller passes canonical
//! paths and whether the current directory holds a marker.

use std::path::{Path, PathBuf};

/// Files that mark a project root. Any `.env` or `.env.*` file counts too ([`is_marker`]).
pub const MARKERS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "deno.json",
    "deno.jsonc",
    "wrangler.toml",
    "wrangler.jsonc",
    "vercel.json",
    "netlify.toml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

/// True for a project-marker file name.
pub fn is_marker(name: &str) -> bool {
    MARKERS.contains(&name) || name == ".env" || name.starts_with(".env.")
}

/// Why `ms init` chose machine mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineWhy {
    /// `--machine`, or a flag that implies it (`--force`).
    Asked,
    /// No git repository and no project marker here.
    NoProject,
    /// The project root would be the home directory (or a dotfiles repo in it).
    Home,
    /// The project root would be `/` or an ancestor of the home directory.
    TooHigh,
    /// The root is inside a system or library location.
    Excluded,
}

/// The mode `ms init` runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Set up this Mac only; no file outside morsec's own directories is read.
    Machine(MachineWhy),
    /// Protect the project at this (canonical) root.
    Project(PathBuf),
}

/// What [`detect`] looks at.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// The current directory, canonical.
    pub cwd: &'a Path,
    /// The home directory, canonical.
    pub home: &'a Path,
    /// `git rev-parse --show-toplevel` from `cwd`, canonical, if `cwd` is in a repository.
    pub git_top: Option<&'a Path>,
    /// `cwd` holds a project marker ([`MARKERS`], `.env`, `.env.*`).
    pub cwd_has_marker: bool,
}

/// `Some(why)` when `root` may never be scanned as a project: `/`, the home directory or one of
/// its ancestors, `~/Library/**`, `/System/**`, `/Applications/**`, or the root of a
/// mounted volume (`/Volumes/<name>`).
pub fn refused_root(root: &Path, home: &Path) -> Option<MachineWhy> {
    if root == Path::new("/") || home.starts_with(root) && root != home {
        return Some(MachineWhy::TooHigh);
    }
    if root == home {
        return Some(MachineWhy::Home);
    }
    let inside = |base: &Path| root.starts_with(base);
    if inside(&home.join("Library"))
        || inside(Path::new("/System"))
        || inside(Path::new("/Applications"))
    {
        return Some(MachineWhy::Excluded);
    }
    if root.parent() == Some(Path::new("/Volumes")) {
        return Some(MachineWhy::Excluded);
    }
    None
}

/// The design §4.1 rule.
pub fn detect(i: Inputs<'_>) -> Mode {
    let top = i.git_top.filter(|t| *t != i.home && *t != Path::new("/"));
    let root = match top {
        Some(t) => Some(t.to_path_buf()),
        None if i.cwd_has_marker => Some(i.cwd.to_path_buf()),
        None => None,
    };
    let Some(root) = root else {
        return Mode::Machine(MachineWhy::NoProject);
    };
    match refused_root(&root, i.home) {
        Some(why) => Mode::Machine(why),
        None => Mode::Project(root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cwd: &str, git: Option<&str>, marker: bool) -> Mode {
        detect(Inputs {
            cwd: Path::new(cwd),
            home: Path::new("/Users/me"),
            git_top: git.map(Path::new),
            cwd_has_marker: marker,
        })
    }

    // protects=SPEC criterion 1 (design §4.1): ms init in $HOME, in /, in a $HOME that is a git
    // repo (dotfiles) with or without markers, and in system locations is machine mode; a
    // project directory or repo is project mode at its root; fails_when=any of those rows picks a
    // project root at $HOME, /, an ancestor of $HOME or a system path; no_claim=the git call
    // itself (the CLI runs it) and the walk audit (ms-cli init_project tests)
    #[test]
    fn init_in_home_is_machine_mode() {
        use MachineWhy::*;
        let table: &[(&str, Option<&str>, bool, Mode)] = &[
            ("/Users/me", None, false, Mode::Machine(NoProject)),
            ("/Users/me", None, true, Mode::Machine(Home)),
            ("/", None, false, Mode::Machine(NoProject)),
            ("/", None, true, Mode::Machine(TooHigh)),
            ("/Users", None, true, Mode::Machine(TooHigh)),
            ("/Users/me/Library/Foo", None, true, Mode::Machine(Excluded)),
            ("/System/x", None, true, Mode::Machine(Excluded)),
            ("/Applications/A.app", None, true, Mode::Machine(Excluded)),
            ("/Volumes/USB", None, true, Mode::Machine(Excluded)),
            (
                "/Users/me/code/shop",
                None,
                true,
                Mode::Project("/Users/me/code/shop".into()),
            ),
            ("/Users/me/code/shop", None, false, Mode::Machine(NoProject)),
            (
                "/Users/me/code/shop/apps/web",
                Some("/Users/me/code/shop"),
                false,
                Mode::Project("/Users/me/code/shop".into()),
            ),
            (
                "/Volumes/USB/code/shop",
                None,
                true,
                Mode::Project("/Volumes/USB/code/shop".into()),
            ),
        ];
        for (cwd, git, marker, want) in table {
            assert_eq!(
                &run(cwd, *git, *marker),
                want,
                "{cwd} git={git:?} marker={marker}"
            );
        }
    }

    // protects=design §4.1: a git repo whose top level is $HOME (dotfiles) counts as no repo, so
    // ms init there or in an unmarked subdirectory never scans the home directory; a marked
    // subdirectory of it is still its own project; fails_when=the dotfiles top level is taken as
    // the project root; no_claim=-
    #[test]
    fn dotfiles_repo_in_home_is_machine_mode() {
        assert_eq!(
            run("/Users/me", Some("/Users/me"), false),
            Mode::Machine(MachineWhy::NoProject)
        );
        assert_eq!(
            run("/Users/me", Some("/Users/me"), true),
            Mode::Machine(MachineWhy::Home)
        );
        assert_eq!(
            run("/Users/me/notes", Some("/Users/me"), false),
            Mode::Machine(MachineWhy::NoProject)
        );
        assert_eq!(
            run("/Users/me/notes", Some("/Users/me"), true),
            Mode::Project("/Users/me/notes".into())
        );
        assert_eq!(run("/x", Some("/"), true), Mode::Project("/x".into()));
        assert!(is_marker(".env.local") && is_marker("go.mod") && !is_marker("README.md"));
    }
}
