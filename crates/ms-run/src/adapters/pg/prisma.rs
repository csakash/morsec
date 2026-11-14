//! Recognising a Prisma CLI call and classifying it (SPEC D4).
//!
//! Unknown shapes fail closed: a command this module doesn't know is treated as one that changes
//! the schema (it needs an approval, and a read-only key refuses it).

use std::path::Path;

/// What a Prisma command does to the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// Reads at most (`migrate status`, `db pull`, `generate`, …).
    ReadOnly,
    /// Writes data but is not a schema change (`db seed`, `studio`).
    Write(String),
    /// Changes the schema or runs arbitrary SQL, or isn't known: always needs an approval.
    Schema(String),
}

fn base(a: &str) -> &str {
    Path::new(a)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(a)
}

/// `prisma`, or `prisma@<version or dist-tag>` (never `prisma@npm:…`, a URL, a path).
fn is_prisma(a: &str) -> bool {
    a == "prisma"
        || a.strip_prefix("prisma@").is_some_and(|v| {
            !v.is_empty()
                && v.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'^' | b'~')
                })
        })
}

/// Index in `argv` of the first argument that names prisma, when this is a Prisma call: `prisma …`,
/// or a package runner (`npx`, `bunx`, `pnpx`, `npm`, `pnpm`, `yarn`, `bun`) with any argument
/// containing `prisma` (a path, `prisma@npm:…`, `@prisma/cli`, a package script …). This match is
/// broad on purpose (fail closed): [`class_of`] treats only the exact binary shape as Prisma's own
/// command and everything else as needing an approval.
pub fn locate(argv: &[String]) -> Option<usize> {
    // macOS file systems ignore case, so `PRISMA` / `NPX` run the same binaries.
    let first = base(argv.first()?).to_ascii_lowercase();
    let first = first.as_str();
    if first == "prisma" {
        return Some(0);
    }
    if !matches!(
        first,
        "npx" | "bunx" | "pnpx" | "npm" | "pnpm" | "yarn" | "bun"
    ) {
        return None;
    }
    argv.iter()
        .enumerate()
        .skip(1)
        .find(|(_, a)| a.to_ascii_lowercase().contains("prisma"))
        .map(|(i, _)| i)
}

/// The class of a whole Prisma call. Only exact shapes count as the prisma binary:
/// `prisma …`; `npx|bunx|pnpx [--yes|-y|--no-install|--quiet|-q|--]… prisma[@v] …`; and
/// `npm|pnpm|yarn|bun exec|dlx|x [--yes|-y|--]… prisma[@v] …` with the runner word first.
/// Anything else that names prisma (a runner option before it, which may take a value such as
/// `yarn --cwd x prisma`; a package script `yarn prisma` / `npm run prisma`; `npm install
/// prisma`; `npx -p ./pkg prisma`) runs code morsec can't see, so it always needs an approval.
pub fn class_of(argv: &[String]) -> Option<Class> {
    let at = locate(argv)?;
    if at == 0 {
        return Some(classify(&argv[1..]));
    }
    let first = base(&argv[0]).to_ascii_lowercase();
    let first = first.as_str();
    let flags_only = |args: &[String]| {
        args.iter().all(|a| {
            matches!(
                a.as_str(),
                "--yes" | "-y" | "--no-install" | "--quiet" | "-q" | "--"
            )
        })
    };
    let binary = is_prisma(&argv[at])
        && match first {
            "npx" | "bunx" | "pnpx" => flags_only(&argv[1..at]),
            _ => {
                at >= 2
                    && matches!(argv[1].as_str(), "exec" | "dlx" | "x")
                    && flags_only(&argv[2..at])
            }
        };
    if binary {
        return Some(classify(&argv[at + 1..]));
    }
    Some(Class::Schema(format!(
        "{} {} (a package script, install or wrapped prisma; morsec can't see what it runs)",
        crate::printable(first),
        argv[1..=at]
            .iter()
            .map(|a| crate::printable(a))
            .collect::<Vec<_>>()
            .join(" ")
    )))
}

/// Classifies the arguments after the `prisma` word.
pub fn classify(rest: &[String]) -> Class {
    let words: Vec<&str> = rest.iter().map(String::as_str).take(2).collect();
    let shown = || {
        let mut s = String::from("prisma");
        for w in &words {
            s.push(' ');
            s.push_str(&crate::printable(w));
        }
        s
    };
    match words.as_slice() {
        []
        | [
            "-v" | "--version" | "version" | "-h" | "--help" | "help",
            ..,
        ] => Class::ReadOnly,
        ["generate" | "validate" | "format", ..] => Class::ReadOnly,
        ["migrate", "status" | "diff"] | ["db", "pull"] => Class::ReadOnly,
        ["db", "seed"] | ["studio", ..] => Class::Write(shown()),
        ["migrate", "deploy" | "dev" | "reset" | "resolve"] | ["db", "push" | "execute"] => {
            Class::Schema(shown())
        }
        _ => Class::Schema(format!(
            "{} (a prisma command morsec doesn't know)",
            shown()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // protects=SPEC D4: prisma is recognised behind the usual launchers, schema changes are
    // classed as needing an approval, and anything unknown fails closed; fails_when=a migrate
    // call is missed or classed read-only; no_claim=launchers not listed (env, node …) — the
    // key's command rule decides those
    #[test]
    fn locate_and_classify() {
        assert_eq!(locate(&a(&["prisma", "migrate", "deploy"])), Some(0));
        assert_eq!(
            locate(&a(&["/x/node_modules/.bin/prisma", "db", "push"])),
            Some(0)
        );
        assert_eq!(
            locate(&a(&["npx", "--yes", "prisma@5", "migrate"])),
            Some(2)
        );
        assert_eq!(locate(&a(&["pnpm", "exec", "prisma", "generate"])), Some(2));
        assert_eq!(locate(&a(&["yarn", "prisma", "generate"])), Some(1));
        assert_eq!(
            locate(&a(&[
                "pnpm", "--filter", "api", "exec", "prisma", "migrate", "deploy"
            ])),
            Some(4)
        );
        assert_eq!(
            locate(&a(&["yarn", "--cwd", "app", "prisma", "migrate"])),
            Some(3)
        );
        assert_eq!(
            locate(&a(&["npm", "exec", "--", "prisma", "migrate"])),
            Some(3)
        );
        let cls = |v: &[&str]| class_of(&a(v));
        assert_eq!(
            cls(&["npm", "exec", "--", "prisma", "migrate", "status"]),
            Some(Class::ReadOnly)
        );
        assert_eq!(
            cls(&["pnpm", "exec", "prisma", "generate"]),
            Some(Class::ReadOnly)
        );
        assert_eq!(
            cls(&["npx", "--yes", "prisma@5", "generate"]),
            Some(Class::ReadOnly)
        );
        assert_eq!(cls(&["npx", "prisma", "generate"]), Some(Class::ReadOnly));
        for script in [
            &["npm", "run", "prisma"][..],
            &["yarn", "prisma"],
            &["pnpm", "prisma", "generate"],
            &["npm", "install", "prisma"],
            &["bun", "run", "prisma", "generate"],
            &["pnpm", "--filter", "api", "exec", "prisma", "generate"],
            &["yarn", "workspace", "x", "prisma", "migrate", "status"],
            &["yarn", "--cwd", "x", "prisma", "generate"],
            &["pnpm", "--dir", "x", "prisma", "generate"],
            &["bun", "--cwd", "x", "prisma", "generate"],
            &["npx", "-p", "./pkg", "prisma", "generate"],
            &["npm", "exec", "--package=./pkg", "--", "prisma", "generate"],
        ] {
            assert!(matches!(cls(script), Some(Class::Schema(_))), "{script:?}");
        }
        assert_eq!(cls(&["npm", "test"]), None);
        assert_eq!(
            locate(&a(&["npx", "-p", "prisma", "prisma", "migrate"])),
            Some(2)
        );
        assert!(matches!(
            classify(&a(&["prisma", "migrate", "deploy"])),
            Class::Schema(_)
        ));
        assert_eq!(locate(&a(&["npx", "tsc"])), None);
        // Only prisma itself, at a version or tag, counts as the binary; any other spelling that
        // names prisma is still matched, and needs an approval.
        assert_eq!(locate(&a(&["npx", "prisma@5.22.0", "generate"])), Some(1));
        assert_eq!(
            class_of(&a(&["npx", "prisma@5.22.0", "generate"])),
            Some(Class::ReadOnly)
        );
        for other in [
            &["npx", "prisma@npm:evil-pkg", "generate"][..],
            &["npx", "prisma@github:attacker/repo", "generate"],
            &["npx", "prisma@file:../x", "generate"],
            &["pnpm", "dlx", "prisma@https://x/y.tgz", "generate"],
            &["npx", "./evil/prisma", "generate"],
            &["npx", "./node_modules/.bin/prisma", "migrate", "reset"],
            &["npx", "prisma@npm:prisma", "migrate", "deploy"],
            &["npx", "prisma@>=5", "db", "push"],
            &["pnpm", "dlx", "prisma@5.x", "migrate", "deploy"],
            &["npx", "@prisma/cli", "generate"],
        ] {
            assert!(
                matches!(class_of(&a(other)), Some(Class::Schema(_))),
                "{other:?}"
            );
        }
        assert_eq!(locate(&a(&["psql"])), None);
        assert_eq!(locate(&a(&["PRISMA", "migrate", "reset"])), Some(0));
        assert_eq!(locate(&a(&["NPX", "prisma", "migrate"])), Some(1));

        let c = |v: &[&str]| classify(&a(v));
        assert_eq!(c(&["migrate", "status"]), Class::ReadOnly);
        assert_eq!(c(&["generate", "--schema", "x"]), Class::ReadOnly);
        assert_eq!(c(&["db", "pull"]), Class::ReadOnly);
        assert!(matches!(c(&["db", "seed"]), Class::Write(_)));
        for schema in [
            &["migrate", "deploy"][..],
            &["migrate", "dev", "--name", "x"],
            &["migrate", "reset", "--force"],
            &["migrate", "resolve"],
            &["db", "push"],
            &["db", "execute", "--file", "x.sql"],
            &["--schema", "x.prisma", "migrate", "deploy"],
            &["migrate"],
            &["frobnicate"],
            &["init"],
            &["debug"],
        ] {
            assert!(matches!(c(schema), Class::Schema(_)), "{schema:?}");
        }
    }
}
