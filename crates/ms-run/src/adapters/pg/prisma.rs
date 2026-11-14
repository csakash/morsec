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

fn is_prisma(a: &str) -> bool {
    a == "prisma" || a.starts_with("prisma@")
}

/// Index in `argv` of the `prisma` word, when this is a Prisma CLI call: `prisma …`, or a
/// package runner (`npx`, `bunx`, `pnpx`, `npm`, `pnpm`, `yarn`, `bun`) with any argument that is
/// `prisma` / `prisma@<v>` (or a path to one). Runner options can take values (`pnpm --filter
/// api exec prisma …`), so morsec doesn't try to parse them: the first such argument counts, and
/// whatever follows it is classified (an option's value of `prisma` then reads as an unknown
/// command, which needs an approval: fail closed).
pub fn locate(argv: &[String]) -> Option<usize> {
    let first = base(argv.first()?);
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
        .find(|(_, a)| is_prisma(base(a)))
        .map(|(i, _)| i)
}

/// The class of a whole Prisma call. Behind `npm`, `pnpm`, `yarn` or `bun`, `prisma` is the
/// binary only after `exec`, `dlx` or `x`; otherwise it names a package script (`yarn prisma`,
/// `npm run prisma`) or a package to install, which run code morsec can't see, so they always
/// need an approval.
pub fn class_of(argv: &[String]) -> Option<Class> {
    let at = locate(argv)?;
    let first = base(&argv[0]);
    if at == 0 || matches!(first, "npx" | "bunx" | "pnpx") {
        return Some(classify(&argv[at + 1..]));
    }
    let before = argv[1..at].iter().rev().find(|a| a.as_str() != "--");
    if before.is_some_and(|b| matches!(b.as_str(), "exec" | "dlx" | "x")) {
        return Some(classify(&argv[at + 1..]));
    }
    Some(Class::Schema(format!(
        "{} {} (a package script or install named prisma; morsec can't see what it runs)",
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
            cls(&["pnpm", "--filter", "api", "exec", "prisma", "generate"]),
            Some(Class::ReadOnly)
        );
        assert_eq!(cls(&["npx", "prisma", "generate"]), Some(Class::ReadOnly));
        for script in [
            &["npm", "run", "prisma"][..],
            &["yarn", "prisma"],
            &["pnpm", "prisma", "generate"],
            &["npm", "install", "prisma"],
            &["bun", "run", "prisma", "generate"],
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
        assert_eq!(locate(&a(&["psql"])), None);

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
