//! Project-wide import naming (design §4.6) on top of [`ms_import::plan::plan`].
//!
//! Per env file, in the walk's order (shallow first):
//! - variables an example file lists, which the classifier called "not secret" here, are added
//!   to [`Options::include`];
//! - every new secret gets `<slug>/<var>`; the same variable with a different value in a later
//!   file gets a file segment (`<slug>/production/<var>`, `<slug>/apps-web/<var>`); a name the
//!   vault already holds gets `-2`, `-3`, … ([`Options::names`]);
//! - the same value in several files is stored once: later rows become `Reuse` of the first key;
//! - `.env.production`, `.env.prod`, `.env.live` (and their `.local` forms) raise the tier to
//!   production, never lower it ([`Options::tiers`]); a key shared with such a file is production.
//!
//! Pure: no I/O. A file whose plan fails is reported on its own; the others go on.

use std::collections::{BTreeMap, BTreeSet};

use ms_core::{KeyMeta, KeyName, MAX_SEGMENT_LEN, Mode, Tier};
use ms_import::catalog::Catalog;
use ms_import::dotenv::Entry;
use ms_import::plan::{Action, Options, Plan, plan};

/// One env file to plan.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// Path relative to the project root.
    pub rel: &'a str,
    /// Its parsed entries.
    pub entries: &'a [Entry],
}

/// File names whose secrets are production.
pub fn is_production_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let name = name.strip_suffix(".local").unwrap_or(&name);
    matches!(name, ".env.production" | ".env.prod" | ".env.live")
}

fn seg(s: &str, fallback: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut out: String = out.chars().take(MAX_SEGMENT_LEN).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

/// `STRIPE_SECRET_KEY` → `stripe-secret-key`.
pub fn var_segment(var: &str) -> String {
    seg(var, "var")
}

/// The file segment: `.env.production` → `production`, `apps/web/.env` → `apps-web`,
/// `apps/web/.env.local` → `apps-web-local`, `prod.env` → `prod`, `.env` → `root`.
pub fn file_segment(rel: &str) -> String {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let lower = name.to_ascii_lowercase();
    let part = if let Some(rest) = lower.strip_prefix(".env.") {
        rest.to_owned()
    } else if lower == ".env" {
        String::new()
    } else if let Some(stem) = lower.strip_suffix(".env") {
        stem.to_owned()
    } else {
        lower
    };
    let joined = [dir.replace('/', "-"), part]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    seg(&joined, "root")
}

fn key(s: &str) -> KeyName {
    KeyName::new(s).unwrap_or_else(|_| unreachable!("built from valid segments: {s}"))
}

/// `name`, or `name` with `-2`, `-3`, … on its last segment, whichever is not taken.
fn free(name: &KeyName, taken: &BTreeSet<KeyName>) -> KeyName {
    if !taken.contains(name) {
        return name.clone();
    }
    let (head, last) = name
        .as_str()
        .rsplit_once('/')
        .unwrap_or_else(|| unreachable!("project keys have a slug segment"));
    for n in 2u32.. {
        let suffix = format!("-{n}");
        let mut l: String = last.chars().take(MAX_SEGMENT_LEN - suffix.len()).collect();
        while l.ends_with('-') {
            l.pop();
        }
        let k = key(&format!("{head}/{l}{suffix}"));
        if !taken.contains(&k) {
            return k;
        }
    }
    unreachable!("u32 suffixes exhausted")
}

struct Chosen {
    file: usize,
    row: usize,
    key: KeyName,
}

fn meta(k: &KeyName) -> KeyMeta {
    KeyMeta {
        name: k.clone(),
        mode: Mode::Swap,
        tier: Tier::Test,
        created_unix_ms: 0,
    }
}

/// Plans every file of a project. `examples` are the variable names example files list;
/// `existing` is the vault's keys. The result lines up with `sources`.
pub fn plan_project(
    catalog: &Catalog,
    slug: &str,
    sources: &[Source<'_>],
    examples: &BTreeSet<String>,
    existing: &[KeyMeta],
) -> Vec<Result<Plan, ms_import::Error>> {
    let mut taken: BTreeSet<KeyName> = existing.iter().map(|m| m.name.clone()).collect();
    let mut chosen: Vec<Chosen> = Vec::new();
    let mut vars_seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<Result<Plan, ms_import::Error>> = Vec::with_capacity(sources.len());
    let mut production_keys: BTreeSet<KeyName> = BTreeSet::new();

    for (f, src) in sources.iter().enumerate() {
        let known: Vec<KeyMeta> = taken.iter().map(meta).collect();
        let one = (|| {
            let raise = is_production_file(src.rel);
            let first = plan(catalog, src.entries, &known, &Options::default())?;
            let include: BTreeSet<String> = first
                .rows
                .iter()
                .filter(|r| r.action == Action::KeptNotSecret && examples.contains(&r.var))
                .map(|r| r.var.clone())
                .collect();
            let base = Options {
                include: include.clone(),
                ..Options::default()
            };
            let p1 = plan(catalog, src.entries, &known, &base)?;
            let mut count: BTreeMap<&str, usize> = BTreeMap::new();
            for e in src.entries {
                *count.entry(e.name.as_str()).or_default() += 1;
            }
            let mut names = BTreeMap::new();
            let mut tiers = BTreeMap::new();
            let mut rename: Vec<(usize, KeyName)> = Vec::new();
            let mut reuse: Vec<(usize, usize)> = Vec::new(); // (row, index into chosen)
            let mut mine: Vec<(usize, KeyName)> = Vec::new();
            let mut local_taken = taken.clone();
            for (i, r) in p1.rows.iter().enumerate() {
                if r.action != Action::Import {
                    continue;
                }
                let value = src.entries[r.entry].value();
                if let Some(c) = chosen.iter().position(|c| {
                    let other = &out[c.file];
                    let entry = match other {
                        Ok(p) => p.rows[c.row].entry,
                        Err(_) => return false,
                    };
                    sources[c.file].entries[entry].value() == value
                }) {
                    reuse.push((i, c));
                    continue;
                }
                let v = var_segment(&r.var);
                let plain = key(&format!("{slug}/{v}"));
                let name = if vars_seen.contains(&r.var) {
                    free(
                        &key(&format!("{slug}/{}/{v}", file_segment(src.rel))),
                        &local_taken,
                    )
                } else {
                    free(&plain, &local_taken)
                };
                local_taken.insert(name.clone());
                if count.get(r.var.as_str()) == Some(&1) {
                    names.insert(r.var.clone(), name.clone());
                    if raise {
                        tiers.insert(r.var.clone(), Tier::Production);
                    }
                } else {
                    rename.push((i, name.clone()));
                }
                mine.push((i, name));
            }
            let opts = Options {
                include,
                names,
                tiers,
                ..Options::default()
            };
            let mut p = plan(catalog, src.entries, &known, &opts)?;
            // Rows renamed or turned into a reuse of an earlier file's key: every row of this
            // file pointing at the old key follows.
            let mut remap: BTreeMap<KeyName, KeyName> = BTreeMap::new();
            for (i, name) in &rename {
                if let Some(old) = p.rows[*i].key.replace(name.clone()) {
                    remap.insert(old, name.clone());
                }
            }
            for (i, c) in &reuse {
                let c = &chosen[*c];
                let Ok(other) = &out[c.file] else {
                    unreachable!("only planned files are chosen")
                };
                let first = &other.rows[c.row];
                let row = &mut p.rows[*i];
                if let Some(old) = row.key.replace(c.key.clone()) {
                    remap.insert(old, c.key.clone());
                }
                row.action = Action::Reuse;
                row.provider = first.provider.clone();
                row.provider_name = first.provider_name.clone();
                row.mode = first.mode;
                row.tier = first.tier;
                row.hosts = first.hosts.clone();
            }
            for (i, r) in p.rows.iter_mut().enumerate() {
                if r.action.rewrites()
                    && !rename.iter().any(|(j, _)| *j == i)
                    && !reuse.iter().any(|(j, _)| *j == i)
                    && let Some(new) = r.key.as_ref().and_then(|k| remap.get(k))
                {
                    r.key = Some(new.clone());
                }
            }
            Ok((p, mine, raise))
        })();
        match one {
            Ok((p, mine, raise)) => {
                for (row, name) in mine {
                    taken.insert(name.clone());
                    chosen.push(Chosen {
                        file: f,
                        row,
                        key: name,
                    });
                }
                for r in &p.rows {
                    if r.action.rewrites() {
                        vars_seen.insert(r.var.clone());
                        if raise && let Some(k) = &r.key {
                            production_keys.insert(k.clone());
                        }
                    }
                }
                out.push(Ok(p));
            }
            Err(e) => out.push(Err(e)),
        }
    }
    // A key used by a production file is production wherever it appears (raise only).
    for p in out.iter_mut().flatten() {
        for r in &mut p.rows {
            if r.action.rewrites() && r.key.as_ref().is_some_and(|k| production_keys.contains(k)) {
                r.tier = Some(Tier::Production);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_import::dotenv::parse;

    fn plans(files: &[(&str, &str)], examples: &[&str], existing: &[&str]) -> Vec<Plan> {
        let parsed: Vec<Vec<Entry>> = files.iter().map(|(_, t)| parse(t).unwrap()).collect();
        let sources: Vec<Source<'_>> = files
            .iter()
            .zip(&parsed)
            .map(|((rel, _), e)| Source { rel, entries: e })
            .collect();
        let ex: BTreeSet<String> = examples.iter().map(|s| (*s).to_owned()).collect();
        let existing: Vec<KeyMeta> = existing.iter().map(|n| meta(&key(n))).collect();
        plan_project(Catalog::builtin(), "shop", &sources, &ex, &existing)
            .into_iter()
            .map(Result::unwrap)
            .collect()
    }

    fn row<'a>(p: &'a Plan, var: &str) -> &'a ms_import::plan::Row {
        p.rows.iter().find(|r| r.var == var).unwrap()
    }

    fn k(p: &Plan, var: &str) -> String {
        row(p, var).key.as_ref().unwrap().to_string()
    }

    const T1: &str = "sk_test_51AAAAaaaaBBBBbbbbCCCCcccc";
    const T2: &str = "sk_test_51ZZZZzzzzYYYYyyyyXXXXxxxx";
    const T3: &str = "sk_test_51SharedSharedSharedShared00";
    const OAI: &str = "sk-proj-AAAAbbbbCCCCddddEEEEffffGGGGhhhh";

    // protects=design §4.6 names: `<slug>/<var>`; the same variable with another value in a later
    // file gets the file segment; a shared value is one key (later rows reuse it, even across
    // files and under another variable); a name the vault holds gets -2; fails_when=two values
    // share a key, a shared value is stored twice, or an existing key would be overwritten;
    // no_claim=tiers (import_raises_tier_from_file_name)
    #[test]
    fn same_var_two_values_gets_file_segment() {
        let p = plans(
            &[
                (
                    ".env",
                    &format!("STRIPE_SECRET_KEY={T1}\nOPENAI_API_KEY={OAI}\nPORT=3000\n"),
                ),
                (".env.production", &format!("STRIPE_SECRET_KEY={T2}\n")),
                (
                    "apps/web/.env",
                    &format!("OPENAI_API_KEY={OAI}\nOTHER_OPENAI={OAI}\n"),
                ),
            ],
            &[],
            &["shop/openai-api-key"],
        );
        assert_eq!(k(&p[0], "STRIPE_SECRET_KEY"), "shop/stripe-secret-key");
        assert_eq!(k(&p[0], "OPENAI_API_KEY"), "shop/openai-api-key-2");
        assert_eq!(row(&p[0], "PORT").action, Action::KeptNotSecret);
        assert_eq!(
            k(&p[1], "STRIPE_SECRET_KEY"),
            "shop/production/stripe-secret-key"
        );
        assert_eq!(row(&p[1], "STRIPE_SECRET_KEY").action, Action::Import);
        for var in ["OPENAI_API_KEY", "OTHER_OPENAI"] {
            assert_eq!(row(&p[2], var).action, Action::Reuse, "{var}");
            assert_eq!(k(&p[2], var), "shop/openai-api-key-2", "{var}");
        }
        assert_eq!(p[2].import_count(), 0);
        assert_eq!(file_segment("apps/web/.env"), "apps-web");
        assert_eq!(file_segment("apps/web/.env.local"), "apps-web-local");
        assert_eq!(file_segment("prod.env"), "prod");
        assert_eq!(file_segment(".env"), "root");
        assert_eq!(file_segment(".dev.vars"), "dev-vars");
    }

    // protects=design §4.6 tiers: a production-named file raises its keys to production (never
    // lowers), and a key shared with such a file is production everywhere; other files keep the
    // classifier's tier; fails_when=a .env.production key is test, or a production hint is
    // lowered; no_claim=classifier tier hints (ms-import classify tests)
    #[test]
    fn import_raises_tier_from_file_name() {
        let p = plans(
            &[
                (".env", &format!("STRIPE_SECRET_KEY={T1}\nPAY_KEY={T3}\n")),
                (
                    ".env.production",
                    &format!("STRIPE_SECRET_KEY={T2}\nPAY_KEY={T3}\n"),
                ),
            ],
            &[],
            &[],
        );
        assert_eq!(row(&p[0], "STRIPE_SECRET_KEY").tier, Some(Tier::Test));
        assert_eq!(row(&p[1], "STRIPE_SECRET_KEY").tier, Some(Tier::Production));
        // Shared with the production file: production in both.
        assert_eq!(row(&p[0], "PAY_KEY").tier, Some(Tier::Production));
        assert_eq!(row(&p[1], "PAY_KEY").action, Action::Reuse);
        assert_eq!(row(&p[1], "PAY_KEY").tier, Some(Tier::Production));
        assert!(is_production_file(".env.prod") && is_production_file("a/.env.live"));
        assert!(is_production_file(".env.production.local"));
        assert!(!is_production_file(".env.staging") && !is_production_file(".env"));
    }

    // protects=design §4.5 example hints: a variable the classifier calls "not secret" is imported
    // when an example file lists it; without the hint it stays; fails_when=the hint is ignored or
    // imports a public value; no_claim=-
    #[test]
    fn example_names_raise_confidence() {
        let src = "APP_FLAG=abc123def456\nNEXT_PUBLIC_X=pk_test_1\n";
        let without = plans(&[(".env", src)], &[], &[]);
        assert_eq!(row(&without[0], "APP_FLAG").action, Action::KeptNotSecret);
        let with = plans(&[(".env", src)], &["APP_FLAG", "NEXT_PUBLIC_X"], &[]);
        assert_eq!(row(&with[0], "APP_FLAG").action, Action::Import);
        assert_eq!(k(&with[0], "APP_FLAG"), "shop/app-flag");
        assert_ne!(row(&with[0], "NEXT_PUBLIC_X").action, Action::Import);
    }
}
