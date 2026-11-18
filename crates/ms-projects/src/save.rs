//! `ProjectSave` (SPEC D-2): the first rules of a project's new keys, approved once.
//!
//! The CLI proposes, per new key, exactly what the catalog gives: its provider's hosts for a swap
//! key, the project root for a run key ([`initial_rules`]). msd re-derives the same rule from the
//! record and the catalog and accepts a proposal only when it is equal ([`check`]): a key whose
//! rule already allows something, a host the catalog doesn't name, a host on a run rule, a root
//! other than the project's, a key outside the slug or not in the vault are all refused. One
//! approval covers the whole set and is bound to [`rules_hash`] of its canonical TOML.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ms_core::{KeyName, Mode};
use ms_import::catalog::Catalog;
use ms_rules::{HostPattern, KeyRule, Rules};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::record::{ProjectRecord, ProjectsFile};

fn bad(why: impl Into<String>) -> Error {
    Error::Invalid(why.into())
}

/// True when `rule` is exactly what `put_key` gives a new key: nothing allowed, defaults kept.
pub fn is_fresh(rule: &KeyRule) -> bool {
    *rule == KeyRule::new(rule.mode, rule.tier)
}

/// The rule the catalog gives `key` in `record`, starting from its fresh rule `current`.
/// `None` when the catalog gives nothing (unknown provider, mint mode, no hosts).
pub fn catalog_rule(
    catalog: &Catalog,
    record: &ProjectRecord,
    key: &KeyName,
    current: &KeyRule,
) -> Option<KeyRule> {
    let mut r = KeyRule::new(current.mode, current.tier);
    match current.mode {
        Mode::Swap => {
            let p = catalog.get(record.provider_of(key)?)?;
            if p.mode != Mode::Swap || p.hosts.is_empty() {
                return None;
            }
            r.hosts = p
                .hosts
                .iter()
                .map(|h| HostPattern::parse(h))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
        }
        Mode::Run => r.roots = vec![PathBuf::from(&record.root)],
        Mode::Mint => return None,
    }
    r.normalise("the catalog", key).ok()
}

/// The rules the CLI proposes: one per key of `record` whose rule in `current` is still fresh
/// and for which the catalog gives something. Version 1 (ignored by msd).
pub fn initial_rules(catalog: &Catalog, record: &ProjectRecord, current: &Rules) -> Rules {
    let mut out = Rules {
        version: 1,
        ..Rules::default()
    };
    for key in record.keys() {
        let Some(cur) = current.keys.get(&key).filter(|r| is_fresh(r)) else {
            continue;
        };
        if let Some(r) = catalog_rule(catalog, record, &key, cur) {
            out.keys.insert(key, r);
        }
    }
    out
}

/// The canonical TOML of a proposed rule set: what the approval is bound to.
pub fn canonical(proposed: &Rules) -> String {
    Rules {
        version: 1,
        keys: proposed.keys.clone(),
        ..Rules::default()
    }
    .to_toml()
}

/// SHA-256 of [`canonical`].
pub fn rules_hash(proposed: &Rules) -> [u8; 32] {
    Sha256::digest(canonical(proposed).as_bytes()).into()
}

/// What the approval shows: `ms init <slug>`, one line per key with its hosts or root, and the
/// rules hash. Every line comes from the checked record and rules.
pub fn approval_argv(record: &ProjectRecord, proposed: &Rules) -> Vec<String> {
    let mut argv = vec!["ms".to_owned(), "init".to_owned(), record.slug.clone()];
    for (k, r) in &proposed.keys {
        let what = match r.mode {
            Mode::Run => format!(
                "may run in {}",
                r.roots
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => format!(
                "may go to {}",
                r.hosts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        argv.push(format!("{k} {what}"));
    }
    argv.push(format!(
        "rules sha256 {}",
        hex::encode(rules_hash(proposed))
    ));
    argv
}

/// msd's checks on a `ProjectSave`. `root_canonical` is `canonicalize(record.root)`;
/// `vault_keys` the vault's user keys; `current` the rules in force; `projects` the verified
/// records. Returns nothing on success: the caller applies `proposed` as given.
pub fn check(
    catalog: &Catalog,
    record: &ProjectRecord,
    proposed: &Rules,
    current: &Rules,
    vault_keys: &BTreeSet<KeyName>,
    projects: &ProjectsFile,
    root_canonical: Option<&Path>,
) -> Result<(), Error> {
    record.validate()?;
    if root_canonical != Some(Path::new(&record.root)) {
        return Err(bad(format!(
            "the project root {} is not an existing canonical directory",
            crate::record::printable(&record.root)
        )));
    }
    for p in &projects.projects {
        if p.slug == record.slug && p.root != record.root {
            return Err(bad(format!(
                "another folder is already project {}",
                record.slug
            )));
        }
        if p.root == record.root && p.slug != record.slug {
            return Err(bad(format!("this folder is already project {}", p.slug)));
        }
    }
    if projects.get(&record.slug).is_none()
        && projects.projects.len() >= crate::record::MAX_PROJECTS
    {
        return Err(bad(format!(
            "morsec keeps at most {} projects",
            crate::record::MAX_PROJECTS
        )));
    }
    let keys: BTreeSet<KeyName> = record.keys().into_iter().collect();
    for k in &keys {
        if !vault_keys.contains(k) {
            return Err(bad(format!("{k} is not in the vault")));
        }
    }
    for (k, r) in &proposed.keys {
        if !keys.contains(k) {
            return Err(bad(format!("{k} is not a key of project {}", record.slug)));
        }
        let Some(cur) = current.keys.get(k) else {
            return Err(bad(format!("{k} has no rule yet")));
        };
        if !is_fresh(cur) {
            return Err(bad(format!(
                "{k} already has a rule; change it with ms rules {k}"
            )));
        }
        match catalog_rule(catalog, record, k, cur) {
            Some(want) if want == *r => {}
            _ => {
                return Err(bad(format!(
                    "the rule for {k} is not the one the catalog gives (only its service's hosts for a swap key, only the project root for a run key)"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::sample;
    use ms_core::Tier;

    fn current() -> Rules {
        let mut r = Rules::default();
        r.keys.insert(
            KeyName::new("shop/stripe-secret-key").unwrap(),
            KeyRule::new(Mode::Swap, Tier::Test),
        );
        r
    }

    // protects=SPEC criterion 5 at the checker: the catalog rule for a fresh key passes; a key
    // outside the slug, a key not in the vault, a key whose rule already allows something, an
    // extra host, a host on a run rule and a non-canonical root are refused; the approval text
    // lists each key with its hosts and the rules hash changes with any rule; fails_when=any bad
    // case passes or two different sets share a hash; no_claim=msd's reply codes (daemon tests)
    #[test]
    fn save_checks() {
        let cat = Catalog::builtin();
        let rec = sample();
        let cur = current();
        let vault: BTreeSet<KeyName> = rec.keys().into_iter().collect();
        let root = PathBuf::from(&rec.root);
        let ok = initial_rules(cat, &rec, &cur);
        assert_eq!(ok.keys.len(), 1);
        let none = ProjectsFile::default();
        check(cat, &rec, &ok, &cur, &vault, &none, Some(&root)).unwrap();
        let argv = approval_argv(&rec, &ok);
        assert!(
            argv[3].starts_with("shop/stripe-secret-key may go to "),
            "{argv:?}"
        );
        assert!(argv[3].contains("api.stripe.com"), "{argv:?}");

        let k = KeyName::new("shop/stripe-secret-key").unwrap();
        let mut extra = ok.clone();
        extra
            .keys
            .get_mut(&k)
            .unwrap()
            .hosts
            .push(HostPattern::parse("evil.example").unwrap());
        assert_ne!(rules_hash(&extra), rules_hash(&ok));
        let mut run = ok.clone();
        let mut rr = KeyRule::new(Mode::Swap, Tier::Test);
        rr.roots = vec![root.clone()];
        run.keys.insert(k.clone(), rr);
        let mut loosened = cur.clone();
        loosened.keys.get_mut(&k).unwrap().hosts = vec![HostPattern::parse("x.example").unwrap()];
        let mut foreign = ok.clone();
        foreign.keys.insert(
            KeyName::new("other/k").unwrap(),
            KeyRule::new(Mode::Swap, Tier::Test),
        );
        let mut tier = ok.clone();
        tier.keys.get_mut(&k).unwrap().tier = Tier::Production;
        let cases: Vec<(&str, Result<(), Error>)> = vec![
            (
                "extra host",
                check(cat, &rec, &extra, &cur, &vault, &none, Some(&root)),
            ),
            (
                "rule with roots on swap",
                check(cat, &rec, &run, &cur, &vault, &none, Some(&root)),
            ),
            (
                "existing rule",
                check(cat, &rec, &ok, &loosened, &vault, &none, Some(&root)),
            ),
            (
                "outside the slug",
                check(cat, &rec, &foreign, &cur, &vault, &none, Some(&root)),
            ),
            (
                "tier change",
                check(cat, &rec, &tier, &cur, &vault, &none, Some(&root)),
            ),
            (
                "not in vault",
                check(cat, &rec, &ok, &cur, &BTreeSet::new(), &none, Some(&root)),
            ),
            (
                "not canonical",
                check(
                    cat,
                    &rec,
                    &ok,
                    &cur,
                    &vault,
                    &none,
                    Some(Path::new("/private/x")),
                ),
            ),
        ];
        for (what, r) in cases {
            assert!(matches!(r, Err(Error::Invalid(_))), "{what}: {r:?}");
        }
        // Another folder already holds the slug.
        let mut other = sample();
        other.root = "/Users/me/old/shop".into();
        let taken = ProjectsFile {
            version: 1,
            projects: vec![other],
        };
        assert!(check(cat, &rec, &ok, &cur, &vault, &taken, Some(&root)).is_err());
    }

    // protects=run-mode keys get only the project root (design §4.6), and unknown providers get
    // nothing (they stay inert); fails_when=a run rule carries hosts or commands, or an unknown
    // key gets any target; no_claim=-
    #[test]
    fn run_keys_get_only_the_root() {
        let cat = Catalog::builtin();
        let mut rec = sample();
        let pg = KeyName::new("shop/database-url").unwrap();
        let unknown = KeyName::new("shop/session-secret").unwrap();
        let mut s = rec.files[0].secrets[0].clone();
        s.key = pg.clone();
        s.provider = Some("pg".into());
        rec.files[0].secrets.push(s.clone());
        s.key = unknown.clone();
        s.provider = None;
        rec.files[0].secrets.push(s);
        let mut cur = current();
        cur.keys
            .insert(pg.clone(), KeyRule::new(Mode::Run, Tier::Production));
        cur.keys
            .insert(unknown.clone(), KeyRule::new(Mode::Swap, Tier::Production));
        let r = initial_rules(cat, &rec, &cur);
        let run = &r.keys[&pg];
        assert_eq!(run.roots, vec![PathBuf::from(&rec.root)]);
        assert!(run.hosts.is_empty() && run.commands.is_empty() && run.env.is_empty());
        assert!(!r.keys.contains_key(&unknown));
    }
}
