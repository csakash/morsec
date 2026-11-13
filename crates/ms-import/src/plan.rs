//! Turns classified entries into the review table: one row per entry, with the key it would go
//! to, its mode, tier and hosts. Pure: no I/O.

use std::collections::{BTreeMap, BTreeSet};

use ms_core::{KeyMeta, KeyName, MAX_SEGMENT_LEN, Mode, Tier};

use crate::Error;
use crate::catalog::Catalog;
use crate::classify::{Class, classify};
use crate::dotenv::Entry;

/// Per-variable overrides from the command line.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Import these even if classed as not secret.
    pub include: BTreeSet<String>,
    /// Never import these.
    pub exclude: BTreeSet<String>,
    /// Tier overrides.
    pub tiers: BTreeMap<String, Tier>,
    /// Key-name overrides.
    pub names: BTreeMap<String, KeyName>,
}

/// What happens to a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Moved into the vault; the file gets a reference.
    Import,
    /// Same value as an earlier row: gets that row's reference, nothing new is stored.
    Reuse,
    /// Stays as it is: not a secret.
    KeptNotSecret,
    /// Stays: public by design.
    KeptPublic,
    /// Stays: empty.
    KeptEmpty,
    /// Stays: excluded on the command line.
    KeptExcluded,
    /// Stays: already a reference.
    AlreadyRef,
    /// Stays: uses interpolation.
    Interpolated,
}

impl Action {
    /// Short label for the table.
    pub fn label(self) -> &'static str {
        match self {
            Action::Import => "import",
            Action::Reuse => "import (same value)",
            Action::KeptNotSecret => "keep: not a secret",
            Action::KeptPublic => "keep: public",
            Action::KeptEmpty => "keep: empty",
            Action::KeptExcluded => "keep: --exclude",
            Action::AlreadyRef => "already a ref",
            Action::Interpolated => "keep: ${...}",
        }
    }

    /// True when the file's value is replaced by a reference.
    pub fn rewrites(self) -> bool {
        matches!(self, Action::Import | Action::Reuse)
    }
}

/// One row of the review table. Holds no value: only an index into the entries.
#[derive(Debug, Clone)]
pub struct Row {
    /// Index into the parsed entries.
    pub entry: usize,
    /// Variable name.
    pub var: String,
    /// Line in the file.
    pub line: usize,
    /// What happens.
    pub action: Action,
    /// Target key, for import and reuse rows.
    pub key: Option<KeyName>,
    /// Provider id, when known.
    pub provider: Option<String>,
    /// Provider display name, or `unknown`.
    pub provider_name: String,
    /// Mode, for import and reuse rows.
    pub mode: Option<Mode>,
    /// Tier, for import and reuse rows.
    pub tier: Option<Tier>,
    /// Hosts the key may go to (empty = unusable until `ms rules` adds one).
    pub hosts: Vec<String>,
    /// What may be shown of the value: a public prefix and `…`, plus the length.
    pub masked: String,
}

/// The review table.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Rows, in file order.
    pub rows: Vec<Row>,
}

impl Plan {
    /// Rows whose value is stored (one per new key).
    pub fn imports(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|r| r.action == Action::Import)
    }

    /// Number of keys that would be stored.
    pub fn import_count(&self) -> usize {
        self.imports().count()
    }
}

fn mask(shown_prefix: &str, len: usize) -> String {
    format!("{shown_prefix}… ({len} bytes)")
}

/// `MY_API_KEY` → `my-api-key`: a valid key-name segment.
fn slug(var: &str) -> String {
    let mut s = String::new();
    for c in var.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    let mut s: String = s
        .trim_end_matches('-')
        .chars()
        .take(MAX_SEGMENT_LEN)
        .collect();
    while s.ends_with('-') {
        s.pop();
    }
    if s.is_empty() { "var".to_owned() } else { s }
}

/// `base`, or `base` with `-2`, `-3`, … on its last segment, whichever is free.
fn unique(base: &KeyName, taken: &BTreeSet<KeyName>) -> KeyName {
    if !taken.contains(base) {
        return base.clone();
    }
    let s = base.as_str();
    let (head, last) = match s.rsplit_once('/') {
        Some((h, l)) => (Some(h), l),
        None => (None, s),
    };
    for n in 2u32.. {
        let suffix = format!("-{n}");
        let mut seg: String = last.chars().take(MAX_SEGMENT_LEN - suffix.len()).collect();
        while seg.ends_with('-') {
            seg.pop();
        }
        seg.push_str(&suffix);
        let candidate = match head {
            Some(h) => format!("{h}/{seg}"),
            None => seg,
        };
        if let Ok(k) = KeyName::new(&candidate)
            && !taken.contains(&k)
        {
            return k;
        }
    }
    unreachable!("u32 suffixes exhausted")
}

/// Builds the review table. `existing` is the vault's current keys: none is ever reused or
/// overwritten.
pub fn plan(
    catalog: &Catalog,
    entries: &[Entry],
    existing: &[KeyMeta],
    opts: &Options,
) -> Result<Plan, Error> {
    // Every override must name a variable in the file (a typo must not silently do nothing).
    let vars: BTreeSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    for v in opts
        .include
        .iter()
        .chain(&opts.exclude)
        .chain(opts.tiers.keys())
        .chain(opts.names.keys())
    {
        if !vars.contains(v.as_str()) {
            return Err(Error::Usage(format!("no variable named {v} in the file")));
        }
    }
    // An override is keyed by variable name, so it would apply to every line defining that
    // name and could give two different values one key (the second put would replace the first).
    for v in opts.tiers.keys().chain(opts.names.keys()) {
        let n = entries.iter().filter(|e| e.name == *v).count();
        if n > 1 {
            return Err(Error::Usage(format!(
                "{v} is defined {n} times in the file, so --tier/--name for it is ambiguous. \
                 Remove the duplicate lines first"
            )));
        }
    }
    if let Some(v) = opts.include.intersection(&opts.exclude).next() {
        return Err(Error::Usage(format!("{v} is both --include and --exclude")));
    }

    let mut taken: BTreeSet<KeyName> = existing.iter().map(|m| m.name.clone()).collect();
    for (var, name) in &opts.names {
        if taken.contains(name) {
            return Err(Error::Usage(format!(
                "--name {var}={name}: a key named {name} already exists"
            )));
        }
    }
    let mut chosen: BTreeMap<&KeyName, &str> = BTreeMap::new();
    for (var, name) in &opts.names {
        if let Some(other) = chosen.insert(name, var) {
            return Err(Error::Usage(format!(
                "--name gives {other} and {var} the same key {name}"
            )));
        }
    }
    taken.extend(opts.names.values().cloned());

    let mut rows = Vec::with_capacity(entries.len());
    // Index of the first import row for each distinct value.
    let mut first_by_value: Vec<usize> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let class = classify(catalog, e);
        let len = e.value().len();
        let mut row = Row {
            entry: i,
            var: e.name.clone(),
            line: e.line,
            action: Action::KeptNotSecret,
            key: None,
            provider: None,
            provider_name: String::new(),
            mode: None,
            tier: None,
            hosts: Vec::new(),
            masked: mask("", len),
        };
        let secret = match class {
            Class::AlreadyRef => {
                row.action = Action::AlreadyRef;
                // A reference is not a secret: show it.
                row.masked = String::from_utf8_lossy(e.value()).into_owned();
                None
            }
            Class::Interpolated => {
                row.action = Action::Interpolated;
                None
            }
            Class::Empty => {
                row.action = Action::KeptEmpty;
                None
            }
            Class::Public if !opts.include.contains(&e.name) => {
                row.action = Action::KeptPublic;
                None
            }
            Class::NotSecret if !opts.include.contains(&e.name) => {
                row.action = Action::KeptNotSecret;
                None
            }
            Class::Public | Class::NotSecret => Some(crate::classify::Secret {
                provider: None,
                tier_hint: None,
                shown_prefix: String::new(),
            }),
            Class::Secret(s) => Some(s),
        };
        let Some(secret) = secret else {
            if opts.tiers.contains_key(&e.name) || opts.names.contains_key(&e.name) {
                return Err(Error::Usage(format!(
                    "{} is not imported ({}), so --tier/--name do not apply; add --include {}",
                    e.name,
                    row.action.label(),
                    e.name
                )));
            }
            rows.push(row);
            continue;
        };
        if opts.exclude.contains(&e.name) {
            row.action = Action::KeptExcluded;
            row.masked = mask(&secret.shown_prefix, len);
            rows.push(row);
            continue;
        }
        let provider = secret.provider.as_deref().and_then(|id| catalog.get(id));
        // No hint: production, so use asks first (fails closed).
        let tier = opts
            .tiers
            .get(&e.name)
            .copied()
            .or(secret.tier_hint)
            .unwrap_or(Tier::Production);
        row.provider = provider.map(|p| p.id.clone());
        row.provider_name = provider.map_or_else(|| "unknown".to_owned(), |p| p.name.clone());
        row.mode = Some(provider.map_or(Mode::Swap, |p| p.mode));
        row.tier = Some(tier);
        row.hosts = provider.map(|p| p.hosts.clone()).unwrap_or_default();
        row.masked = mask(&secret.shown_prefix, len);

        // Same value as an earlier import → same key.
        if let Some(&j) = first_by_value
            .iter()
            .find(|&&j| entries[rows[j].entry].value() == e.value())
        {
            if opts.names.contains_key(&e.name) || opts.tiers.contains_key(&e.name) {
                return Err(Error::Usage(format!(
                    "{} has the same value as {}, so it shares that key; set --name/--tier on {}",
                    e.name, rows[j].var, rows[j].var
                )));
            }
            let first = &rows[j];
            row.action = Action::Reuse;
            row.key = first.key.clone();
            row.provider = first.provider.clone();
            row.provider_name = first.provider_name.clone();
            row.mode = first.mode;
            row.tier = first.tier;
            row.hosts = first.hosts.clone();
            rows.push(row);
            continue;
        }

        let key = match opts.names.get(&e.name) {
            Some(k) => k.clone(),
            None => {
                let base = match provider {
                    Some(p) => p.key_name(tier),
                    None => KeyName::new(&format!("env/{}", slug(&e.name)))
                        .unwrap_or_else(|_| unreachable!("slug is a valid segment")),
                };
                let k = unique(&base, &taken);
                taken.insert(k.clone());
                k
            }
        };
        row.action = Action::Import;
        row.key = Some(key);
        first_by_value.push(rows.len());
        rows.push(row);
    }

    // No two stored keys may share a name: the second put would replace the first value.
    let mut seen = BTreeSet::new();
    for r in rows.iter().filter(|r| r.action == Action::Import) {
        if let Some(k) = &r.key
            && !seen.insert(k)
        {
            return Err(Error::Usage(format!(
                "two different values would be stored as {k}. Use --name to tell them apart"
            )));
        }
    }

    // An unquoted value cut at ` #` may continue into the comment for some loaders; rewriting
    // only the part before it could leave the rest of a secret in the file.
    if let Some(r) = rows
        .iter()
        .find(|r| r.action.rewrites() && entries[r.entry].inline_comment)
    {
        return Err(Error::Usage(format!(
            "{} (line {}): the unquoted value is followed by ' #...', which some loaders read as \
             part of the value. Quote the value or move the comment to its own line, or skip it \
             with --exclude {}",
            r.var, r.line, r.var
        )));
    }

    // A kept row holding the same value as an imported secret would leave that secret in the
    // file under another name: it gets the same reference.
    for i in 0..rows.len() {
        if !matches!(rows[i].action, Action::KeptNotSecret | Action::KeptPublic) {
            continue;
        }
        let value = entries[rows[i].entry].value();
        if let Some(&j) = first_by_value
            .iter()
            .find(|&&j| entries[rows[j].entry].value() == value)
        {
            let first = rows[j].clone();
            let row = &mut rows[i];
            row.action = Action::Reuse;
            row.key = first.key;
            row.provider = first.provider;
            row.provider_name = first.provider_name;
            row.mode = first.mode;
            row.tier = first.tier;
            row.hosts = first.hosts;
        }
    }
    Ok(Plan { rows })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotenv::parse;

    fn plan_of(src: &str, existing: &[&str], opts: &Options) -> Result<Plan, Error> {
        let entries = parse(src).unwrap();
        let existing: Vec<KeyMeta> = existing
            .iter()
            .map(|n| KeyMeta {
                name: KeyName::new(n).unwrap(),
                mode: Mode::Swap,
                tier: Tier::Test,
                created_unix_ms: 0,
            })
            .collect();
        plan(Catalog::builtin(), &entries, &existing, opts)
    }

    fn keys(p: &Plan) -> Vec<(String, String, String)> {
        p.rows
            .iter()
            .map(|r| {
                (
                    r.var.clone(),
                    r.action.label().to_owned(),
                    r.key.as_ref().map(|k| k.to_string()).unwrap_or_default(),
                )
            })
            .collect()
    }

    fn row(v: &str, a: &str, k: &str) -> (String, String, String) {
        (v.into(), a.into(), k.into())
    }

    // protects=naming, collision suffixes, never reusing an existing vault key, AWS pairs, and
    // one key for a repeated value; fails_when=two rows share a key without the same value, an
    // existing key is targeted, or the AWS pair is split; no_claim=storage (see import tests)
    #[test]
    fn naming_and_dedupe() {
        let x = "x".repeat(40);
        let src = format!(
            "STRIPE_A=sk_test_{x}\n\
             STRIPE_B=sk_test_{x}\n\
             STRIPE_C=sk_test_{x}y\n\
             STRIPE_LIVE=sk_live_{x}\n\
             AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
             AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
             SESSION_SECRET=hunter2\n\
             PORT=3000\n\
             NEXT_PUBLIC_X=1\n\
             REF=ms://a/b\n\
             EMPTY=\n"
        );
        let p = plan_of(&src, &["stripe/test"], &Options::default()).unwrap();
        assert_eq!(
            keys(&p),
            vec![
                row("STRIPE_A", "import", "stripe/test-2"),
                row("STRIPE_B", "import (same value)", "stripe/test-2"),
                row("STRIPE_C", "import", "stripe/test-3"),
                row("STRIPE_LIVE", "import", "stripe/production"),
                row(
                    "AWS_ACCESS_KEY_ID",
                    "import",
                    "aws/production/access-key-id"
                ),
                row(
                    "AWS_SECRET_ACCESS_KEY",
                    "import",
                    "aws/production/secret-access-key"
                ),
                row("SESSION_SECRET", "import", "env/session-secret"),
                row("PORT", "keep: not a secret", ""),
                row("NEXT_PUBLIC_X", "keep: public", ""),
                row("REF", "already a ref", ""),
                row("EMPTY", "keep: empty", ""),
            ]
        );
        assert_eq!(p.import_count(), 6);
        let unknown = &p.rows[6];
        assert_eq!(unknown.mode, Some(Mode::Swap));
        assert_eq!(unknown.tier, Some(Tier::Production));
        assert!(unknown.hosts.is_empty(), "unknown keys get no hosts");
        assert_eq!(p.rows[0].hosts, ["api.stripe.com"]);
        assert_eq!(p.rows[0].masked, "sk_test_… (48 bytes)");
        assert_eq!(p.rows[6].masked, "… (7 bytes)");
    }

    // protects=overrides work and typos fail loudly; fails_when=an unknown variable, a clash or
    // an override on a kept row is accepted silently; no_claim=CLI parsing (see ms-cli tests)
    #[test]
    fn overrides() {
        let src = "A_KEY=one\nB_KEY=two\nPORT=3000\nSAME=one\n";
        let mut o = Options::default();
        o.include.insert("PORT".into());
        o.exclude.insert("B_KEY".into());
        o.tiers.insert("A_KEY".into(), Tier::Test);
        o.names
            .insert("A_KEY".into(), KeyName::new("custom/a").unwrap());
        let p = plan_of(src, &[], &o).unwrap();
        assert_eq!(
            keys(&p),
            vec![
                row("A_KEY", "import", "custom/a"),
                row("B_KEY", "keep: --exclude", ""),
                row("PORT", "import", "env/port"),
                row("SAME", "import (same value)", "custom/a"),
            ]
        );
        assert_eq!(p.rows[0].tier, Some(Tier::Test));

        let bad = |f: &dyn Fn(&mut Options)| {
            let mut o = Options::default();
            f(&mut o);
            plan_of(src, &["taken/x"], &o).unwrap_err().to_string()
        };
        assert!(
            bad(&|o| {
                o.include.insert("NOPE".into());
            })
            .contains("no variable named NOPE")
        );
        assert!(
            bad(&|o| {
                o.include.insert("A_KEY".into());
                o.exclude.insert("A_KEY".into());
            })
            .contains("both")
        );
        assert!(
            bad(&|o| {
                o.names
                    .insert("A_KEY".into(), KeyName::new("taken/x").unwrap());
            })
            .contains("already exists")
        );
        assert!(
            bad(&|o| {
                o.names.insert("A_KEY".into(), KeyName::new("k").unwrap());
                o.names.insert("B_KEY".into(), KeyName::new("k").unwrap());
            })
            .contains("same key")
        );
        assert!(
            bad(&|o| {
                o.tiers.insert("PORT".into(), Tier::Test);
            })
            .contains("--include PORT")
        );
        assert!(
            bad(&|o| {
                o.include.insert("SAME".into());
                o.names.insert("SAME".into(), KeyName::new("z").unwrap());
            })
            .contains("same value")
        );
        // A non-secret name holding a secret's value is rewritten too, even before it.
        let p = plan_of(
            "PORT=hunter2\nDB_PASSWORD=hunter2\n",
            &[],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(
            keys(&p),
            vec![
                row("PORT", "import (same value)", "env/db-password"),
                row("DB_PASSWORD", "import", "env/db-password"),
            ]
        );
    }

    // protects=a variable defined twice can't take --name/--tier (it would map two values to one
    // key and lose one), and without overrides the two values get two keys; fails_when=a value
    // is lost; no_claim=which definition a loader uses
    #[test]
    fn repeated_variable() {
        let src = "A_KEY=one\nA_KEY=two\n";
        let mut o = Options::default();
        o.names
            .insert("A_KEY".into(), KeyName::new("custom/a").unwrap());
        let e = plan_of(src, &[], &o).unwrap_err().to_string();
        assert!(e.contains("defined 2 times"), "{e}");
        let mut o = Options::default();
        o.tiers.insert("A_KEY".into(), Tier::Test);
        assert!(plan_of(src, &[], &o).is_err());
        let p = plan_of(src, &[], &Options::default()).unwrap();
        assert_eq!(
            keys(&p),
            vec![
                row("A_KEY", "import", "env/a-key"),
                row("A_KEY", "import", "env/a-key-2"),
            ]
        );
    }

    // protects=a secret whose unquoted value is followed by ' #' is refused (part of it could
    // stay behind), while a quoted one or a kept row with a comment is fine; fails_when=the
    // import proceeds; no_claim=which loader reads the comment
    #[test]
    fn inline_comment_on_secret_refused() {
        let e = plan_of("A_SECRET=abc #def\n", &[], &Options::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains("A_SECRET (line 1)") && !e.contains("abc"), "{e}");
        plan_of(
            "A_SECRET=\"abc\" # ok\nPORT=3000 # ok\n",
            &[],
            &Options::default(),
        )
        .unwrap();
        let mut o = Options::default();
        o.exclude.insert("A_SECRET".into());
        plan_of("A_SECRET=abc #def\n", &[], &o).unwrap();
    }

    // protects=slugs and suffixes always yield valid key names, even for long or odd variable
    // names; fails_when=KeyName::new would reject one (it would panic); no_claim=readability
    #[test]
    fn slug_and_unique_edge_cases() {
        assert_eq!(slug("MY__API.KEY_"), "my-api-key");
        assert_eq!(slug("_"), "var");
        let long = "A".repeat(100);
        assert_eq!(slug(&long).len(), MAX_SEGMENT_LEN);
        let base = KeyName::new(&format!("env/{}", "a".repeat(63))).unwrap();
        let mut taken = BTreeSet::from([base.clone()]);
        let k2 = unique(&base, &taken);
        assert!(k2.as_str().ends_with("-2") && k2.as_str().len() == 4 + 63);
        taken.insert(k2);
        assert!(unique(&base, &taken).as_str().ends_with("-3"));
    }
}
