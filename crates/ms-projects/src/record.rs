//! The project record (design §5.2): what `ms init` found and did in one project. It never holds
//! a value: variable names, lines, key names, providers and a masked form of code findings only.

use std::path::{Component, Path};

use ms_core::KeyName;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Most projects in `projects.toml`.
pub const MAX_PROJECTS: usize = 500;
/// Most secrets in one project.
pub const MAX_SECRETS: usize = 2_000;
/// Most code findings kept for one project.
pub const MAX_FINDINGS: usize = 2_000;
/// Most bytes of paths in one project's lists.
pub const MAX_PATH_BYTES: usize = 64 * 1024;
/// Longest single path or text field.
pub const MAX_FIELD: usize = 1024;

/// How a value was quoted in the file (restores the original form on Undo, L33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quote {
    /// `NAME=value`
    None,
    /// `NAME='value'`
    Single,
    /// `NAME="value"`
    Double,
    /// `` NAME=`value` ``
    Backtick,
}

impl From<ms_import::dotenv::Quote> for Quote {
    fn from(q: ms_import::dotenv::Quote) -> Self {
        match q {
            ms_import::dotenv::Quote::None => Quote::None,
            ms_import::dotenv::Quote::Single => Quote::Single,
            ms_import::dotenv::Quote::Double => Quote::Double,
            ms_import::dotenv::Quote::Backtick => Quote::Backtick,
        }
    }
}

/// What import did with one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    /// Stored as a new key.
    Import,
    /// Same value as another line: points at that key.
    Reuse,
}

/// One secret line of an env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRecord {
    /// Variable name.
    pub var: String,
    /// 1-based line.
    pub line: u64,
    /// The key the line now refers to.
    pub key: KeyName,
    /// Original quoting.
    pub quote: Quote,
    /// Import or reuse.
    pub action: SecretAction,
    /// Catalog provider id, when known (msd checks proposed hosts against it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// One env file of the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// Path relative to the root.
    pub path: String,
    /// Commits in git history that touched the file, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_history_commits: Option<u64>,
    /// Its secret lines.
    #[serde(default, rename = "secret", skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretRecord>,
}

/// A key written into code: never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRecord {
    /// Path relative to the root.
    pub path: String,
    /// 1-based line.
    pub line: u64,
    /// Catalog provider id.
    pub provider: String,
    /// The catalog prefix, `…` and the length.
    pub masked: String,
}

/// A file the agent hint block was added to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HintRecord {
    /// Path relative to the root.
    pub path: String,
}

/// How the last scan went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRecord {
    /// Entries visited.
    pub entries: u64,
    /// A budget stopped it.
    pub stopped_early: bool,
    /// Wall time, ms.
    pub ms: u64,
}

/// One project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    /// Name; every key of the project starts with `<slug>/`.
    pub slug: String,
    /// The folder's own name, for display (render it inert).
    pub display: String,
    /// Canonical root.
    pub root: String,
    /// When first set up, Unix ms.
    pub created_unix_ms: u64,
    /// The last scan.
    #[serde(default)]
    pub scan: ScanRecord,
    /// Env files.
    #[serde(default, rename = "file", skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileRecord>,
    /// Keys written into code.
    #[serde(default, rename = "finding", skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingRecord>,
    /// Files holding the hint block.
    #[serde(default, rename = "hint", skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<HintRecord>,
}

/// `projects.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectsFile {
    /// Rises by one on every save; an older file put back is refused (rollback).
    pub version: u64,
    /// The projects.
    #[serde(default, rename = "project", skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<ProjectRecord>,
}

fn bad(why: impl Into<String>) -> Error {
    Error::Invalid(why.into())
}

/// A text field msd accepts: 1 to [`MAX_FIELD`] bytes without control characters.
pub fn check_text(s: &str, what: &str) -> Result<(), Error> {
    text_ok(s, what)
}

/// Control characters, and bidi, zero-width and other invisible format characters (security
/// review S3): none may reach the approval text or a terminal from a record.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control() || ms_approve::render::is_invisible_or_bidi(c)
}

fn text_ok(s: &str, what: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > MAX_FIELD || s.chars().any(is_unsafe_char) {
        return Err(bad(format!(
            "{what} must be 1 to {MAX_FIELD} bytes without control or invisible characters"
        )));
    }
    Ok(())
}

/// `s` with control characters escaped, at most 200 characters.
pub fn printable(s: &str) -> String {
    s.chars().take(200).flat_map(char::escape_default).collect()
}

/// A path relative to the root: no `/` at the start, no `.` or `..`, no empty segment.
pub fn check_rel(p: &str) -> Result<(), Error> {
    text_ok(p, "a project path")?;
    let path = Path::new(p);
    if p.starts_with('/')
        || p.ends_with('/')
        || p.contains("//")
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(bad(format!(
            "{} is not a plain path inside the project",
            printable(p)
        )));
    }
    Ok(())
}

/// Room kept in a project's path budget for the hint files (`CLAUDE.md`, `AGENTS.md`).
pub const HINT_RESERVE: usize = 64;

/// A display name [`ProjectRecord::validate`] accepts: control characters dropped, cut to
/// [`MAX_FIELD`] bytes on a character boundary; `fallback` when nothing is left.
pub fn display_name(s: &str, fallback: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !is_unsafe_char(*c)) {
        if out.len() + c.len_utf8() > MAX_FIELD {
            break;
        }
        out.push(c);
    }
    if out.trim().is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

/// Whether an env file can be added to a record that already holds `secrets_so_far` secrets and
/// `path_bytes_so_far` bytes of paths: its path must be recordable and both limits must still
/// hold. The CLI imports a file only when this passes, so no key exists without a record entry.
pub fn admit_file(
    rel: &str,
    new_secrets: usize,
    secrets_so_far: usize,
    path_bytes_so_far: usize,
) -> Result<(), Error> {
    check_rel(rel)?;
    if secrets_so_far + new_secrets > MAX_SECRETS {
        return Err(bad(format!(
            "the project would have more than {MAX_SECRETS} secrets"
        )));
    }
    if path_bytes_so_far + rel.len() + HINT_RESERVE > MAX_PATH_BYTES {
        return Err(bad(format!(
            "the project's file list would be larger than {MAX_PATH_BYTES} bytes"
        )));
    }
    Ok(())
}

fn check_finding(f: &FindingRecord) -> Result<(), Error> {
    check_rel(&f.path)?;
    if KeyName::new(&f.provider).is_err() || f.provider.contains('/') {
        return Err(bad("a provider id must be one key-name segment"));
    }
    // The catalog prefix (at most a few dozen bytes), "…" and the length: no room for a value.
    if f.masked.len() > 80 || !f.masked.ends_with(" bytes)") || !f.masked.contains('…') {
        return Err(bad("a code finding's masked form is not prefix… (N bytes)"));
    }
    Ok(())
}

/// The code findings a record with `path_bytes_used` bytes of paths can hold: each must pass
/// the record's checks, at most [`MAX_FINDINGS`], within [`MAX_PATH_BYTES`]. Returns the kept
/// findings and how many were left out.
pub fn fit_findings(
    findings: Vec<FindingRecord>,
    path_bytes_used: usize,
) -> (Vec<FindingRecord>, usize) {
    let mut left = MAX_PATH_BYTES.saturating_sub(path_bytes_used + HINT_RESERVE);
    let total = findings.len();
    let mut kept = Vec::new();
    for f in findings {
        if kept.len() >= MAX_FINDINGS || check_finding(&f).is_err() || f.path.len() > left {
            continue;
        }
        left -= f.path.len();
        kept.push(f);
    }
    let skipped = total - kept.len();
    (kept, skipped)
}

impl ProjectRecord {
    /// Bytes of file and hint paths (findings excluded).
    pub fn path_bytes(&self) -> usize {
        self.files.iter().map(|f| f.path.len()).sum::<usize>()
            + self.hints.iter().map(|h| h.path.len()).sum::<usize>()
    }

    /// Secret lines in the record.
    pub fn secret_count(&self) -> usize {
        self.files.iter().map(|f| f.secrets.len()).sum()
    }

    /// Every key the record names, deduplicated, sorted.
    pub fn keys(&self) -> Vec<KeyName> {
        let mut k: Vec<KeyName> = self
            .files
            .iter()
            .flat_map(|f| f.secrets.iter().map(|s| s.key.clone()))
            .collect();
        k.sort();
        k.dedup();
        k
    }

    /// The provider recorded for `key`, if any line names one.
    pub fn provider_of(&self, key: &KeyName) -> Option<&str> {
        self.files
            .iter()
            .flat_map(|f| &f.secrets)
            .find(|s| &s.key == key && s.provider.is_some())
            .and_then(|s| s.provider.as_deref())
    }

    /// Checks the limits and shapes (design §5.2). Does not touch the file system.
    pub fn validate(&self) -> Result<(), Error> {
        if KeyName::new(&format!("{}/x", self.slug)).is_err() || self.slug.contains('/') {
            return Err(bad(
                "the project name must be one key-name segment (a-z, 0-9, -)",
            ));
        }
        text_ok(&self.display, "the display name")?;
        ms_rules::validate_root(Path::new(&self.root)).map_err(bad)?;
        if self.root.chars().any(is_unsafe_char) {
            return Err(bad(
                "the project root has bidi or invisible characters; move the project to a plain path",
            ));
        }
        let secrets: usize = self.files.iter().map(|f| f.secrets.len()).sum();
        if secrets > MAX_SECRETS {
            return Err(bad(format!(
                "more than {MAX_SECRETS} secrets in one project"
            )));
        }
        if self.findings.len() > MAX_FINDINGS {
            return Err(bad(format!("more than {MAX_FINDINGS} code findings")));
        }
        let mut bytes = 0usize;
        let prefix = format!("{}/", self.slug);
        for f in &self.files {
            check_rel(&f.path)?;
            bytes += f.path.len();
            for s in &f.secrets {
                text_ok(&s.var, "a variable name")?;
                if !s.key.as_str().starts_with(&prefix) {
                    return Err(bad(format!(
                        "{} is not a key of project {}",
                        s.key, self.slug
                    )));
                }
                if let Some(p) = &s.provider
                    && (p.len() > 64 || KeyName::new(p).is_err() || p.contains('/'))
                {
                    return Err(bad("a provider id must be one key-name segment"));
                }
            }
        }
        for f in &self.findings {
            check_finding(f)?;
            bytes += f.path.len();
        }
        for h in &self.hints {
            check_rel(&h.path)?;
            bytes += h.path.len();
        }
        if bytes > MAX_PATH_BYTES {
            return Err(bad(format!(
                "the project's path lists are larger than {MAX_PATH_BYTES} bytes"
            )));
        }
        Ok(())
    }

    /// The record as TOML (one `[[project]]` table, for IPC).
    pub fn to_toml(&self) -> String {
        toml::to_string(&ProjectsFile {
            version: 0,
            projects: vec![self.clone()],
        })
        .unwrap_or_else(|e| unreachable!("a project record always serializes: {e}"))
    }

    /// Parses [`Self::to_toml`]'s form and validates it.
    pub fn from_toml(text: &str) -> Result<Self, Error> {
        if text.len() > 4 << 20 {
            return Err(bad("the project record is larger than 4 MiB"));
        }
        let f: ProjectsFile = toml::from_str(text)
            .map_err(|e| bad(format!("the project record: {}", e.message())))?;
        let [p] = <[ProjectRecord; 1]>::try_from(f.projects)
            .map_err(|_| bad("exactly one project record expected"))?;
        p.validate()?;
        Ok(p)
    }
}

impl ProjectsFile {
    /// The file as TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_else(|e| unreachable!("projects always serialize: {e}"))
    }

    /// Parses and validates `projects.toml`.
    pub fn from_toml(text: &str) -> Result<Self, Error> {
        let f: ProjectsFile =
            toml::from_str(text).map_err(|e| bad(format!("projects.toml: {}", e.message())))?;
        if f.projects.len() > MAX_PROJECTS {
            return Err(bad(format!("more than {MAX_PROJECTS} projects")));
        }
        for p in &f.projects {
            p.validate()?;
        }
        Ok(f)
    }

    /// The project named `slug`.
    pub fn get(&self, slug: &str) -> Option<&ProjectRecord> {
        self.projects.iter().find(|p| p.slug == slug)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> ProjectRecord {
        ProjectRecord {
            slug: "shop".into(),
            display: "Shop".into(),
            root: "/Users/me/code/shop".into(),
            created_unix_ms: 1,
            scan: ScanRecord {
                entries: 42,
                stopped_early: false,
                ms: 3,
            },
            files: vec![FileRecord {
                path: ".env".into(),
                git_history_commits: Some(2),
                secrets: vec![SecretRecord {
                    var: "STRIPE_SECRET_KEY".into(),
                    line: 4,
                    key: KeyName::new("shop/stripe-secret-key").unwrap(),
                    quote: Quote::Double,
                    action: SecretAction::Import,
                    provider: Some("stripe".into()),
                }],
            }],
            findings: vec![FindingRecord {
                path: "src/lib/stripe.ts".into(),
                line: 4,
                provider: "stripe".into(),
                masked: "sk_live_… (107 bytes)".into(),
            }],
            hints: vec![HintRecord {
                path: "CLAUDE.md".into(),
            }],
        }
    }

    // protects=design §5.2: the record round-trips through TOML (the IPC form and the file
    // form) unchanged; unknown fields are refused; fails_when=a field is lost or an extra field
    // is accepted; no_claim=MAC (store tests)
    #[test]
    fn record_toml_round_trip() {
        let r = sample();
        let text = r.to_toml();
        assert!(text.contains("[[project.file.secret]]"), "{text}");
        assert_eq!(ProjectRecord::from_toml(&text).unwrap(), r);
        let f = ProjectsFile {
            version: 7,
            projects: vec![r.clone()],
        };
        assert_eq!(ProjectsFile::from_toml(&f.to_toml()).unwrap(), f);
        let extra = text.replacen("slug = ", "value = \"x\"\nslug = ", 1);
        assert!(ProjectRecord::from_toml(&extra).is_err());
    }

    // protects=review R3: what the CLI builds from file-derived data always passes msd's checks:
    // a control character or an oversized display name is cleaned; a file with an unrecordable
    // name, one past the secret cap or past the path budget is not admitted (so it isn't
    // imported); findings that fail the checks or overflow the path budget are left out and
    // counted; fails_when=any of those produces a record validate() refuses, or drops a good
    // finding while there is room; no_claim=the CLI's summary wording (ms-cli tests)
    #[test]
    fn client_side_fits_the_limits() {
        assert_eq!(display_name("my\tshop\u{1b}[2J", "shop"), "myshop[2J");
        assert_eq!(display_name("\u{7}\n", "shop"), "shop");
        let long = display_name(&"é".repeat(MAX_FIELD), "x");
        assert!(long.len() <= MAX_FIELD && check_text(&long, "d").is_ok());
        assert!(admit_file(".env", 3, 0, 0).is_ok());
        assert!(admit_file(".env.\u{1}x", 1, 0, 0).is_err());
        assert!(admit_file("../.env", 1, 0, 0).is_err());
        assert!(admit_file(".env", 2, MAX_SECRETS - 1, 0).is_err());
        assert!(admit_file(".env", 1, 0, MAX_PATH_BYTES - 10).is_err());

        let mut r = sample();
        let good = r.findings[0].clone();
        let mut bad_path = good.clone();
        bad_path.path = "src/\u{1}.ts".into();
        let mut many: Vec<FindingRecord> = vec![bad_path];
        let mut big = good.clone();
        big.path = format!("src/{}.ts", "a".repeat(900));
        many.extend(std::iter::repeat_n(big, 100));
        many.push(good.clone());
        let (kept, skipped) = fit_findings(many, r.path_bytes());
        assert_eq!(kept.len() + skipped, 102);
        assert!(skipped > 1);
        r.findings = kept;
        r.validate().unwrap();
        let (kept, skipped) = fit_findings(vec![good.clone(); MAX_FINDINGS + 5], 0);
        assert_eq!((kept.len(), skipped), (MAX_FINDINGS, 5));
    }

    // protects=security review S3: a bidi override (U+202E) or a zero-width character in the root,
    // a display name, a path or a variable name is refused by validate (so it never reaches the
    // approval text), and the CLI's display_name drops it; fails_when=any of them validates;
    // no_claim=homoglyphs (T-07)
    #[test]
    fn invisible_and_bidi_characters_refused() {
        let mut r = sample();
        r.root = "/Users/me/code/\u{202e}pohs".into();
        assert!(r.validate().is_err());
        let mut r = sample();
        r.display = "shop\u{202e}gnp.exe".into();
        assert!(r.validate().is_err());
        let mut r = sample();
        r.files[0].path = ".env\u{200b}".into();
        assert!(r.validate().is_err());
        let mut r = sample();
        r.files[0].secrets[0].var = "A\u{2066}B".into();
        assert!(r.validate().is_err());
        assert_eq!(display_name("sh\u{202e}op\u{200b}", "x"), "shop");
        let mut r = sample();
        r.display = display_name("sh\u{202e}op", "x");
        r.validate().unwrap();
    }

    // protects=design §5.2 limits and shapes: keys outside the slug, paths that leave the root,
    // a non-canonical root, a masked form with room for a value, too many secrets are refused;
    // fails_when=any is accepted; no_claim=that the root exists (msd checks)
    #[test]
    fn record_validation() {
        let ok = sample();
        ok.validate().unwrap();
        let mut cases: Vec<ProjectRecord> = Vec::new();
        let mut r = sample();
        r.files[0].secrets[0].key = KeyName::new("other/k").unwrap();
        cases.push(r);
        for p in ["../.env", "/etc/x", "a/../b", "a//b", "./a", ""] {
            let mut r = sample();
            r.files[0].path = p.into();
            cases.push(r);
        }
        for root in ["relative", "/", "/a/../b", "/a/"] {
            let mut r = sample();
            r.root = root.into();
            cases.push(r);
        }
        let mut r = sample();
        r.findings[0].masked = concat!(
            "sk_live_",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef (99 bytes)"
        )
        .into();
        cases.push(r);
        let mut r = sample();
        r.slug = "Shop".into();
        cases.push(r);
        let mut r = sample();
        let s = r.files[0].secrets[0].clone();
        r.files[0].secrets = vec![s; MAX_SECRETS + 1];
        cases.push(r);
        for (i, c) in cases.iter().enumerate() {
            assert!(c.validate().is_err(), "case {i} accepted: {c:?}");
        }
    }
}
