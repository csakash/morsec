//! The provider catalog (`catalog/providers.toml`), compiled into the binary.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use ms_core::{KeyName, Mode, Tier};
use serde::Deserialize;

/// The catalog source shipped with this build.
pub const BUILTIN: &str = include_str!("../../../catalog/providers.toml");

/// Where a provider's credential goes in a request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Location {
    /// A request header, `<prefix><value>`.
    Header {
        /// Header name.
        name: String,
        /// Text before the value, e.g. `Bearer `.
        #[serde(default)]
        prefix: String,
    },
    /// The user part of HTTP basic auth.
    BasicUser,
    /// The password part of HTTP basic auth.
    BasicPassword,
    /// The value is a URL whose path is the credential (webhooks).
    UrlPath,
    /// A database connection string (run mode).
    Dsn,
    /// AWS SigV4 signing.
    Sigv4,
}

/// A value prefix that identifies a provider.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefix {
    /// The prefix, case-sensitive.
    pub prefix: String,
    /// The tier a value with this prefix belongs to, when the prefix says.
    #[serde(default)]
    pub tier: Option<Tier>,
    /// Minimum length of the whole value.
    #[serde(default)]
    pub min_len: usize,
}

/// One provider.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    /// Id, a key-name segment.
    pub id: String,
    /// Display name.
    pub name: String,
    /// How morsec uses the key.
    pub mode: Mode,
    /// Hosts the key may go to.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Key-name template; `{tier}` is replaced. Defaults to `{id}/{tier}`.
    #[serde(default)]
    pub key: Option<String>,
    /// Where the credential goes.
    pub location: Location,
    /// Value prefixes.
    #[serde(default)]
    pub prefixes: Vec<Prefix>,
    /// URL schemes (lowercase, no `://`).
    #[serde(default)]
    pub url_schemes: Vec<String>,
    /// https URL hosts.
    #[serde(default)]
    pub url_hosts: Vec<String>,
    /// Identifying variable names.
    #[serde(default)]
    pub env_names: Vec<String>,
}

impl Provider {
    /// The default key name for a value of this provider at `tier`.
    pub fn key_name(&self, tier: Tier) -> KeyName {
        let t = match tier {
            Tier::Test => "test",
            Tier::Production => "production",
        };
        let template = self.key.as_deref().unwrap_or("{id}/{tier}");
        let s = template.replace("{id}", &self.id).replace("{tier}", t);
        // Validated in Catalog::parse, so this cannot fail for a loaded catalog.
        KeyName::new(&s).unwrap_or_else(|_| unreachable!("catalog key template validated"))
    }

    /// True when `var` names this provider: equal to an `env_names` entry, or one with a
    /// `_`-separated prefix or suffix added (`AWS_PROD_SECRET_ACCESS_KEY` has neither, so it
    /// is matched by the infix rule too).
    pub fn matches_env_name(&self, var: &str) -> bool {
        let var = var.to_ascii_uppercase();
        self.env_names.iter().any(|n| {
            var == *n
                || var.ends_with(&format!("_{n}"))
                || var.starts_with(&format!("{n}_"))
                || infix_match(&var, n)
        })
    }
}

/// `AWS_PROD_SECRET_ACCESS_KEY` matches `AWS_SECRET_ACCESS_KEY`: the name with one extra
/// `_`-separated token inserted after its first token.
fn infix_match(var: &str, name: &str) -> bool {
    let Some((head, tail)) = name.split_once('_') else {
        return false;
    };
    let Some(rest) = var.strip_prefix(&format!("{head}_")) else {
        return false;
    };
    let Some((_extra, after)) = rest.split_once('_') else {
        return false;
    };
    after == tail
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    version: u32,
    #[serde(default)]
    public_prefixes: Vec<String>,
    #[serde(default)]
    public_name_prefixes: Vec<String>,
    provider: Vec<Provider>,
}

/// A validated catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// Providers, in file order.
    pub providers: Vec<Provider>,
    /// Public value prefixes (never imported).
    pub public_prefixes: Vec<String>,
    /// Public variable-name prefixes.
    pub public_name_prefixes: Vec<String>,
}

/// A catalog that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("provider catalog is invalid: {0}")]
pub struct CatalogError(pub String);

fn bad(msg: impl Into<String>) -> CatalogError {
    CatalogError(msg.into())
}

fn is_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl Catalog {
    /// The catalog compiled into this build.
    pub fn builtin() -> &'static Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| {
            // The builtin catalog is checked by a unit test, so this only fails on a broken build.
            Catalog::parse(BUILTIN).unwrap_or_else(|e| panic!("{e}"))
        })
    }

    /// Parses and validates a catalog.
    pub fn parse(src: &str) -> Result<Catalog, CatalogError> {
        let file: CatalogFile = toml::from_str(src).map_err(|e| bad(e.message().to_owned()))?;
        if file.version != 1 {
            return Err(bad(format!("unsupported version {}", file.version)));
        }
        let mut ids = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        let mut schemes = BTreeSet::new();
        let mut url_hosts = BTreeSet::new();
        for p in &file.provider {
            let who = format!("provider {:?}", p.id);
            if KeyName::new(&p.id).is_err() || p.id.contains('/') {
                return Err(bad(format!("{who}: id must be one key-name segment")));
            }
            if !ids.insert(p.id.clone()) {
                return Err(bad(format!("{who}: duplicate id")));
            }
            for tier in [Tier::Test, Tier::Production] {
                let t = if tier == Tier::Test {
                    "test"
                } else {
                    "production"
                };
                let s = p
                    .key
                    .as_deref()
                    .unwrap_or("{id}/{tier}")
                    .replace("{id}", &p.id)
                    .replace("{tier}", t);
                if KeyName::new(&s).is_err() {
                    return Err(bad(format!("{who}: key template gives invalid name {s:?}")));
                }
            }
            if matches!(p.mode, Mode::Swap | Mode::Mint) && p.hosts.is_empty() {
                return Err(bad(format!("{who}: a swap or mint provider needs hosts")));
            }
            if let Some(h) = p.hosts.iter().find(|h| !is_host(h)) {
                return Err(bad(format!("{who}: {h:?} is not a lowercase host name")));
            }
            if matches!(p.location, Location::Dsn) != (p.mode == Mode::Run) {
                return Err(bad(format!(
                    "{who}: location dsn goes with mode run, and only with it"
                )));
            }
            if p.prefixes.is_empty()
                && p.url_schemes.is_empty()
                && p.url_hosts.is_empty()
                && p.env_names.is_empty()
            {
                return Err(bad(format!("{who}: nothing identifies it")));
            }
            for pre in &p.prefixes {
                if pre.prefix.len() < 2 || pre.prefix.bytes().any(|b| !b.is_ascii_graphic()) {
                    return Err(bad(format!("{who}: prefix {:?} is too short", pre.prefix)));
                }
                if !prefixes.insert(pre.prefix.clone()) {
                    return Err(bad(format!("{who}: prefix {:?} used twice", pre.prefix)));
                }
                if file.public_prefixes.iter().any(|pp| pp == &pre.prefix) {
                    return Err(bad(format!("{who}: prefix {:?} is public", pre.prefix)));
                }
            }
            for s in &p.url_schemes {
                if s.is_empty()
                    || s.bytes()
                        .any(|b| !b.is_ascii_lowercase() && !b.is_ascii_digit())
                {
                    return Err(bad(format!("{who}: scheme {s:?} must be lowercase")));
                }
                if !schemes.insert(s.clone()) {
                    return Err(bad(format!("{who}: scheme {s:?} used twice")));
                }
            }
            for h in &p.url_hosts {
                if !is_host(h) || !url_hosts.insert(h.clone()) {
                    return Err(bad(format!("{who}: url host {h:?} invalid or used twice")));
                }
            }
            if let Some(n) = p.env_names.iter().find(|n| {
                n.is_empty()
                    || !n
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            }) {
                return Err(bad(format!("{who}: env name {n:?} must be UPPER_SNAKE")));
            }
        }
        Ok(Catalog {
            providers: file.provider,
            public_prefixes: file.public_prefixes,
            public_name_prefixes: file.public_name_prefixes,
        })
    }

    /// The provider with this id.
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// The longest catalog prefix `value` starts with (and is long enough for).
    pub fn match_prefix(&self, value: &[u8]) -> Option<(&Provider, &Prefix)> {
        self.providers
            .iter()
            .flat_map(|p| p.prefixes.iter().map(move |pre| (p, pre)))
            .filter(|(_, pre)| {
                value.starts_with(pre.prefix.as_bytes()) && value.len() >= pre.min_len
            })
            .max_by_key(|(_, pre)| pre.prefix.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=the shipped catalog loads, validates and covers every provider the L04 card
    // names; fails_when=the file is invalid or a provider is missing; no_claim=that every host
    // is complete for each provider's whole API surface
    #[test]
    fn builtin_is_valid_and_complete() {
        let c = Catalog::parse(BUILTIN).unwrap();
        for id in [
            "stripe",
            "openai",
            "anthropic",
            "github",
            "slack",
            "slack-webhook",
            "sendgrid",
            "twilio",
            "pg",
            "mysql",
            "aws-access-key-id",
            "aws-secret-access-key",
        ] {
            assert!(c.get(id).is_some(), "missing {id}");
        }
        assert_eq!(
            c.get("stripe").unwrap().key_name(Tier::Test).as_str(),
            "stripe/test"
        );
        assert_eq!(
            c.get("aws-secret-access-key")
                .unwrap()
                .key_name(Tier::Production)
                .as_str(),
            "aws/production/secret-access-key"
        );
    }

    // protects=longest prefix wins and min_len is enforced; fails_when=sk-ant- is classed as
    // OpenAI or a short sk- string matches; no_claim=classification of names (classify tests)
    #[test]
    fn longest_prefix() {
        let c = Catalog::builtin();
        let ant = format!("sk-ant-api03-{}", "a".repeat(40));
        assert_eq!(c.match_prefix(ant.as_bytes()).unwrap().0.id, "anthropic");
        let oai = format!("sk-proj-{}", "a".repeat(40));
        assert_eq!(c.match_prefix(oai.as_bytes()).unwrap().0.id, "openai");
        assert!(c.match_prefix(b"sk-short").is_none());
    }

    // protects=the validator rejects each class of broken catalog; fails_when=one is accepted;
    // no_claim=every possible malformed TOML
    #[test]
    fn validator_rejects() {
        let ok = r#"
version = 1
[[provider]]
id = "x"
name = "X"
mode = "swap"
hosts = ["api.x.com"]
location = { kind = "header", name = "Authorization", prefix = "Bearer " }
prefixes = [{ prefix = "xk_" }]
"#;
        Catalog::parse(ok).unwrap();
        let cases = [
            ok.replace("version = 1", "version = 2"),
            ok.replace("id = \"x\"", "id = \"X\""),
            ok.replace("id = \"x\"", "id = \"a/b\""),
            ok.replace("hosts = [\"api.x.com\"]", "hosts = []"),
            ok.replace("api.x.com", "https://api.x.com"),
            ok.replace("api.x.com", "API.x.com"),
            ok.replace("mode = \"swap\"", "mode = \"run\""),
            ok.replace("xk_", "x"),
            ok.replace("prefixes = [{ prefix = \"xk_\" }]", ""),
            ok.replace("name = \"X\"", "name = \"X\"\nkey = \"{id}/UPPER\""),
            ok.replace("name = \"X\"", "name = \"X\"\nbogus = 1"),
            format!("{ok}\n{}", ok.replace("version = 1", "")),
            format!(
                "{ok}\n{}",
                ok.replace("version = 1", "")
                    .replace("id = \"x\"", "id = \"y\"")
            ),
            ok.replace("version = 1", "version = 1\npublic_prefixes = [\"xk_\"]"),
            ok.replace(
                "prefixes = [{ prefix = \"xk_\" }]",
                "env_names = [\"lower\"]",
            ),
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(Catalog::parse(c).is_err(), "case {i} accepted:\n{c}");
        }
    }

    // protects=env-name matching accepts the documented decorations only; fails_when=an
    // unrelated name matches; no_claim=names outside the catalog
    #[test]
    fn env_names() {
        let c = Catalog::builtin();
        let aws = c.get("aws-secret-access-key").unwrap();
        for yes in [
            "AWS_SECRET_ACCESS_KEY",
            "PROD_AWS_SECRET_ACCESS_KEY",
            "AWS_SECRET_ACCESS_KEY_PROD",
            "AWS_PROD_SECRET_ACCESS_KEY",
            "aws_secret_access_key",
        ] {
            assert!(aws.matches_env_name(yes), "{yes}");
        }
        for no in [
            "AWS_SECRET",
            "MY_AWS_SECRET_ACCESS_KEYS",
            "AWS_A_B_SECRET_ACCESS_KEY",
        ] {
            assert!(!aws.matches_env_name(no), "{no}");
        }
    }
}
