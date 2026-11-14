//! Project rules (`<repo>/.morsec.toml`) and the tighten-only merge.
//!
//! The agent can write this file, so it must never widen anything: every field can only narrow
//! the user's rule, a key the user rules lack is ignored, and a file that fails to parse disables
//! every key (fail closed).

use std::collections::BTreeMap;

use ms_core::{KeyName, Mode, Tier};
use serde::Deserialize;

use crate::error::{Result, RulesError};
use crate::model::{KeyRule, MAX_KEYS, MAX_SESSION_TTL_SECS, Rules, validate_scope};
use crate::pattern::{CommandPattern, HostPattern, intersect_sets};

/// File name of project rules at a repository root.
pub const PROJECT_FILE: &str = ".morsec.toml";
/// Largest project file read, bytes.
pub const MAX_PROJECT_FILE: usize = 64 * 1024;

/// Restrictions on one key. Absent fields restrict nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyLimit {
    /// The key must have this mode, or it is disabled.
    pub mode: Option<Mode>,
    /// Raise the tier to at least this.
    pub tier: Option<Tier>,
    /// Intersect hosts with these.
    pub hosts: Option<Vec<HostPattern>>,
    /// Intersect commands with these.
    pub commands: Option<Vec<CommandPattern>>,
    /// Intersect mint scopes with these.
    pub mint_scopes: Option<Vec<String>>,
    /// Lower the session TTL to at most this.
    pub session_ttl_secs: Option<u64>,
    /// Force read-only when true (false restricts nothing).
    pub read_only: bool,
    /// Disable the key in this project.
    pub disabled: bool,
}

/// A parsed project file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectRules {
    /// Per-key restrictions.
    pub keys: BTreeMap<KeyName, KeyLimit>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFile {
    #[serde(default)]
    keys: BTreeMap<KeyName, KeyLimitFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLimitFile {
    mode: Option<Mode>,
    tier: Option<Tier>,
    hosts: Option<Vec<String>>,
    commands: Option<Vec<Vec<String>>>,
    mint_scopes: Option<Vec<String>>,
    session_ttl_secs: Option<u64>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    disabled: bool,
}

impl ProjectRules {
    /// Parses a project file. `file` names it in errors.
    pub fn from_toml(text: &str, file: &str) -> Result<Self> {
        if text.len() > MAX_PROJECT_FILE {
            return Err(RulesError::invalid(
                file,
                format!("larger than {MAX_PROJECT_FILE} bytes"),
            ));
        }
        let raw: ProjectFile =
            toml::from_str(text).map_err(|e| RulesError::invalid(file, e.to_string()))?;
        if raw.keys.len() > MAX_KEYS {
            return Err(RulesError::invalid(
                file,
                format!("more than {MAX_KEYS} keys"),
            ));
        }
        let mut keys = BTreeMap::new();
        for (name, l) in raw.keys {
            let bad = |why: String| RulesError::invalid(file, format!("key {name}: {why}"));
            if let Some(ttl) = l.session_ttl_secs
                && !(1..=MAX_SESSION_TTL_SECS).contains(&ttl)
            {
                return Err(bad(format!(
                    "session_ttl_secs must be 1 to {MAX_SESSION_TTL_SECS}"
                )));
            }
            if let Some(scopes) = &l.mint_scopes {
                for s in scopes {
                    validate_scope(s).map_err(&bad)?;
                }
            }
            let limit = KeyLimit {
                mode: l.mode,
                tier: l.tier,
                hosts: l
                    .hosts
                    .map(|h| crate::model::parse_hosts(&h, file, &name))
                    .transpose()?,
                commands: l
                    .commands
                    .map(|c| crate::model::parse_commands(&c, file, &name))
                    .transpose()?,
                mint_scopes: l.mint_scopes,
                session_ttl_secs: l.session_ttl_secs,
                read_only: l.read_only,
                disabled: l.disabled,
            };
            keys.insert(name, limit);
        }
        Ok(Self { keys })
    }
}

fn disable(rule: &mut KeyRule) {
    rule.roots.clear();
    rule.env.clear();
    rule.ssh_host_keys.clear();
    rule.hosts.clear();
    rule.commands.clear();
    rule.mint_scopes.clear();
    rule.git_hosts.clear();
}

/// Applies project restrictions to the user rules. Never widens: a request the result allows,
/// the user rules allow too, and a request the user rules send to approval is never allowed
/// outright. Notes for `ms rules` are added to `notes`.
pub fn merge(user: &Rules, project: &ProjectRules) -> Rules {
    let mut out = user.clone();
    for (name, limit) in &project.keys {
        let Some(rule) = out.keys.get_mut(name) else {
            out.notes.push(format!(
                "project rule for {name} ignored: no such key in your rules (projects can't add keys)"
            ));
            continue;
        };
        if limit.disabled {
            disable(rule);
            out.notes
                .push(format!("{name} is disabled by the project file"));
            continue;
        }
        if let Some(mode) = limit.mode
            && mode != rule.mode
        {
            disable(rule);
            out.notes.push(format!(
                "{name} is disabled: the project file expects another mode"
            ));
            continue;
        }
        if let Some(tier) = limit.tier {
            rule.tier = rule.tier.max(tier);
        }
        if let Some(h) = &limit.hosts {
            rule.hosts = intersect_sets(&rule.hosts, h, HostPattern::intersect);
            let hosts = &rule.hosts;
            rule.git_hosts.retain(|g| {
                hosts
                    .iter()
                    .any(|p| matches!(p, HostPattern::Exact(e) if e == g))
            });
        }
        if let Some(c) = &limit.commands {
            rule.commands = intersect_sets(&rule.commands, c, CommandPattern::intersect);
        }
        if let Some(s) = &limit.mint_scopes {
            rule.mint_scopes.retain(|x| s.contains(x));
        }
        if let Some(ttl) = limit.session_ttl_secs {
            rule.session_ttl_secs = rule.session_ttl_secs.min(ttl);
        }
        rule.read_only |= limit.read_only;
    }
    out
}

/// The effective rules for a project: `user` merged with the project file text, if any. A file
/// that fails to parse disables every key (fail closed) and the error is returned alongside.
pub fn effective(
    user: &Rules,
    project_text: Option<&str>,
    file: &str,
) -> (Rules, Option<RulesError>) {
    let Some(text) = project_text else {
        return (user.clone(), None);
    };
    match ProjectRules::from_toml(text, file) {
        Ok(p) => (merge(user, &p), None),
        Err(e) => (disable_all(user, file), Some(e)),
    }
}

/// `user` with every key disabled, for a project file that is invalid or unreadable.
pub fn disable_all(user: &Rules, file: &str) -> Rules {
    let mut out = user.clone();
    out.keys.values_mut().for_each(disable);
    out.notes.push(format!(
        "every key is disabled in this project because {file} is not valid"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KeyRule;
    use crate::pattern::tests_support::*;
    use crate::policy::{decide, decide_run, permissiveness};
    use ms_core::{AgentKind, Request, SessionId};
    use proptest::prelude::*;
    use std::path::Path;

    fn k(s: &str) -> KeyName {
        KeyName::new(s).unwrap()
    }
    fn session() -> SessionId {
        SessionId {
            agent: AgentKind::Codex,
            pid: 9,
            started_unix_ms: 1,
        }
    }

    const USER: &str = r#"
version = 5
[keys."pg/staging"]
mode = "run"
tier = "test"
commands = [["psql", "**"], ["pg_dump", "*"]]
session_ttl_secs = 3600

[keys."stripe/test"]
mode = "swap"
tier = "test"
hosts = ["*.stripe.com"]
"#;

    // protects=a typical project file tightens as documented; fails_when=hosts/commands are not
    // intersected, TTL not minimised, tier not maximised, read_only lost, or a new key is created;
    // no_claim=the property over all inputs (below)
    #[test]
    fn tightens_as_documented() {
        let user = Rules::from_toml(USER, "rules.toml").unwrap();
        let project = ProjectRules::from_toml(
            r#"
[keys."pg/staging"]
commands = [["psql", "-c", "*"], ["rm", "-rf", "/"]]
session_ttl_secs = 600
tier = "production"
read_only = true

[keys."stripe/test"]
hosts = ["api.stripe.com", "evil.net", "*.example.com"]

[keys."new/key"]
mode = "swap"
hosts = ["*.com"]
"#,
            ".morsec.toml",
        )
        .unwrap();
        let m = merge(&user, &project);
        assert_eq!(m.version, 5);
        let pg = &m.keys[&k("pg/staging")];
        assert_eq!(
            pg.commands,
            vec![CommandPattern::parse(&["psql".into(), "-c".into(), "*".into()]).unwrap()]
        );
        assert_eq!(pg.session_ttl_secs, 600);
        assert_eq!(pg.tier, Tier::Production);
        assert!(pg.read_only);
        let st = &m.keys[&k("stripe/test")];
        assert_eq!(
            st.hosts,
            vec![HostPattern::parse("api.stripe.com").unwrap()]
        );
        assert!(!m.keys.contains_key(&k("new/key")));
        assert!(m.notes.iter().any(|n| n.contains("new/key")));

        // A project can't lower a tier or raise a TTL.
        let loose = ProjectRules::from_toml(
            "[keys.\"pg/staging\"]\ntier = \"test\"\nsession_ttl_secs = 86400\nread_only = false",
            ".morsec.toml",
        )
        .unwrap();
        let mut prod = user.clone();
        let r = prod.keys.get_mut(&k("pg/staging")).unwrap();
        r.tier = Tier::Production;
        r.session_ttl_secs = 60;
        r.read_only = true;
        let m = merge(&prod, &loose);
        let r = &m.keys[&k("pg/staging")];
        assert_eq!(
            (r.tier, r.session_ttl_secs, r.read_only),
            (Tier::Production, 60, true)
        );
    }

    // protects=disabled, mode mismatch and an unparsable project file all disable keys (fail
    // closed); fails_when=such a key still allows anything; no_claim=locating the file (CLI)
    // protects=L16 SPEC D2 (review R7): a project file can't pin SSH host keys; one that tries
    // fails to parse, which disables every key, pins included; fails_when=a project file adds
    // a pin or a disabled key keeps one; no_claim=-
    #[test]
    fn projects_cant_pin_ssh_hosts() {
        let pin = "AAAAC3NzaC1lZDI1NTE5AAAAIPtd2fa6erUsRui9x7T64boFCGFRwuEig/mwpm4LdTO7";
        let text = format!("[keys.\"k\"]\nssh_host_keys = [\"evil.example ssh-ed25519 {pin}\"]\n");
        assert!(ProjectRules::from_toml(&text, ".morsec.toml").is_err());
        let mut rule = KeyRule::new(Mode::Run, Tier::Test);
        rule.commands = vec![CommandPattern::parse(&["git".into(), "push".into()]).unwrap()];
        rule.ssh_host_keys = vec![
            crate::model::SshHostKey::parse(&format!("git.example ssh-ed25519 {pin}")).unwrap(),
        ];
        let user = Rules {
            version: 1,
            keys: BTreeMap::from([(k("k"), rule)]),
            ..Rules::default()
        };
        let (eff, err) = effective(&user, Some(&text), ".morsec.toml");
        assert!(err.is_some());
        assert!(eff.keys[&k("k")].ssh_host_keys.is_empty());
    }

    #[test]
    fn disables_fail_closed() {
        let user = Rules::from_toml(USER, "rules.toml").unwrap();
        let swap = Request::Swap {
            key: k("stripe/test"),
            host: "api.stripe.com".into(),
        };
        for text in [
            "[keys.\"stripe/test\"]\ndisabled = true",
            "[keys.\"stripe/test\"]\nmode = \"run\"",
        ] {
            let (m, err) = effective(&user, Some(text), ".morsec.toml");
            assert!(err.is_none());
            assert!(m.keys[&k("stripe/test")].allows_nothing(), "{text}");
            assert_eq!(permissiveness(&decide(&m, &session(), &swap)), 0);
        }
        for broken in [
            "not toml [",
            "[keys.\"stripe/test\"]\nhosts = \"api.stripe.com\"",
            "[keys.\"stripe/test\"]\nhost = [\"a.com\"]",
            "[keys.\"stripe/test\"]\nsession_ttl_secs = 0",
            "[keys.\"Stripe\"]\ndisabled = true",
            "extra = 1",
        ] {
            let (m, err) = effective(&user, Some(broken), ".morsec.toml");
            assert!(err.is_some(), "{broken}");
            assert!(m.keys.values().all(KeyRule::allows_nothing), "{broken}");
        }
        let big = "#".repeat(MAX_PROJECT_FILE + 1);
        assert!(effective(&user, Some(&big), ".morsec.toml").1.is_some());
        let (m, err) = effective(&user, None, ".morsec.toml");
        assert!(err.is_none());
        assert_eq!(m, user);
    }

    // protects=L30 D1 a project can't add git hosts, narrowing hosts drops them and disabling
    // clears them; fails_when=a project file with git_hosts parses, or a git host survives without
    // its host; no_claim=the proxy bindings (msd)
    #[test]
    fn projects_cant_widen_git_hosts() {
        let user = Rules::from_toml(
            "version = 1\n[keys.\"gh/t\"]\nmode = \"swap\"\ntier = \"test\"\nhosts = [\"api.github.com\", \"github.com\", \"git.example.com\"]\ngit_hosts = [\"github.com\", \"git.example.com\"]",
            "rules.toml",
        )
        .unwrap();
        let (m, err) = effective(
            &user,
            Some("[keys.\"gh/t\"]\ngit_hosts = [\"evil.net\"]"),
            ".morsec.toml",
        );
        assert!(err.is_some());
        assert!(
            m.keys
                .values()
                .all(|r| r.allows_nothing() && r.git_hosts.is_empty())
        );
        let (m, err) = effective(
            &user,
            Some("[keys.\"gh/t\"]\nhosts = [\"api.github.com\", \"*.example.com\"]"),
            ".morsec.toml",
        );
        assert!(err.is_none());
        let r = &m.keys[&k("gh/t")];
        assert_eq!(r.git_hosts, ["git.example.com"]);
        let (m, _) = effective(
            &user,
            Some("[keys.\"gh/t\"]\ndisabled = true"),
            ".morsec.toml",
        );
        assert!(m.keys[&k("gh/t")].git_hosts.is_empty());
    }

    fn arb_mode() -> impl Strategy<Value = Mode> {
        prop::sample::select(vec![Mode::Swap, Mode::Run, Mode::Mint])
    }
    fn arb_tier() -> impl Strategy<Value = Tier> {
        prop::sample::select(vec![Tier::Test, Tier::Production])
    }
    fn arb_scope() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["read", "write", "admin"]).prop_map(String::from)
    }

    fn arb_user_rule() -> impl Strategy<Value = KeyRule> {
        (
            arb_mode(),
            arb_tier(),
            prop::collection::vec(host_pattern_strings(), 0..4),
            prop::collection::vec(pattern_strings(), 0..4),
            prop::collection::vec(arb_scope(), 0..3),
            1u64..10_000,
            any::<bool>(),
        )
            .prop_map(|(mode, tier, hosts, cmds, scopes, ttl, ro)| KeyRule {
                mode,
                tier,
                hosts: hosts
                    .iter()
                    .map(|h| HostPattern::parse(h).unwrap())
                    .collect(),
                commands: if mode == Mode::Run {
                    cmds.iter()
                        .map(|c| CommandPattern::parse(c).unwrap())
                        .collect()
                } else {
                    vec![]
                },
                mint_scopes: if mode == Mode::Mint { scopes } else { vec![] },
                session_ttl_secs: ttl,
                read_only: ro,
                git_hosts: vec![],
                roots: if mode == Mode::Run {
                    vec!["/r/app".into()]
                } else {
                    vec![]
                },
                env: if mode == Mode::Run {
                    vec!["TOKEN".into()]
                } else {
                    vec![]
                },
                ssh_host_keys: vec![],
            })
    }

    fn arb_limit() -> impl Strategy<Value = KeyLimit> {
        (
            prop::option::of(arb_mode()),
            prop::option::of(arb_tier()),
            prop::option::of(prop::collection::vec(host_pattern_strings(), 0..4)),
            prop::option::of(prop::collection::vec(pattern_strings(), 0..4)),
            prop::option::of(prop::collection::vec(arb_scope(), 0..3)),
            prop::option::of(1u64..20_000),
            any::<bool>(),
            prop::bool::weighted(0.1),
        )
            .prop_map(|(mode, tier, hosts, cmds, scopes, ttl, ro, dis)| KeyLimit {
                mode,
                tier,
                hosts: hosts.map(|v| v.iter().map(|h| HostPattern::parse(h).unwrap()).collect()),
                commands: cmds.map(|v| {
                    v.iter()
                        .map(|c| CommandPattern::parse(c).unwrap())
                        .collect()
                }),
                mint_scopes: scopes,
                session_ttl_secs: ttl,
                read_only: ro,
                disabled: dis,
            })
    }

    fn arb_request(key: KeyName) -> impl Strategy<Value = (Request, Vec<String>)> {
        prop_oneof![
            probe_host().prop_map({
                let key = key.clone();
                move |h| {
                    (
                        Request::Swap {
                            key: key.clone(),
                            host: h,
                        },
                        vec![],
                    )
                }
            }),
            probe_argv().prop_map({
                let key = key.clone();
                move |a| {
                    (
                        Request::Run {
                            key: key.clone(),
                            argv_hash: crate::policy::argv_hash(&a),
                            cwd: "/r".into(),
                        },
                        a,
                    )
                }
            }),
            arb_scope().prop_map(move |s| (
                Request::Mint {
                    key: key.clone(),
                    scope: s
                },
                vec![]
            )),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]
        // protects=a project file can never widen the effective rule: for every user rule,
        // project restriction and request (all modes, both decide and decide_run), the merged
        // decision is never more permissive, the TTL never grows, the tier never drops and
        // read_only is never cleared; fails_when=any merged decision is looser;
        // no_claim=inputs outside the generators' alphabets (the pattern intersection proptests
        // show exactness separately)
        #[test]
        fn project_never_widens(
            user_rule in arb_user_rule(),
            limit in arb_limit(),
            target_other in prop::bool::weighted(0.1),
            (req, argv) in arb_request(KeyName::new("k").unwrap()),
        ) {
            let user = Rules {
                version: 1,
                keys: BTreeMap::from([(k("k"), user_rule.clone())]),
                ..Rules::default()
            };
            let name = if target_other { k("other") } else { k("k") };
            let project = ProjectRules { keys: BTreeMap::from([(name, limit)]) };
            let merged = merge(&user, &project);
            let s = session();
            // What the user rules allow, judged on the full request: for run requests that is
            // decide_run on the argv (decide only sees a hash and so only matches literal
            // patterns; a merge can narrow `["psql", "*"]` to the literal `["psql", "a"]`, which
            // decide then matches, but the user rule already allowed that argv).
            let user_view = match req {
                Request::Run { .. } => decide_run(&user, &s, &k("k"), &argv, Path::new("/r")),
                _ => decide(&user, &s, &req),
            };
            let after = decide(&merged, &s, &req);
            prop_assert!(permissiveness(&after) <= permissiveness(&user_view), "{:?} -> {:?}", user_view, after);
            if let Request::Run { .. } = req {
                let after = decide_run(&merged, &s, &k("k"), &argv, Path::new("/r"));
                prop_assert!(permissiveness(&after) <= permissiveness(&user_view));
                // The hash-only path is never looser than the full-argv path on the same rules.
                prop_assert!(permissiveness(&decide(&user, &s, &req)) <= permissiveness(&user_view));
            }
            let m = &merged.keys[&k("k")];
            prop_assert!(m.session_ttl_secs <= user_rule.session_ttl_secs);
            prop_assert!(m.tier >= user_rule.tier);
            prop_assert!(m.read_only || !user_rule.read_only);
            prop_assert_eq!(m.mode, user_rule.mode);
            prop_assert_eq!(merged.keys.len(), 1);
        }
    }
}
