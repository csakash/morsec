//! The policy decision function. Pure: no I/O, no clock, no vault.

use std::path::{Path, PathBuf};

use ms_core::{ApprovalRequest, Decision, KeyName, Mode, Reason, Request, SessionId, Tier};
use sha2::{Digest, Sha256};

use crate::model::{KeyRule, Rules};
use crate::pattern::NormalHost;

const ARGV_HASH_DOMAIN: &[u8] = b"morsec-argv-v1\0";

/// SHA-256 over an argv in the one canonical encoding every loop uses (`ApprovalRequest`,
/// approval tokens, receipts): a domain label, then for each argument its byte length as a
/// big-endian u64 followed by its bytes. Length prefixes make it unambiguous:
/// `["a b"]` and `["a", "b"]` hash differently.
pub fn argv_hash<S: AsRef<str>>(argv: &[S]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ARGV_HASH_DOMAIN);
    for a in argv {
        let a = a.as_ref().as_bytes();
        h.update((a.len() as u64).to_be_bytes());
        h.update(a);
    }
    h.finalize().into()
}

/// Decides a request. Deny by default.
///
/// Order: tampered rules, `ms stop`, unknown key, wrong mechanism, target not allowed, then the
/// tier (test allows, production needs an approval).
///
/// The frozen `Request::Run` carries only the argv hash, so this matches a run request only
/// against wildcard-free command patterns. Callers that have the argv use [`decide_run`].
pub fn decide(rules: &Rules, session: &SessionId, request: &Request) -> Decision {
    match request {
        Request::Swap { key, host } => {
            let rule = match lookup(rules, key, Mode::Swap, Reason::HostNotAllowed) {
                Ok(r) => r,
                Err(reason) => return deny(reason),
            };
            let allowed =
                NormalHost::parse(host).is_some_and(|h| rule.hosts.iter().any(|p| p.matches(&h)));
            if !allowed {
                return deny(Reason::HostNotAllowed);
            }
            let display = vec!["swap".to_owned(), host.clone()];
            by_tier(rule, session, key, display, PathBuf::new())
        }
        Request::Run {
            key,
            argv_hash: hash,
            cwd,
        } => {
            let rule = match lookup(rules, key, Mode::Run, Reason::CommandNotAllowed) {
                Ok(r) => r,
                Err(reason) => return deny(reason),
            };
            let literal = rule
                .commands
                .iter()
                .filter_map(|c| c.literal())
                .find(|argv| argv_hash(argv) == *hash);
            match literal {
                Some(argv) => by_tier(rule, session, key, argv, cwd.clone()),
                None => deny(Reason::CommandNotAllowed),
            }
        }
        Request::Mint { key, scope } => {
            let rule = match lookup(rules, key, Mode::Mint, Reason::CommandNotAllowed) {
                Ok(r) => r,
                Err(reason) => return deny(reason),
            };
            if !rule.mint_scopes.iter().any(|s| s == scope) {
                return deny(Reason::CommandNotAllowed);
            }
            let display = vec!["mint".to_owned(), scope.clone()];
            by_tier(rule, session, key, display, PathBuf::new())
        }
    }
}

/// Decides a run request when the caller has the exact argv: full pattern matching, and an
/// `ApprovalRequest` bound to `argv_hash(argv)` that shows the real arguments.
pub fn decide_run(
    rules: &Rules,
    session: &SessionId,
    key: &KeyName,
    argv: &[String],
    cwd: &Path,
) -> Decision {
    let rule = match lookup(rules, key, Mode::Run, Reason::CommandNotAllowed) {
        Ok(r) => r,
        Err(reason) => return deny(reason),
    };
    if argv.is_empty() || !rule.commands.iter().any(|c| c.matches(argv)) {
        return deny(Reason::CommandNotAllowed);
    }
    by_tier(rule, session, key, argv.to_vec(), cwd.to_path_buf())
}

fn deny(reason: Reason) -> Decision {
    Decision::Deny { reason }
}

fn lookup<'r>(
    rules: &'r Rules,
    key: &KeyName,
    mode: Mode,
    wrong_mode: Reason,
) -> Result<&'r KeyRule, Reason> {
    if rules.tampered {
        return Err(Reason::RulesTampered);
    }
    if rules.stopped {
        return Err(Reason::Stopped);
    }
    let rule = rules.keys.get(key).ok_or(Reason::NoSuchKey)?;
    if rule.mode != mode {
        return Err(wrong_mode);
    }
    Ok(rule)
}

fn by_tier(
    rule: &KeyRule,
    session: &SessionId,
    key: &KeyName,
    argv_display: Vec<String>,
    cwd: PathBuf,
) -> Decision {
    match rule.tier {
        Tier::Test => Decision::Allow,
        Tier::Production => Decision::NeedsApproval {
            request: ApprovalRequest {
                session: session.clone(),
                key: key.clone(),
                tier: rule.tier,
                argv_hash: argv_hash(&argv_display),
                argv_display,
                cwd,
                effect: None,
            },
        },
    }
}

/// How permissive a decision is: Deny < NeedsApproval < Allow.
pub fn permissiveness(d: &Decision) -> u8 {
    match d {
        Decision::Deny { .. } => 0,
        Decision::NeedsApproval { .. } => 1,
        Decision::Allow => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{CommandPattern, HostPattern};
    use ms_core::AgentKind;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn session() -> SessionId {
        SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
            started_unix_ms: 7,
        }
    }
    fn k(s: &str) -> KeyName {
        KeyName::new(s).unwrap()
    }
    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn rule(mode: Mode, tier: Tier) -> KeyRule {
        let mut r = KeyRule::new(mode, tier);
        match mode {
            Mode::Swap => r.hosts = vec![HostPattern::parse("api.stripe.com").unwrap()],
            Mode::Run => {
                r.commands = vec![
                    CommandPattern::parse(&strs(&["psql", "-c", "select 1"])).unwrap(),
                    CommandPattern::parse(&strs(&["psql", "-c", "*"])).unwrap(),
                ]
            }
            Mode::Mint => r.mint_scopes = vec!["s3:read".into()],
        }
        r
    }

    fn rules_with(name: &str, r: KeyRule) -> Rules {
        Rules {
            version: 1,
            keys: BTreeMap::from([(k(name), r)]),
            ..Rules::default()
        }
    }

    /// (allowed request, not-allowed request) for a key in `mode`.
    fn requests(mode: Mode, key: &KeyName) -> (Request, Request) {
        match mode {
            Mode::Swap => (
                Request::Swap {
                    key: key.clone(),
                    host: "API.stripe.com.".into(),
                },
                Request::Swap {
                    key: key.clone(),
                    host: "paste.example.net".into(),
                },
            ),
            Mode::Run => (
                Request::Run {
                    key: key.clone(),
                    argv_hash: argv_hash(&["psql", "-c", "select 1"]),
                    cwd: "/repo".into(),
                },
                Request::Run {
                    key: key.clone(),
                    argv_hash: argv_hash(&["psql", "-c", "drop table x"]),
                    cwd: "/repo".into(),
                },
            ),
            Mode::Mint => (
                Request::Mint {
                    key: key.clone(),
                    scope: "s3:read".into(),
                },
                Request::Mint {
                    key: key.clone(),
                    scope: "s3:*".into(),
                },
            ),
        }
    }

    fn not_allowed_reason(mode: Mode) -> Reason {
        match mode {
            Mode::Swap => Reason::HostNotAllowed,
            Mode::Run | Mode::Mint => Reason::CommandNotAllowed,
        }
    }

    const MODES: [Mode; 3] = [Mode::Swap, Mode::Run, Mode::Mint];
    const TIERS: [Tier; 2] = [Tier::Test, Tier::Production];

    // protects=the decision table for every mode x tier x (allowed, not allowed, wrong mechanism),
    // plus stopped, tampered and unknown key; fails_when=any cell differs from the SPEC table;
    // no_claim=what the daemon does with the decision
    #[test]
    fn decision_table() {
        let s = session();
        let key = k("the/key");
        for mode in MODES {
            for tier in TIERS {
                let rules = rules_with("the/key", rule(mode, tier));
                let (ok, bad) = requests(mode, &key);
                let got = decide(&rules, &s, &ok);
                match tier {
                    Tier::Test => assert_eq!(got, Decision::Allow, "{mode:?} {tier:?}"),
                    Tier::Production => {
                        let Decision::NeedsApproval { request } = got else {
                            panic!("{mode:?} production gave {got:?}")
                        };
                        assert_eq!(request.session, s);
                        assert_eq!(request.key, key);
                        assert_eq!(request.tier, Tier::Production);
                        assert_eq!(request.argv_hash, argv_hash(&request.argv_display));
                    }
                }
                assert_eq!(
                    decide(&rules, &s, &bad),
                    deny(not_allowed_reason(mode)),
                    "{mode:?} {tier:?} not-allowed"
                );
                // A request for another mechanism on this key is denied.
                for other in MODES.into_iter().filter(|m| *m != mode) {
                    let (req, _) = requests(other, &key);
                    assert_eq!(
                        decide(&rules, &s, &req),
                        deny(not_allowed_reason(other)),
                        "{mode:?} key, {other:?} request"
                    );
                }
                // Unknown key, stopped, tampered.
                let (other_key_req, _) = requests(mode, &k("nope"));
                assert_eq!(decide(&rules, &s, &other_key_req), deny(Reason::NoSuchKey));
                let mut stopped = rules.clone();
                stopped.stopped = true;
                assert_eq!(decide(&stopped, &s, &ok), deny(Reason::Stopped));
                let mut tampered = rules.clone();
                tampered.tampered = true;
                tampered.stopped = true;
                assert_eq!(decide(&tampered, &s, &ok), deny(Reason::RulesTampered));
                assert_eq!(
                    decide(&Rules::tampered(), &s, &ok),
                    deny(Reason::RulesTampered)
                );
                assert_eq!(decide(&Rules::default(), &s, &ok), deny(Reason::NoSuchKey));
            }
        }
    }

    // protects=hosts with ports, userinfo, paths or look-alike suffixes never match a swap rule;
    // fails_when=any is allowed; no_claim=DNS resolution and SSRF checks (L05)
    #[test]
    fn swap_host_edge_cases() {
        let rules = rules_with("s", rule(Mode::Swap, Tier::Test));
        for host in [
            "api.stripe.com:443",
            "user@api.stripe.com",
            "api.stripe.com/v1",
            "api.stripe.com.evil.net",
            "evilapi.stripe.com",
            "",
            "api.stripe.com..",
        ] {
            let r = Request::Swap {
                key: k("s"),
                host: host.into(),
            };
            assert_eq!(
                decide(&rules, &session(), &r),
                deny(Reason::HostNotAllowed),
                "{host:?}"
            );
        }
    }

    // protects=decide_run matches wildcard patterns and binds the approval to the exact argv;
    // fails_when=a changed argument keeps the same hash, the display differs from argv, or an
    // unlisted command passes; no_claim=the approver checking the token (L11)
    #[test]
    fn decide_run_binds_approval_to_argv() {
        let rules = rules_with("pg", rule(Mode::Run, Tier::Production));
        let argv = strs(&["psql", "-c", "delete from orders where id = 3"]);
        let d = decide_run(&rules, &session(), &k("pg"), &argv, Path::new("/repo"));
        let Decision::NeedsApproval { request } = d else {
            panic!("{d:?}")
        };
        assert_eq!(request.argv_display, argv);
        assert_eq!(request.argv_hash, argv_hash(&argv));
        assert_eq!(request.cwd, PathBuf::from("/repo"));
        let mut changed = argv.clone();
        changed[2].push(' ');
        assert_ne!(argv_hash(&changed), request.argv_hash);
        // The hash-only path can't match the wildcard pattern for this argv: denied, not allowed.
        let hashed = Request::Run {
            key: k("pg"),
            argv_hash: argv_hash(&argv),
            cwd: "/repo".into(),
        };
        assert_eq!(
            decide(&rules, &session(), &hashed),
            deny(Reason::CommandNotAllowed)
        );
        for bad in [
            vec![],
            strs(&["psql"]),
            strs(&["psql", "-c", "a", "b"]),
            strs(&["/usr/bin/psql", "-c", "a"]),
            strs(&["sh", "-c", "psql"]),
        ] {
            assert_eq!(
                decide_run(&rules, &session(), &k("pg"), &bad, Path::new("/")),
                deny(Reason::CommandNotAllowed),
                "{bad:?}"
            );
        }
    }

    // protects=argv_hash is unambiguous across argument boundaries and stable; fails_when=two
    // different argvs that concatenate alike collide, or the encoding changes silently;
    // no_claim=collision resistance beyond SHA-256
    #[test]
    fn argv_hash_is_unambiguous_and_pinned() {
        assert_ne!(argv_hash(&["a b"]), argv_hash(&["a", "b"]));
        assert_ne!(argv_hash(&["ab", ""]), argv_hash(&["a", "b"]));
        assert_ne!(argv_hash::<&str>(&[]), argv_hash(&[""]));
        // Pinned so a change to the encoding (which would void every issued approval) is
        // deliberate.
        assert_eq!(
            hex::encode(argv_hash(&["psql", "-c", "select 1"])),
            "1119efc56811fc6451e14705348a585f933a037109bb6d5eed8510228209f8de"
        );
    }

    fn mode_strategy() -> impl Strategy<Value = Mode> {
        prop::sample::select(MODES.to_vec())
    }

    proptest! {
        // protects=a production key never yields Allow, and when its rule matches it always yields
        // NeedsApproval; fails_when=any production request is allowed outright;
        // no_claim=approval token checks (L11)
        #[test]
        fn production_always_needs_approval(mode in mode_strategy(), req_mode in mode_strategy(), ok in any::<bool>()) {
            let rules = rules_with("p", rule(mode, Tier::Production));
            let (good, bad) = requests(req_mode, &k("p"));
            let req = if ok { good } else { bad };
            let d = decide(&rules, &session(), &req);
            prop_assert_ne!(&d, &Decision::Allow);
            if ok && mode == req_mode {
                let is_approval = matches!(d, Decision::NeedsApproval { .. });
                prop_assert!(is_approval);
            }
        }
    }
}
