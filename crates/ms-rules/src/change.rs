//! Classifying a rules change as tightening or loosening.
//!
//! Loosening needs an approval (`RulesProposeLoosen`, Touch ID); tightening doesn't. When in doubt
//! the answer is `Loosen`: a pattern that is only covered by several old patterns together is
//! treated as new, which costs at most one unneeded prompt.

use ms_core::KeyName;

use crate::model::{KeyRule, Rules};
use crate::pattern::{CommandPattern, HostPattern};

/// How a change relates to the current rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// Nothing changed.
    Same,
    /// Allows nothing new.
    Tighten,
    /// Allows something new; needs an approval.
    Loosen,
}

/// Compares one key's rule. `old = None` means the key is new.
pub fn classify_rule(old: Option<&KeyRule>, new: Option<&KeyRule>) -> Change {
    match (old, new) {
        (None, None) => Change::Same,
        (Some(_), None) => Change::Tighten,
        (None, Some(n)) if n.allows_nothing() => Change::Tighten,
        (None, Some(_)) => Change::Loosen,
        (Some(o), Some(n)) if o == n => Change::Same,
        (Some(o), Some(n)) => {
            let narrower = o.mode == n.mode
                && n.tier >= o.tier
                && n.session_ttl_secs <= o.session_ttl_secs
                && (n.read_only || !o.read_only)
                && hosts_within(&n.hosts, &o.hosts)
                && commands_within(&n.commands, &o.commands)
                && n.mint_scopes.iter().all(|s| o.mint_scopes.contains(s))
                && n.roots
                    .iter()
                    .all(|r| o.roots.iter().any(|old| crate::model::within_root(r, old)))
                && n.env.iter().all(|e| o.env.contains(e))
                && n.ssh_host_keys.iter().all(|k| o.ssh_host_keys.contains(k))
                && n.git_hosts.iter().all(|g| o.git_hosts.contains(g));
            if narrower {
                Change::Tighten
            } else {
                Change::Loosen
            }
        }
    }
}

/// Compares whole rule sets. Returns the overall change and the keys that loosen.
pub fn classify(old: &Rules, new: &Rules) -> (Change, Vec<KeyName>) {
    let mut worst = Change::Same;
    let mut loosened = Vec::new();
    for name in old.keys.keys().chain(new.keys.keys()) {
        let c = classify_rule(old.keys.get(name), new.keys.get(name));
        if c == Change::Loosen && !loosened.contains(name) {
            loosened.push(name.clone());
        }
        worst = worst.max(c);
    }
    (worst, loosened)
}

fn hosts_within(new: &[HostPattern], old: &[HostPattern]) -> bool {
    new.iter().all(|n| old.iter().any(|o| n.is_within(o)))
}

fn commands_within(new: &[CommandPattern], old: &[CommandPattern]) -> bool {
    new.iter().all(|n| old.iter().any(|o| n.is_within(o)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{KeyLimit, ProjectRules, merge};
    use ms_core::{Mode, Tier};
    use std::collections::BTreeMap;

    const PIN: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIPtd2fa6erUsRui9x7T64boFCGFRwuEig/mwpm4LdTO7";

    fn base() -> KeyRule {
        let mut r = KeyRule::new(Mode::Run, Tier::Test);
        r.ssh_host_keys = vec![
            crate::model::SshHostKey::parse(&format!("git.example ssh-ed25519 {PIN}")).unwrap(),
        ];
        r.commands = vec![CommandPattern::parse(&["psql".into(), "**".into()]).unwrap()];
        r.hosts = vec![HostPattern::parse("*.db.internal").unwrap()];
        r.session_ttl_secs = 600;
        r.roots = vec!["/r/app".into()];
        r.env = vec!["PGPASSWORD".into()];
        r
    }

    // protects=every loosening dimension is classified Loosen and every narrowing Tighten;
    // fails_when=a looser rule passes as Tighten (it would skip the approval); no_claim=the
    // approval flow itself (L07/L11)
    #[test]
    fn classifies_each_dimension() {
        let o = base();
        assert_eq!(classify_rule(Some(&o), Some(&o)), Change::Same);
        type Edit = Box<dyn Fn(&mut KeyRule)>;
        let loosen: Vec<Edit> = vec![
            Box::new(|r| r.tier = Tier::Test),
            Box::new(|r| r.session_ttl_secs = 601),
            Box::new(|r| r.read_only = false),
            Box::new(|r| r.mode = Mode::Swap),
            Box::new(|r| r.hosts.push(HostPattern::parse("db.internal").unwrap())),
            Box::new(|r| r.hosts = vec![HostPattern::parse("*.internal").unwrap()]),
            Box::new(|r| {
                r.commands
                    .push(CommandPattern::parse(&["sh".into(), "**".into()]).unwrap())
            }),
            Box::new(|r| r.roots.push("/r/other".into())),
            Box::new(|r| r.roots = vec!["/r".into()]),
            // A sibling that shares a string prefix is not inside the root.
            Box::new(|r| r.roots = vec!["/r/application".into()]),
            Box::new(|r| r.env.push("CURL_HOME".into())),
            // L16: a new pinned SSH host key lets the key sign logins somewhere new.
            Box::new(|r| {
                r.ssh_host_keys.push(
                    crate::model::SshHostKey::parse(&format!("other.example ssh-ed25519 {PIN}"))
                        .unwrap(),
                )
            }),
            // L30: a git host changes where the key goes on a host, even one already bound.
            Box::new(|r| r.git_hosts.push("a.db.internal".into())),
        ];
        for (i, f) in loosen.iter().enumerate() {
            let mut start = o.clone();
            start.tier = Tier::Production;
            start.read_only = true;
            let mut n = start.clone();
            f(&mut n);
            assert_eq!(
                classify_rule(Some(&start), Some(&n)),
                Change::Loosen,
                "case {i}"
            );
        }
        let mut n = o.clone();
        n.tier = Tier::Production;
        n.session_ttl_secs = 60;
        n.read_only = true;
        n.hosts = vec![HostPattern::parse("a.db.internal").unwrap()];
        n.commands =
            vec![CommandPattern::parse(&["psql".into(), "-c".into(), "*".into()]).unwrap()];
        n.roots = vec!["/r/app/sub".into()];
        assert_eq!(classify_rule(Some(&o), Some(&n)), Change::Tighten);
        n.roots.clear();
        n.env.clear();
        n.ssh_host_keys.clear();
        assert_eq!(classify_rule(Some(&o), Some(&n)), Change::Tighten);
        assert_eq!(classify_rule(Some(&o), None), Change::Tighten);
        assert_eq!(classify_rule(None, Some(&o)), Change::Loosen);
        assert_eq!(
            classify_rule(None, Some(&KeyRule::new(Mode::Swap, Tier::Test))),
            Change::Tighten
        );
    }

    // protects=whole-set classification reports every loosened key; fails_when=a loosened key
    // is hidden behind a tightened one; no_claim=ordering of the list
    #[test]
    fn classify_sets() {
        let a = KeyName::new("a").unwrap();
        let b = KeyName::new("b").unwrap();
        let old = Rules {
            version: 1,
            keys: BTreeMap::from([(a.clone(), base()), (b.clone(), base())]),
            ..Rules::default()
        };
        let mut new = old.clone();
        new.keys.get_mut(&a).unwrap().tier = Tier::Production;
        new.keys.get_mut(&b).unwrap().session_ttl_secs = 9999;
        assert_eq!(classify(&old, &new), (Change::Loosen, vec![b.clone()]));
        new.keys.remove(&b);
        assert_eq!(classify(&old, &new), (Change::Tighten, vec![]));
        assert_eq!(classify(&old, &old), (Change::Same, vec![]));
    }

    // protects=a merged project rule always classifies as Tighten or Same against the user rule
    // (the two checks agree); fails_when=the merge produces something classify calls Loosen;
    // no_claim=nothing beyond this fixed sample
    #[test]
    fn merge_result_is_never_a_loosen() {
        let k = KeyName::new("k").unwrap();
        let user = Rules {
            version: 1,
            keys: BTreeMap::from([(k.clone(), base())]),
            ..Rules::default()
        };
        let limit = KeyLimit {
            commands: Some(vec![
                CommandPattern::parse(&["psql".into(), "*".into(), "**".into()]).unwrap(),
            ]),
            hosts: Some(vec![HostPattern::parse("*.a.db.internal").unwrap()]),
            session_ttl_secs: Some(30),
            ..KeyLimit::default()
        };
        let merged = merge(
            &user,
            &ProjectRules {
                keys: BTreeMap::from([(k, limit)]),
            },
        );
        assert_eq!(classify(&user, &merged).0, Change::Tighten);
    }
}
