//! One rule edit, shared by `ms rules` and the dashboard (L33 SPEC D-14): the same parsing,
//! validation and normalisation for both, so a change made in the page is exactly the change the
//! same words make on the command line. The caller classifies the result
//! ([`crate::classify_rule`]): loosening needs a person's approval, tightening none.

use std::path::PathBuf;

use ms_core::{KeyName, Tier};

use crate::model::{KeyRule, SshHostKey, validate_env_name, validate_root};
use crate::pattern::{CommandPattern, HostPattern};

/// One change to one key's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// `--add-host`: `api.example.com` or `*.example.com`.
    AddHost(String),
    /// `--remove-host` (also drops it as a git host).
    RemoveHost(String),
    /// `--add-git-host`: one exact name; adds the host too.
    AddGitHost(String),
    /// `--remove-git-host` (the host itself stays).
    RemoveGitHost(String),
    /// `--add-command`, as its words.
    AddCommand(Vec<String>),
    /// `--remove-command`, as its words.
    RemoveCommand(Vec<String>),
    /// `--add-root`: an absolute directory, already resolved by the caller.
    AddRoot(PathBuf),
    /// `--remove-root`.
    RemoveRoot(PathBuf),
    /// `--add-env` (the caller also refuses names morsec sets itself).
    AddEnv(String),
    /// `--remove-env`.
    RemoveEnv(String),
    /// `--add-ssh-host-key`, a known_hosts line.
    AddSshHostKey(String),
    /// `--remove-ssh-host-key`.
    RemoveSshHostKey(String),
    /// `--tier`.
    SetTier(Tier),
    /// `--ttl`, seconds.
    SetTtl(u64),
    /// `--read-only` (true) or `--writable` (false).
    SetReadOnly(bool),
}

fn host(h: &str) -> Result<HostPattern, String> {
    HostPattern::parse(h).map_err(|e| format!("morsec: {e}"))
}

fn command(words: &[String]) -> Result<CommandPattern, String> {
    CommandPattern::parse(words).map_err(|e| format!("morsec: {e}"))
}

/// Applies `edits` to `current` in order and normalises the result as the rules file would be.
/// The messages are the ones `ms rules` prints.
pub fn apply(current: &KeyRule, name: &KeyName, edits: &[Edit]) -> Result<KeyRule, String> {
    let mut r = current.clone();
    // A host both added as a git host and removed is refused whichever comes first.
    let removed: Vec<HostPattern> = edits
        .iter()
        .filter_map(|e| match e {
            Edit::RemoveHost(h) | Edit::RemoveGitHost(h) => HostPattern::parse(h).ok(),
            _ => None,
        })
        .collect();
    for e in edits {
        match e {
            Edit::AddHost(h) => r.hosts.push(host(h)?),
            Edit::RemoveHost(h) => {
                let p = host(h)?;
                r.hosts.retain(|x| *x != p);
                r.git_hosts.retain(|g| HostPattern::Exact(g.clone()) != p);
            }
            Edit::AddGitHost(h) => {
                let p = host(h)?;
                let HostPattern::Exact(exact) = &p else {
                    return Err(format!(
                        "morsec: a git host is one exact name such as github.com, not {h:?}"
                    ));
                };
                if removed.contains(&p) {
                    return Err(format!(
                        "morsec: {exact} is both added and removed; say one or the other"
                    ));
                }
                if !r.hosts.contains(&p) {
                    r.hosts.push(p.clone());
                }
                r.git_hosts.push(exact.clone());
            }
            Edit::RemoveGitHost(h) => {
                let p = host(h)?;
                r.git_hosts.retain(|g| HostPattern::Exact(g.clone()) != p);
            }
            Edit::AddCommand(words) => r.commands.push(command(words)?),
            Edit::RemoveCommand(words) => {
                let p = command(words)?;
                r.commands.retain(|x| *x != p);
            }
            Edit::AddRoot(p) => {
                validate_root(p).map_err(|e| format!("morsec: {e}"))?;
                r.roots.push(p.clone());
            }
            Edit::RemoveRoot(p) => r.roots.retain(|x| x != p),
            Edit::AddEnv(n) => {
                validate_env_name(n).map_err(|e| format!("morsec: {e}"))?;
                r.env.push(n.clone());
            }
            Edit::RemoveEnv(n) => r.env.retain(|x| x != n),
            Edit::AddSshHostKey(l) => r
                .ssh_host_keys
                .push(SshHostKey::parse(l).map_err(|e| format!("morsec: {e}"))?),
            Edit::RemoveSshHostKey(l) => {
                let p = SshHostKey::parse(l).map_err(|e| format!("morsec: {e}"))?;
                r.ssh_host_keys.retain(|x| *x != p);
            }
            Edit::SetTier(t) => r.tier = *t,
            Edit::SetTtl(s) => r.session_ttl_secs = *s,
            Edit::SetReadOnly(b) => r.read_only = *b,
        }
    }
    // Same limits and per-mode checks as the file.
    r.normalise("your proposed change", name)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Change, classify_rule};
    use ms_core::Mode;

    fn k() -> KeyName {
        KeyName::new("gh/t").unwrap()
    }

    fn words(w: &[&str]) -> Vec<String> {
        w.iter().map(|s| (*s).to_owned()).collect()
    }

    // protects=L33 SPEC D-14 and T-97: the one edit function behaves as `ms rules` always did:
    // hosts parsed and normalised (never stored raw), a removed host leaves both lists, a git
    // host is exact and adds the host, add-and-remove of one host is refused, commands are parsed
    // patterns, folders must be absolute, tiers change, and the result classifies as `ms rules`
    // would (adding loosens, removing tightens); fails_when=the page and the CLI could produce
    // different rules from the same words, or a bad host or command is accepted;
    // no_claim=msd's approval of the result (msd dash_actions tests)
    #[test]
    fn edit_matches_cli_semantics() {
        let base = KeyRule::new(Mode::Swap, Tier::Test);
        for odd in ["GitHub.com", "github.com.", "*.github.com", "10.0.0.1"] {
            assert!(
                apply(&base, &k(), &[Edit::AddGitHost(odd.into())]).is_err(),
                "{odd}"
            );
        }
        let r = apply(&base, &k(), &[Edit::AddGitHost("github.com".into())]).unwrap();
        assert_eq!(r.git_hosts, ["github.com"]);
        assert_eq!(r.hosts, [HostPattern::parse("github.com").unwrap()]);
        let gone = apply(&r, &k(), &[Edit::RemoveHost("github.com".into())]).unwrap();
        assert!(gone.hosts.is_empty() && gone.git_hosts.is_empty());
        let plain = apply(&r, &k(), &[Edit::RemoveGitHost("github.com".into())]).unwrap();
        assert!(plain.git_hosts.is_empty());
        assert_eq!(plain.hosts, r.hosts);
        for conflict in [
            vec![
                Edit::AddGitHost("github.com".into()),
                Edit::RemoveHost("github.com".into()),
            ],
            vec![
                Edit::RemoveGitHost("github.com".into()),
                Edit::AddGitHost("github.com".into()),
            ],
        ] {
            assert!(apply(&base, &k(), &conflict).is_err(), "{conflict:?}");
        }

        let wide = apply(&base, &k(), &[Edit::AddHost("*.example.com".into())]).unwrap();
        assert_eq!(wide.hosts[0].to_string(), "*.example.com");
        assert_eq!(classify_rule(Some(&base), Some(&wide)), Change::Loosen);
        for bad in [
            "",
            "http://x.example",
            "a b",
            "x.example/path",
            "Example.com",
        ] {
            let e = apply(&base, &k(), &[Edit::AddHost(bad.into())]).unwrap_err();
            assert!(e.starts_with("morsec: "), "{e}");
        }
        let narrow = apply(&wide, &k(), &[Edit::RemoveHost("*.example.com".into())]).unwrap();
        assert_eq!(classify_rule(Some(&wide), Some(&narrow)), Change::Tighten);
        let prod = apply(&wide, &k(), &[Edit::SetTier(Tier::Production)]).unwrap();
        assert_eq!(classify_rule(Some(&wide), Some(&prod)), Change::Tighten);
        assert_eq!(classify_rule(Some(&prod), Some(&wide)), Change::Loosen);

        let run = KeyRule::new(Mode::Run, Tier::Test);
        assert!(apply(&run, &k(), &[Edit::AddGitHost("github.com".into())]).is_err());
        let psql = apply(&run, &k(), &[Edit::AddCommand(words(&["psql", "-c", "*"]))]).unwrap();
        assert_eq!(psql.commands.len(), 1);
        assert_eq!(classify_rule(Some(&run), Some(&psql)), Change::Loosen);
        assert!(apply(&run, &k(), &[Edit::AddCommand(Vec::new())]).is_err());
        let back = apply(
            &psql,
            &k(),
            &[Edit::RemoveCommand(words(&["psql", "-c", "*"]))],
        )
        .unwrap();
        assert!(back.commands.is_empty());
        assert!(apply(&run, &k(), &[Edit::AddRoot(PathBuf::from("relative/dir"))]).is_err());
        let rooted = apply(&run, &k(), &[Edit::AddRoot(PathBuf::from("/tmp"))]).unwrap();
        assert_eq!(rooted.roots, [PathBuf::from("/tmp")]);
        assert!(apply(&run, &k(), &[Edit::AddEnv("not a name".into())]).is_err());
    }
}
