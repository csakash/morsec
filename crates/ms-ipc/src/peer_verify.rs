//! Client-side check that the process serving the daemon socket is the signed `msd` (T-03).
//!
//! The agent morsec guards against runs as the user, so "the server has my uid" proves nothing:
//! it can take over the socket path and listen there itself. Before a client sends anything, it
//! reads the peer's audit token from the *connected* socket (the kernel's word, not the path's),
//! and has Security.framework check that code against msd's Developer ID designated requirement
//! with the client's own Team ID. Checking the connected socket rather than the path leaves no
//! check-then-use gap to race.
//!
//! A client with no Team ID (every `cargo build`: unsigned or ad-hoc) can't name a team, so it
//! refuses unless [`DEV_OPT_OUT_ENV`]`=1` is set, and then says so on stderr. A signed release
//! ignores that variable: [`policy`] decides from the client's own signature first.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "macos")]
mod macos;

/// The code-signing identifier every release signs msd with (`packaging/macos/sign-targets`).
pub const MSD_IDENTIFIER: &str = "cc.morsec.msd";

/// Dev builds only: `MORSEC_DEV_UNVERIFIED_DAEMON=1` lets a client with no Team ID talk to a
/// same-user daemon it can't verify. Ignored by a client signed with a Team ID.
pub const DEV_OPT_OUT_ENV: &str = "MORSEC_DEV_UNVERIFIED_DAEMON";

/// What this process's own code signature says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnSignature {
    /// Signed with a Developer ID from this team (a release).
    Team(String),
    /// Unsigned, ad-hoc or linker-signed: a dev build. (Always the case off macOS.)
    NoTeam,
    /// The signature could not be read. Treated as a failure, never as "no team".
    Unreadable(String),
}

/// How a client must treat the daemon's peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Verify the peer against this code requirement.
    Verify {
        /// The client's own Team ID, which msd must share.
        team: String,
        /// The requirement text handed to `SecRequirementCreateWithString`.
        requirement: String,
    },
    /// Dev build with the explicit opt-out: uid check only. Announced on stderr.
    DevUnverified,
    /// Talk to nothing. The reason is shown to the person.
    Refuse(String),
}

/// What [`crate::Client::connect`] established about the peer, for `ms doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    /// The peer satisfied msd's designated requirement for this team.
    Verified {
        /// Team ID shared by the client and msd.
        team: String,
    },
    /// Not verified: dev build running with [`DEV_OPT_OUT_ENV`].
    DevUnverified,
}

/// msd's Developer ID designated requirement for `team`: Apple-anchored Developer ID chain
/// (intermediate and leaf marker OIDs), msd's identifier, and the leaf's team (subject OU).
/// `None` when `team` isn't a well-formed Team ID (10 characters, A-Z and 0-9), so the
/// requirement language never sees anything else.
pub fn developer_id_requirement(identifier: &str, team: &str) -> Option<String> {
    let team_ok = team.len() == 10
        && team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let ident_ok = !identifier.is_empty()
        && identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    (team_ok && ident_ok).then(|| {
        format!(
            "identifier \"{identifier}\" and anchor apple generic and \
             certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
             certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
             certificate leaf[subject.OU] = \"{team}\""
        )
    })
}

/// The decision table. The client's own signature is consulted first: with a Team ID the
/// answer is always [`Trust::Verify`], whatever `opt_out` says and whatever the build profile.
pub fn policy(own: &OwnSignature, opt_out: bool) -> Trust {
    match own {
        OwnSignature::Team(team) => match developer_id_requirement(MSD_IDENTIFIER, team) {
            Some(requirement) => Trust::Verify {
                team: team.clone(),
                requirement,
            },
            None => Trust::Refuse(format!(
                "this ms is signed with an unexpected Team ID ({}); reinstall morsec",
                team.escape_debug()
            )),
        },
        OwnSignature::NoTeam if opt_out => Trust::DevUnverified,
        OwnSignature::NoTeam => Trust::Refuse(format!(
            "this ms is a dev build without a Developer ID signature, so it can't check that the \
             socket is served by the signed msd. Install the signed release (brew install \
             morsec), or for development only set {DEV_OPT_OUT_ENV}=1"
        )),
        OwnSignature::Unreadable(why) => Trust::Refuse(format!(
            "can't read this program's own code signature: {why}"
        )),
    }
}

/// This process's own signature. It can't change while the process runs, so it is read once.
pub fn own_signature() -> OwnSignature {
    static OWN: OnceLock<OwnSignature> = OnceLock::new();
    OWN.get_or_init(read_own_signature).clone()
}

#[cfg(target_os = "macos")]
fn read_own_signature() -> OwnSignature {
    match macos::own_team_id() {
        Ok(Some(team)) => OwnSignature::Team(team),
        Ok(None) => OwnSignature::NoTeam,
        Err(e) => OwnSignature::Unreadable(e),
    }
}

// No code signatures off macOS: every build is a dev build here (Linux verification is L21).
#[cfg(not(target_os = "macos"))]
fn read_own_signature() -> OwnSignature {
    OwnSignature::NoTeam
}

/// Whether the dev opt-out is set (exactly `1`).
pub fn opt_out_requested() -> bool {
    std::env::var_os(DEV_OPT_OUT_ENV).is_some_and(|v| v == "1")
}

/// The policy for this process right now.
pub fn current_trust() -> Trust {
    policy(&own_signature(), opt_out_requested())
}

/// Checks the peer of a connected Unix socket against `requirement`. Uses the peer's audit
/// token, so a PID that exited and was reused fails instead of matching another process.
#[cfg(target_os = "macos")]
pub fn verify_peer<S: std::os::fd::AsFd>(socket: &S, requirement: &str) -> Result<(), String> {
    macos::verify_peer(socket.as_fd(), requirement)
}

/// Off macOS there is nothing to check a signature with: always refused.
#[cfg(not(target_os = "macos"))]
pub fn verify_peer<S: std::os::fd::AsFd>(_socket: &S, _requirement: &str) -> Result<(), String> {
    Err("code-signature checks are macOS only (Linux peer verification is L21)".into())
}

/// Applies `trust` to a connection: `verify` runs the signature check (only for
/// [`Trust::Verify`]). `Err` is the reason to show.
pub fn apply(
    trust: Trust,
    verify: impl FnOnce(&str) -> Result<(), String>,
) -> Result<PeerIdentity, String> {
    match trust {
        Trust::Verify { team, requirement } => {
            verify(&requirement).map_err(|e| {
                format!("can't confirm it is msd ({MSD_IDENTIFIER}, team {team}): {e}")
            })?;
            Ok(PeerIdentity::Verified { team })
        }
        Trust::DevUnverified => {
            warn_dev_once();
            Ok(PeerIdentity::DevUnverified)
        }
        Trust::Refuse(why) => Err(why),
    }
}

#[allow(clippy::print_stderr)]
fn warn_dev_once() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "morsec: DEV BUILD: not checking that the socket is served by the signed msd \
             ({DEV_OPT_OUT_ENV}=1 with an unsigned ms). Never use this with real secrets."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "ABCDE12345";

    // protects=T-03 release configuration: a client signed with a Team ID always verifies msd,
    // and the dev opt-out can't switch that off in any build profile; fails_when=a signed client
    // with MORSEC_DEV_UNVERIFIED_DAEMON=1 gets DevUnverified or Refuse; no_claim=a live
    // Developer ID signature (needs the release identity; see PROOF.md)
    #[test]
    fn release_signature_ignores_the_dev_opt_out() {
        for opt_out in [false, true] {
            match policy(&OwnSignature::Team(TEAM.into()), opt_out) {
                Trust::Verify { team, requirement } => {
                    assert_eq!(team, TEAM);
                    assert!(requirement.contains("identifier \"cc.morsec.msd\""));
                    assert!(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
                    assert!(requirement.contains("anchor apple generic"));
                }
                other => panic!("opt_out={opt_out}: {other:?}"),
            }
        }
    }

    // protects=T-03 dev builds fail closed: no Team ID and no opt-out refuses, with a message
    // naming the fix; an unreadable own signature refuses even with the opt-out;
    // fails_when=an unsigned client talks to an unverified daemon by default;
    // no_claim=the stderr warning text (msd's tests/peer_verify.rs checks it live)
    #[test]
    fn dev_builds_need_the_explicit_opt_out() {
        match policy(&OwnSignature::NoTeam, false) {
            Trust::Refuse(why) => {
                assert!(
                    why.contains(DEV_OPT_OUT_ENV) && why.contains("brew install"),
                    "{why}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(policy(&OwnSignature::NoTeam, true), Trust::DevUnverified);
        for opt_out in [false, true] {
            assert!(matches!(
                policy(&OwnSignature::Unreadable("x".into()), opt_out),
                Trust::Refuse(_)
            ));
        }
    }

    // protects=the requirement text can't be steered: only a well-formed Team ID and identifier
    // reach the requirement language; fails_when=a quote or space in the team is interpolated;
    // no_claim=how Security.framework parses it (requirement_compiles checks that)
    #[test]
    fn requirement_rejects_malformed_team_ids() {
        for bad in [
            "",
            "abcde12345",
            "ABCDE1234",
            "ABCDE123456",
            "ABCDE\"1234",
            "ABCDE 1234",
        ] {
            assert_eq!(developer_id_requirement(MSD_IDENTIFIER, bad), None, "{bad}");
            assert!(matches!(
                policy(&OwnSignature::Team(bad.into()), true),
                Trust::Refuse(_)
            ));
        }
        assert_eq!(developer_id_requirement("cc.morsec.msd\" or", TEAM), None);
    }

    // protects=a failed verification is a refusal that names msd and the team, and a refusal
    // never calls the verifier; fails_when=a verifier error is swallowed into success;
    // no_claim=the live Security.framework call
    #[test]
    fn apply_fails_closed() {
        let trust = policy(&OwnSignature::Team(TEAM.into()), false);
        let err = apply(trust.clone(), |_| Err("no such guest".into())).unwrap_err();
        assert!(
            err.contains("cc.morsec.msd") && err.contains(TEAM) && err.contains("no such guest")
        );
        assert_eq!(
            apply(trust, |_| Ok(())).unwrap(),
            PeerIdentity::Verified { team: TEAM.into() }
        );
        let refused = apply(Trust::Refuse("no".into()), |_| panic!("must not verify"));
        assert_eq!(refused.unwrap_err(), "no");
    }
}
