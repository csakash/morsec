//! Run mode in msd (L12): policy, approvals and receipts around `ms-run`'s runner.
//!
//! For each `Run` / `RunStream`:
//!
//! 1. The caller is identified from the kernel peer (never from the request); an unidentified
//!    or LOG-2-stopped session is refused.
//! 2. The request is checked (`ms_run::RunInput`). The run-mode keys among its refs are the
//!    keys the call needs; none at all answers `not_run`, so the shim runs the tool unchanged.
//! 3. For every such key: the working directory must lie inside the key's project roots (user
//!    rules; resolved through symlinks), and `ms_rules::decide_run` on the user rules merged with
//!    the project's `.morsec.toml` must allow the exact argv. A production key asks the
//!    [`Approver`](ms_approve::Approver) with an `ApprovalRequest` built here from the
//!    normalised argv, the canonical cwd and the adapter's preview.
//! 4. The receipts (one per key, with the argv hash) are written before anything runs; if they
//!    can't be, nothing runs.
//! 5. The runner builds the plan and runs it; output is redacted on the way out.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use ms_core::{Decision, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, SecretRef, SessionId};
use ms_ipc::{ErrorCode, PeerInfo, ResponseBody, RunEnv, StreamIo};
use ms_receipts::ReceiptDetail;
use ms_rules::project::MAX_PROJECT_FILE;
use ms_rules::{PROJECT_FILE, Rules};
use ms_run::{ExecIo, Prepared, RunError, RunInput, Runner, RunnerConfig};
use tokio::sync::{Semaphore, mpsc};

use super::{Daemon, now_ms, reply_err, session_of};

/// Most runs at once.
pub const MAX_RUNS: usize = 8;
/// Cap per output stream of a buffered `Run`.
pub const BUFFERED_CAP: usize = 256 * 1024;
/// How often a running command checks for `ms stop`.
const STOP_POLL: std::time::Duration = std::time::Duration::from_millis(200);
/// What a run killed by `ms stop` answers.
const STOPPED_MID_RUN: &str =
    "morsec: morsec was stopped (ms stop or a stopped session), so the command was killed";
/// Most output bytes in one `RunOutput` frame.
const FRAME_DATA: usize = 32 * 1024;
/// Longest argv shown in a receipt's target.
const TARGET_MAX: usize = 512;

static RUNNER: OnceLock<Runner> = OnceLock::new();
static RUNS: Semaphore = Semaphore::const_new(MAX_RUNS);

/// The runner, configured from msd's own environment on first use.
fn runner() -> &'static Runner {
    RUNNER.get_or_init(|| Runner::new(RunnerConfig::from_process_env()))
}

/// Per-key outcome while deciding, for receipts.
struct Decided {
    key: KeyName,
    result: ReceiptResult,
    approval_id: Option<String>,
}

impl Daemon {
    /// Steps 1–4: everything up to an exec plan. Blocking (vault, approvals, receipts).
    // The error is the reply itself.
    #[allow(clippy::result_large_err)]
    pub(crate) fn prepare_run(
        &self,
        peer: &PeerInfo,
        argv: Vec<String>,
        cwd: PathBuf,
        env: Vec<RunEnv>,
        via: Option<&str>,
    ) -> Result<(Prepared, SessionId), ResponseBody> {
        let caller = self.caller(peer).ok_or_else(|| {
            reply_err(
                ErrorCode::Denied,
                "morsec: the process that opened this connection can't be identified any more, so the run is refused. Reconnect from a running process",
            )
        })?;
        let session = session_of(Some(&caller), peer);
        if self.session_stopped(&session) {
            return Err(reply_err(
                ErrorCode::Denied,
                "morsec: this agent session was stopped after repeated blocked attempts (LOG-2). Start a new session",
            ));
        }
        let mut input = RunInput::new(
            argv,
            cwd,
            env.into_iter().map(|e| (e.name, e.value)).collect(),
        )
        .map_err(|e| e.reply())?;

        let (user, version) = {
            let l = self.read_live();
            (l.rules.clone(), l.rules.version)
        };
        let run_keys: BTreeSet<KeyName> = input
            .keys()
            .into_iter()
            .filter(|k| user.keys.get(k).is_some_and(|r| r.mode == Mode::Run))
            .collect();
        if run_keys.is_empty() {
            return Err(RunError::not_run(
                "morsec: no run-mode key is referenced, so morsec has nothing to run",
            )
            .reply());
        }
        let carries_run_ref = |v: &str| {
            SecretRef::find_all(v)
                .iter()
                .any(|(_, r)| run_keys.contains(r.name()))
        };
        let env_names: Vec<&str> = input
            .env
            .iter()
            .filter(|(_, v)| carries_run_ref(v))
            .map(|(n, _)| n.as_str())
            .collect();
        let mut target = if env_names.is_empty() {
            target_of(&input.argv)
        } else {
            format!("{} [env {}]", target_of(&input.argv), env_names.join(","))
        };
        // Where the call came from (`mcp:<tool>`, L14); built by msd, never agent text.
        if let Some(v) = via {
            target = format!("{v} {target}");
        }
        let hash = ms_rules::argv_hash(&input.argv);
        let refuse = |key: &KeyName, result: ReceiptResult, reply: ResponseBody| {
            if let Err(e) = self.record_run(&session, key, &target, hash, version, result, None) {
                tracing::error!(error = %e, "could not record a refused run");
            }
            reply
        };

        // Values go only into variables the key's rule names, and only as the whole value
        // (`NAME=ms://key`): a variable the agent picks, or text around the ref, could make the
        // tool load the agent's config or send the value somewhere else (security review S1).
        // Variables that hold no run-mode ref are not given to the child at all.
        let mut kept = Vec::new();
        for (name, value) in std::mem::take(&mut input.env) {
            if !carries_run_ref(&value) {
                continue;
            }
            let whole = SecretRef::parse(&value)
                .ok()
                .filter(|r| run_keys.contains(r.name()));
            let Some(r) = whole else {
                let k = SecretRef::find_all(&value)
                    .into_iter()
                    .map(|(_, r)| r.name().clone())
                    .find(|k| run_keys.contains(k))
                    .unwrap_or_else(|| unreachable!("carries_run_ref checked it"));
                let msg = format!(
                    "morsec: {name} must be exactly ms://{k} (nothing before or after it, no other reference); morsec puts a value only into a whole variable"
                );
                let result = ReceiptResult::Blocked(Reason::CommandNotAllowed);
                return Err(refuse(&k, result, reply_err(ErrorCode::Denied, msg)));
            };
            let k = r.name().clone();
            let allowed = user
                .keys
                .get(&k)
                .is_some_and(|rule| rule.env.contains(&name));
            if !ms_run::input::env_name_allowed(&name) {
                let msg = format!(
                    "morsec: {name} can't carry a key's value: it changes how programs load code or run commands"
                );
                let result = ReceiptResult::Blocked(Reason::CommandNotAllowed);
                return Err(refuse(&k, result, reply_err(ErrorCode::Denied, msg)));
            }
            if !allowed {
                let msg = format!(
                    "morsec: {k}'s value may not go into {name}. If that variable is how the tool takes it, allow it from your own terminal: ms rules {k} --add-env {name}"
                );
                let result = ReceiptResult::Blocked(Reason::CommandNotAllowed);
                return Err(refuse(&k, result, reply_err(ErrorCode::Denied, msg)));
            }
            kept.push((name, value));
        }
        input.env_keys = kept
            .iter()
            .filter_map(|(_, v)| SecretRef::parse(v).ok().map(|r| r.name().clone()))
            .collect();
        input.env = kept;

        // Roots: the user's rules, for every key. All keys must agree on one directory.
        let mut real_cwd = None;
        for k in &run_keys {
            let roots = user
                .keys
                .get(k)
                .map(|r| r.roots.clone())
                .unwrap_or_default();
            match ms_run::cwd::check(&input.cwd, &roots, k.as_str()) {
                Ok(c) => real_cwd = Some(c),
                Err(e) => {
                    let result = ReceiptResult::Blocked(Reason::CommandNotAllowed);
                    return Err(refuse(k, result, e.reply()));
                }
            }
        }
        let Some(real_cwd) = real_cwd else {
            unreachable!("run_keys is not empty")
        };

        let rules = effective_for(&user, &real_cwd);
        let call = Runner::call(&input, real_cwd.clone(), session.clone());
        let mut decided = Vec::new();
        for k in &run_keys {
            match ms_rules::decide_run(&rules, &session, k, &input.argv, &real_cwd) {
                Decision::Allow => decided.push(Decided {
                    key: k.clone(),
                    result: ReceiptResult::Allowed,
                    approval_id: None,
                }),
                Decision::Deny { reason } => {
                    let msg = deny_message(k, &reason, &input.argv);
                    return Err(refuse(
                        k,
                        ReceiptResult::Blocked(reason),
                        reply_err(ErrorCode::Denied, msg),
                    ));
                }
                Decision::NeedsApproval { mut request } => {
                    request.effect = runner().preview(&call).map(|p| p.summary);
                    // L11: a person approves in `ms approve` with Touch ID; the token is then
                    // checked against this exact request (key, argv hash, cwd, session) before
                    // anything runs, and the plan below is built from that same argv and cwd.
                    match self.approve_exact(&request) {
                        Ok(token) => decided.push(Decided {
                            key: k.clone(),
                            result: ReceiptResult::Approved,
                            approval_id: Some(token.id),
                        }),
                        Err(reply) => return Err(refuse(k, ReceiptResult::Denied, reply)),
                    }
                }
            }
        }
        // An approval can take minutes; `ms stop` or a LOG-2 stop may have come meanwhile.
        if self.is_stopped() || self.session_stopped(&session) {
            return Err(reply_err(
                ErrorCode::Denied,
                "morsec: morsec was stopped while this command waited, so it did not run",
            ));
        }

        let prepared = match runner().plan(&input, &call, &run_keys, &*self.vault) {
            Ok(p) => p,
            Err(e) => {
                for d in &decided {
                    let _ = self.record_run(
                        &session,
                        &d.key,
                        &target,
                        hash,
                        version,
                        ReceiptResult::Failed(e.message.clone()),
                        d.approval_id.clone(),
                    );
                }
                return Err(e.reply());
            }
        };
        for d in decided {
            if let Err(e) = self.record_run(
                &session,
                &d.key,
                &target,
                hash,
                version,
                d.result,
                d.approval_id,
            ) {
                return Err(reply_err(
                    ErrorCode::Internal,
                    format!(
                        "morsec: the receipt for this run could not be written ({e}), so it did not run"
                    ),
                ));
            }
        }
        Ok((prepared, session))
    }

    /// Resolves once `ms stop` is in effect or a LOG-2 alert stopped `session`, so a run in
    /// progress can be killed (security review S3).
    async fn stop_signal(&self, session: &SessionId) {
        loop {
            if self.is_stopped() || self.session_stopped(session) {
                return;
            }
            tokio::time::sleep(STOP_POLL).await;
        }
    }

    // Private helper; each argument is one receipt field.
    #[allow(clippy::too_many_arguments)]
    fn record_run(
        &self,
        session: &SessionId,
        key: &KeyName,
        target: &str,
        argv_hash: [u8; 32],
        rule_version: u64,
        result: ReceiptResult,
        approval_id: Option<String>,
    ) -> ms_core::Result<()> {
        let method = approval_id
            .as_ref()
            .map(|_| super::TOUCH_ID_METHOD.to_owned());
        self.receipts
            .append_detailed(
                ReceiptEvent {
                    time_unix_ms: now_ms(),
                    session: session.clone(),
                    key: key.clone(),
                    mode: Mode::Run,
                    target: target.to_owned(),
                    argv_hash: Some(argv_hash),
                    rule_version,
                    approval_id,
                    result,
                },
                ReceiptDetail {
                    approval_method: method,
                    ..ReceiptDetail::default()
                },
            )
            .map(drop)
    }
}

/// `Run`: the buffered form. Runs on the blocking pool, like every other request.
pub(crate) fn run_buffered(
    d: &Daemon,
    peer: &PeerInfo,
    argv: Vec<String>,
    cwd: PathBuf,
    env: Vec<RunEnv>,
    via: Option<&str>,
) -> ResponseBody {
    let Ok(_permit) = RUNS.try_acquire() else {
        return busy();
    };
    let (prepared, session) = match d.prepare_run(peer, argv, cwd, env, via) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let handle = tokio::runtime::Handle::current();
    let result = handle.block_on(async {
        tokio::select! {
            r = runner().execute_buffered(prepared, BUFFERED_CAP) => Some(r),
            () = d.stop_signal(&session) => None,
        }
    });
    let Some(result) = result else {
        return reply_err(ErrorCode::Denied, STOPPED_MID_RUN);
    };
    match result {
        Ok((exit, out, err, truncated)) => ResponseBody::RunResult {
            code: exit.code,
            signal: exit.signal,
            stdout: ms_ipc::b64_encode(&out),
            stderr: ms_ipc::b64_encode(&err),
            truncated,
        },
        Err(e) => e.reply(),
    }
}

/// `RunStream`: decide on the blocking pool, then stream. Dropping the future (the client left)
/// kills the child's process group.
pub(crate) async fn run_stream(
    d: Arc<Daemon>,
    peer: PeerInfo,
    argv: Vec<String>,
    cwd: PathBuf,
    env: Vec<RunEnv>,
    io: StreamIo,
) -> ResponseBody {
    let Ok(_permit) = RUNS.try_acquire() else {
        return busy();
    };
    let d2 = d.clone();
    let (prepared, session) = match tokio::task::spawn_blocking(move || {
        d2.prepare_run(&peer, argv, cwd, env, None)
    })
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(r)) => return r,
        Err(e) => {
            tracing::error!(error = %e, "run handler failed");
            return reply_err(
                ErrorCode::Internal,
                "morsec: the daemon failed handling this run",
            );
        }
    };
    let StreamIo { input, output } = io;
    // Only now may the client read its stdin: a refusal above leaves it untouched.
    if output.send(ResponseBody::RunStarted).await.is_err() {
        return reply_err(ErrorCode::Internal, "morsec: the client left");
    }
    let (tx, mut rx) = mpsc::channel::<(ms_ipc::OutStream, Vec<u8>)>(16);
    let forward = async move {
        while let Some((stream, bytes)) = rx.recv().await {
            // A redacted chunk can exceed the read size (held-back tail, labels); frames stay
            // small and far under the frame limit.
            for part in bytes.chunks(FRAME_DATA) {
                let frame = ResponseBody::RunOutput {
                    stream,
                    data: ms_ipc::b64_encode(part),
                };
                if output.send(frame).await.is_err() {
                    return;
                }
            }
        }
    };
    let exec = runner().execute(
        prepared,
        ExecIo {
            stdin: input,
            output: tx,
        },
    );
    let both = async { tokio::join!(exec, forward).0 };
    let exit = tokio::select! {
        e = both => e,
        // Dropping the run kills the child's process group.
        () = d.stop_signal(&session) => return reply_err(ErrorCode::Denied, STOPPED_MID_RUN),
    };
    match exit {
        Ok(e) => ResponseBody::RunExit {
            code: e.code,
            signal: e.signal,
        },
        Err(e) => e.reply(),
    }
}

fn busy() -> ResponseBody {
    reply_err(
        ErrorCode::Busy,
        format!(
            "morsec: {MAX_RUNS} commands are already running through morsec; try again when one finishes"
        ),
    )
}

/// The argv as recorded: arguments joined by spaces, escaped and bounded.
fn target_of(argv: &[String]) -> String {
    let joined = argv.join(" ");
    let mut out: String = joined
        .chars()
        .take(TARGET_MAX)
        .flat_map(char::escape_default)
        .collect();
    if joined.chars().count() > TARGET_MAX {
        out.push('…');
    }
    out
}

fn deny_message(key: &KeyName, reason: &Reason, argv: &[String]) -> String {
    let shown = target_of(argv);
    match reason {
        Reason::CommandNotAllowed => format!(
            "morsec: {key} is not allowed to run `{shown}`. If it should be, allow it from your own terminal: ms rules {key} --add-command '<json argv pattern>'"
        ),
        Reason::Stopped => "morsec: morsec is stopped (ms stop); nothing runs until it is resumed".into(),
        Reason::RulesTampered => {
            "morsec: the rules file failed its integrity check, so every key is refused. Check ms status".into()
        }
        Reason::NoSuchKey => format!("morsec: there is no rule for {key}"),
        other => format!("morsec: {key} was refused ({other:?})"),
    }
}

/// The user rules merged with the project file above `cwd` (up to the git root). A project file
/// that can't be read or parsed disables every key (fail closed).
fn effective_for(user: &Rules, cwd: &Path) -> Rules {
    let Some(file) = find_project_file(cwd) else {
        return user.clone();
    };
    let shown = file.display().to_string();
    match read_project(&file) {
        Ok(text) => ms_rules::effective(user, Some(&text), &shown).0,
        Err(_) => ms_rules::project::disable_all(user, &shown),
    }
}

/// `.morsec.toml` in `start` or a parent, up to and including the directory holding `.git`
/// (the same walk as `ms rules`). Outside a git repository nothing is found.
fn find_project_file(start: &Path) -> Option<PathBuf> {
    let mut found = None;
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(PROJECT_FILE);
        if found.is_none() && std::fs::symlink_metadata(&candidate).is_ok() {
            found = Some(candidate);
        }
        if d.join(".git").exists() {
            return found;
        }
        dir = d.parent();
    }
    None
}

/// Reads a project file: a regular file (not a link), at most `MAX_PROJECT_FILE` bytes, UTF-8.
fn read_project(p: &Path) -> std::io::Result<String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    f.take(MAX_PROJECT_FILE as u64 + 1)
        .read_to_string(&mut text)?;
    if text.len() > MAX_PROJECT_FILE {
        return Err(std::io::Error::other("too large"));
    }
    Ok(text)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    // protects=a project file can't widen and an unreadable one fails closed; the walk stops at
    // the git root; fails_when=a link or oversized file is read, or a file above .git applies;
    // no_claim=the merge semantics (ms-rules project tests)
    #[test]
    fn project_file_lookup() {
        let d = tempfile::tempdir().unwrap();
        let top = std::fs::canonicalize(d.path()).unwrap();
        let repo = top.join("repo");
        let sub = repo.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir(repo.join(".git")).unwrap();
        std::fs::write(top.join(PROJECT_FILE), "junk").unwrap();
        assert_eq!(find_project_file(&sub), None);
        std::fs::write(repo.join(PROJECT_FILE), "").unwrap();
        assert_eq!(find_project_file(&sub), Some(repo.join(PROJECT_FILE)));
        assert_eq!(read_project(&repo.join(PROJECT_FILE)).unwrap(), "");

        std::fs::remove_file(repo.join(PROJECT_FILE)).unwrap();
        std::os::unix::fs::symlink(top.join(PROJECT_FILE), repo.join(PROJECT_FILE)).unwrap();
        assert!(read_project(&repo.join(PROJECT_FILE)).is_err());
        let user = Rules::from_toml(
            "version = 1\n[keys.\"k\"]\nmode = \"run\"\ntier = \"test\"\ncommands = [[\"env\"]]\nroots = [\"/r\"]",
            "rules.toml",
        )
        .unwrap();
        let eff = effective_for(&user, &sub);
        assert!(eff.keys[&KeyName::new("k").unwrap()].commands.is_empty());

        std::fs::remove_file(repo.join(PROJECT_FILE)).unwrap();
        std::fs::write(repo.join(PROJECT_FILE), "x".repeat(MAX_PROJECT_FILE + 1)).unwrap();
        assert!(read_project(&repo.join(PROJECT_FILE)).is_err());
    }

    use crate::backend::Backend;
    use crate::daemon::Identify;
    use crate::paths::Paths;
    use ms_approve::HumanApprover;
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{AgentKind, KeyMeta, SecretBytes, Tier};
    use ms_ipc::{ApprovalScope, RequestBody};
    use ms_session::Caller;
    use ms_vault::memory::MemoryVault;
    use std::sync::Mutex;

    pub(crate) const VALUE: &str = "pk_live_RUNMSD_canary_93a1";
    /// The PID the person answering approvals connects from (outside every agent tree).
    const PERSON_PID: i32 = 7001;

    pub(crate) fn peer() -> PeerInfo {
        PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(42),
            accepted_unix_ms: 1,
        }
    }

    fn person() -> PeerInfo {
        PeerInfo {
            pid: Some(PERSON_PID),
            ..peer()
        }
    }

    /// Answers the next pending approval as the person (`ms approve`), approving or denying.
    pub(crate) fn answer(
        d: &Arc<Daemon>,
        approve: bool,
        expect_argv: Option<&'static [&'static str]>,
    ) -> std::thread::JoinHandle<ResponseBody> {
        let d = d.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match d.handle(&person(), RequestBody::ApprovalPending, None) {
                    ResponseBody::Approval { pending: Some(p) } => {
                        if let Some(want) = expect_argv {
                            assert_eq!(p.request.argv_display, want);
                        }
                        return d.handle(
                            &person(),
                            RequestBody::ApprovalDecide {
                                id: p.id,
                                approve,
                                scope: Some(ApprovalScope::Once),
                            },
                            None,
                        );
                    }
                    ResponseBody::Approval { pending: None } => {}
                    other => return other,
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "no approval was requested"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    }

    // protects=AUTH-3 with L11's real approver: a production run key waits for a person
    // (`ms approve` + Touch ID, here the fake authenticator), the request shows the normalised
    // argv and canonical cwd that run, the token is checked against that request, and only then
    // does the command run, with redacted output; a denial, or Touch ID failing, refuses it; all
    // are recorded; fails_when=a production run runs without a verified approval or the value is
    // returned; no_claim=the real Touch ID sheet (manual, L11 evidence)
    #[test]
    fn production_runs_need_the_approver() {
        let rt = rt();
        // (Touch ID failing is L11's broker test; here the setup itself needs Touch ID to pass.)
        for approve in [false, true] {
            let touch_id_ok = true;
            let (d, dir, root) = test_daemon_with(
                Tier::Production,
                "commands = [[\"env\"]]\nenv = [\"TOKEN\"]",
                FakeAuthenticator::approve(),
            );
            let decider = answer(&d, approve, Some(&["env"]));
            let r = buffered(&rt, &d, &root, &["env"], &[("TOKEN", "ms://svc/test")]);
            let decision = decider.join().unwrap();
            let receipts = std::fs::read_dir(dir.path().join("receipts"))
                .unwrap()
                .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
                .collect::<String>();
            assert!(!receipts.contains(VALUE));
            if touch_id_ok && approve {
                assert!(matches!(decision, ResponseBody::Ok { .. }), "{decision:?}");
                let ResponseBody::RunResult { code, stdout, .. } = r else {
                    panic!("{r:?}")
                };
                assert_eq!(code, Some(0));
                let out = String::from_utf8(ms_ipc::b64_decode(&stdout).unwrap()).unwrap();
                assert!(out.contains("TOKEN=[redacted ms://svc/test]"), "{out}");
                assert!(!out.contains(VALUE));
                assert!(receipts.contains("\"approved\""), "{receipts}");
                assert!(
                    receipts.contains("touch-id") && receipts.contains("once-"),
                    "{receipts}"
                );
            } else {
                assert!(
                    matches!(
                        &r,
                        ResponseBody::Error {
                            code: ErrorCode::NeedsApproval,
                            ..
                        }
                    ),
                    "touch_id_ok={touch_id_ok} approve={approve}: {r:?}"
                );
                assert!(receipts.contains("\"denied\""), "{receipts}");
            }
        }
    }

    /// A daemon with one test-tier run key `svc/test` (value VALUE) under `rule_body`, roots =
    /// `<tmp>/proj`; the caller is an agent session.
    pub(crate) fn test_daemon(rule_body: &str) -> (Arc<Daemon>, tempfile::TempDir, PathBuf) {
        test_daemon_with(Tier::Test, rule_body, FakeAuthenticator::approve())
    }

    /// Like [`test_daemon`], with the key's tier and the Touch ID stand-in chosen. The person
    /// answering approvals connects from PERSON_PID.
    pub(crate) fn test_daemon_with(
        tier: Tier,
        rule_body: &str,
        auth: FakeAuthenticator,
    ) -> (Arc<Daemon>, tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("proj");
        std::fs::create_dir(&root).unwrap();
        let who: Arc<Mutex<Option<Caller>>> = Arc::new(Mutex::new(Some(Caller::Unattributed {
            pid: 43,
            started_unix_ms: 1,
        })));
        let w = who.clone();
        let identify: Identify = Arc::new(move |p: &PeerInfo| match p.pid {
            Some(PERSON_PID) => Some(Caller::Unattributed {
                pid: 99,
                started_unix_ms: 1,
            }),
            _ => w.lock().unwrap().clone(),
        });
        let approvals = Arc::new(HumanApprover::new(Arc::new(auth)).unwrap());
        approvals.set_cooldown(std::time::Duration::ZERO);
        let d = Daemon::open(
            Backend::Memory(Arc::new(MemoryVault::new())),
            Paths::under(dir.path()),
            0,
            approvals,
            identify,
        )
        .unwrap();
        let k = KeyName::new("svc/test").unwrap();
        let put = d.handle(
            &peer(),
            RequestBody::PutKey {
                name: k.clone(),
                meta: KeyMeta {
                    name: k.clone(),
                    mode: Mode::Run,
                    tier,
                    created_unix_ms: 1,
                },
            },
            Some(SecretBytes::new(VALUE.as_bytes().to_vec())),
        );
        assert!(matches!(put, ResponseBody::Ok { .. }), "{put:?}");
        let tier_s = match tier {
            Tier::Test => "test",
            Tier::Production => "production",
        };
        let rule = format!(
            "version = 1\n[keys.\"svc/test\"]\nmode = \"run\"\ntier = \"{tier_s}\"\nroots = [\"{}\"]\n{rule_body}\n",
            root.display()
        );
        // Loosening needs the person's approval (L11): answer it as they would in ms approve.
        let decider = answer(&d, true, None);
        let saved = d.handle(
            &peer(),
            RequestBody::RulesProposeLoosen {
                key: k,
                rule: Some(rule),
                at_terminal: false,
            },
            None,
        );
        assert!(matches!(decider.join().unwrap(), ResponseBody::Ok { .. }));
        assert!(matches!(saved, ResponseBody::Ok { .. }), "{saved:?}");
        *who.lock().unwrap() = Some(Caller::Agent(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
            started_unix_ms: 1,
        }));
        (d, dir, root)
    }

    fn buffered(
        rt: &tokio::runtime::Runtime,
        d: &Arc<Daemon>,
        root: &Path,
        argv: &[&str],
        env: &[(&str, &str)],
    ) -> ResponseBody {
        let d = d.clone();
        let root = root.to_path_buf();
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let env: Vec<RunEnv> = env
            .iter()
            .map(|(n, v)| RunEnv {
                name: n.to_string(),
                value: v.to_string(),
            })
            .collect();
        rt.block_on(async move {
            tokio::task::spawn_blocking(move || {
                d.handle(
                    &peer(),
                    RequestBody::Run {
                        argv,
                        cwd: root,
                        env,
                    },
                    None,
                )
            })
            .await
            .unwrap()
        })
    }

    pub(crate) fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    // protects=security review S1: a value goes only into a variable the key's rule names, and
    // only as the whole value; a variable that holds no run-mode ref (CURL_HOME=…/ms://zz/h, the
    // agent's config dir) never reaches the child; fails_when=any of those reaches the child
    // or runs; no_claim=what the tool does with an allowed variable
    #[test]
    fn env_only_as_the_rule_names_it() {
        let rt = rt();
        let (d, _dir, root) = test_daemon("commands = [[\"env\"]]\nenv = [\"TOKEN\"]");
        let out = |r: ResponseBody| match r {
            ResponseBody::RunResult { stdout, .. } => {
                String::from_utf8(ms_ipc::b64_decode(&stdout).unwrap()).unwrap()
            }
            other => panic!("{other:?}"),
        };
        let o = out(buffered(
            &rt,
            &d,
            &root,
            &["env"],
            &[("TOKEN", "ms://svc/test"), ("CURL_HOME", "/proj/ms://zz/h")],
        ));
        assert!(o.contains("TOKEN=[redacted ms://svc/test]"), "{o}");
        assert!(!o.contains("CURL_HOME") && !o.contains(VALUE), "{o}");
        for env in [
            [("TOKEN", "Bearer ms://svc/test")],
            [("TOKEN", "ms://svc/test#x")],
            [("OTHER", "ms://svc/test")],
            [("CURL_HOME", "/x/ms://svc/test")],
        ] {
            let r = buffered(&rt, &d, &root, &["env"], &env);
            assert!(
                matches!(
                    &r,
                    ResponseBody::Error {
                        code: ErrorCode::Denied | ErrorCode::Invalid,
                        ..
                    }
                ),
                "{env:?}: {r:?}"
            );
        }
    }

    // protects=security review S3: `ms stop` kills a run in progress (and a later run is
    // refused); fails_when=the command runs to completion after the stop; no_claim=-
    #[test]
    fn stop_kills_a_running_command() {
        let rt = rt();
        let (d, _dir, root) = test_daemon("commands = [[\"sleep\", \"30\"]]\nenv = [\"TOKEN\"]");
        let d2 = d.clone();
        let started = std::time::Instant::now();
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            d2.handle(&peer(), RequestBody::Stop, None)
        });
        let r = buffered(
            &rt,
            &d,
            &root,
            &["sleep", "30"],
            &[("TOKEN", "ms://svc/test")],
        );
        assert!(matches!(stopper.join().unwrap(), ResponseBody::Ok { .. }));
        assert!(
            matches!(&r, ResponseBody::Error { code: ErrorCode::Denied, message } if message.contains("killed")),
            "{r:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    // protects=receipt targets are escaped and bounded, so an agent's argv can't inject lines or
    // flood the log; fails_when=a newline/ESC survives or the length is unbounded; no_claim=-
    #[test]
    fn target_is_bounded() {
        let t = target_of(&["x\n\u{1b}[2J".into(), "y".repeat(5000)]);
        assert!(!t.contains('\n') && !t.contains('\u{1b}'));
        assert!(t.chars().count() <= TARGET_MAX * 6 + 1);
    }
}
