//! The runner: turns an allowed call into an exec plan and runs it (SPEC D3–D5, D10).
//!
//! Policy is not decided here; msd does that (rules, approvals, receipts) and then calls
//! [`Runner::plan`] with the run-mode keys it allowed, and [`Runner::execute`].
//!
//! - The adapter is the first registered one whose `matches` is true; the generic adapter is
//!   the fallback. Every plan's program is re-checked here (absolute, regular, executable, not
//!   writable by others, not a shim), whichever adapter made it.
//! - The child's environment is built from nothing: the adapter's variables, then the minimal
//!   base set from msd ([`RunnerConfig::base_env`]), then the forwarded variables with run-mode
//!   refs replaced by values.
//! - The child runs in its own process group, with stdin, stdout and stderr piped. Output goes
//!   through one [`StreamRedactor`] per stream. When the child exits, when the run times out and
//!   when the run is cancelled (the future is dropped), the whole group is killed, so nothing
//!   holding a value outlives the run.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ms_core::{KeyName, SecretBytes, SecretRef, SessionId};
use ms_ipc::{OutStream, StdinEvent};
use ms_vault::{Vault, VaultExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::context::{AdapterPlan, CallContext, ContextAdapter, RunGuard};
use crate::error::{RunError, from_core};
use crate::generic::GenericAdapter;
use crate::input::RunInput;
use crate::redact::{Patterns, StreamRedactor};
use crate::resolve::Resolver;
use crate::{EffectPreview, EnvValue, ExecPlan, RunAdapter, RunCall};

/// Longest a run may take by default; the IPC connection lifetime (10 min) is the outer bound.
pub const DEFAULT_MAX_RUNTIME: Duration = Duration::from_secs(590);
/// How long a read of the child's output may wait once the child exited and its group was killed
/// (time spent sending output to a slow client is not counted).
pub const EXIT_GRACE: Duration = Duration::from_secs(2);
/// Bytes read from the child's output per step.
pub const OUTPUT_CHUNK: usize = 32 * 1024;
/// Variables copied from msd's own environment into every child, when set.
pub const BASE_ENV: &[&str] = &["HOME", "USER", "LOGNAME", "LANG", "TMPDIR"];

/// How the runner is set up.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Finds programs.
    pub resolver: Resolver,
    /// The base environment every child gets (besides `PATH`, which is the resolver's).
    pub base_env: Vec<(OsString, OsString)>,
    /// Longest a run may take.
    pub max_runtime: Duration,
}

impl RunnerConfig {
    /// The trusted search path and [`BASE_ENV`] from this process's (msd's) environment.
    pub fn from_process_env() -> Self {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .filter(|h| h.is_absolute());
        let base_env = BASE_ENV
            .iter()
            .filter_map(|k| {
                std::env::var_os(k)
                    .filter(|v| !v.is_empty())
                    .map(|v| (OsString::from(k), v))
            })
            .collect();
        Self {
            resolver: Resolver::trusted(home.as_deref()),
            base_env,
            max_runtime: DEFAULT_MAX_RUNTIME,
        }
    }
}

/// A plan ready to run, with the redaction patterns for its values. `Debug` shows no value.
#[derive(Debug)]
pub struct Prepared {
    plan: ExecPlan,
    arg0: OsString,
    patterns: Arc<Patterns>,
    /// A contextual adapter's guard, dropped when the run ends (L15).
    guard: Option<Box<dyn RunGuard>>,
}

impl Prepared {
    /// The program that will run.
    pub fn program(&self) -> &Path {
        &self.plan.program
    }

    /// The patterns output is redacted with.
    pub fn patterns(&self) -> Arc<Patterns> {
        self.patterns.clone()
    }

    /// Names of the child's environment variables (values never).
    pub fn env_names(&self) -> Vec<String> {
        self.plan
            .env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }
}

/// The two directions of a run.
#[derive(Debug)]
pub struct ExecIo {
    /// Stdin. Closing the channel counts as the end of stdin.
    pub stdin: mpsc::Receiver<StdinEvent>,
    /// Redacted output chunks.
    pub output: mpsc::Sender<(OutStream, Vec<u8>)>,
}

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    /// Exit code.
    pub code: Option<i32>,
    /// Signal.
    pub signal: Option<i32>,
}

impl Exit {
    /// The code a shell would report: the exit code, or 128 + the signal.
    pub fn shell_code(&self) -> i32 {
        match (self.code, self.signal) {
            (Some(c), _) => c,
            (None, Some(s)) => 128 + s,
            (None, None) => 70,
        }
    }
}

/// See the module docs.
pub struct Runner {
    cfg: RunnerConfig,
    contextual: Vec<Box<dyn ContextAdapter>>,
    adapters: Vec<Box<dyn RunAdapter>>,
    generic: GenericAdapter,
}

/// The adapter chosen for a call.
enum Chosen<'a> {
    Contextual(&'a dyn ContextAdapter),
    Plain(&'a dyn RunAdapter),
}

impl std::fmt::Debug for Runner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runner")
            .field("cfg", &self.cfg)
            .field("contextual", &self.contextual.len())
            .field("adapters", &self.adapters.len())
            .finish()
    }
}

impl Runner {
    /// A runner with only the generic adapter.
    pub fn new(cfg: RunnerConfig) -> Self {
        let generic = GenericAdapter::new(cfg.resolver.clone());
        Self {
            cfg,
            contextual: Vec::new(),
            adapters: Vec::new(),
            generic,
        }
    }

    /// Adds an adapter, consulted before the generic one in the order added (L15, L16).
    /// Adapters should resolve programs with [`Runner::resolver`].
    pub fn register(&mut self, adapter: Box<dyn RunAdapter>) {
        self.adapters.push(adapter);
    }

    /// Adds a context-aware adapter (L15 SPEC D1), consulted before every frozen adapter, in
    /// the order added.
    pub fn register_contextual(&mut self, adapter: Box<dyn ContextAdapter>) {
        self.contextual.push(adapter);
    }

    /// The program resolver.
    pub fn resolver(&self) -> &Resolver {
        &self.cfg.resolver
    }

    /// The frozen `RunCall` for a checked input, run in `cwd` (the canonical directory).
    pub fn call(input: &RunInput, cwd: PathBuf, session: SessionId) -> RunCall {
        RunCall {
            argv: input.argv.iter().map(OsString::from).collect(),
            cwd,
            session,
        }
    }

    fn adapter(&self, argv: &[OsString]) -> Chosen<'_> {
        if let Some(a) = self.contextual.iter().find(|a| a.matches(argv)) {
            return Chosen::Contextual(&**a);
        }
        Chosen::Plain(
            self.adapters
                .iter()
                .find(|a| a.matches(argv))
                .map(|a| &**a)
                .unwrap_or(&self.generic),
        )
    }

    /// The adapter's effect preview, for the approval dialog. A contextual adapter gets no
    /// facts here; use [`Runner::preview_in`].
    pub fn preview(&self, call: &RunCall) -> Option<EffectPreview> {
        match self.adapter(&call.argv) {
            Chosen::Contextual(_) => None,
            Chosen::Plain(a) => a.preview(call),
        }
    }

    /// The adapter's effect preview with the call's rule facts and vault.
    pub fn preview_in(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<EffectPreview> {
        match self.adapter(&call.argv) {
            Chosen::Contextual(a) => a.preview(call, ctx),
            Chosen::Plain(a) => a.preview(call),
        }
    }

    /// `Some(why)` when the adapter says this call needs an approval whatever the key's tier
    /// (L15 SPEC D4). Frozen adapters never do.
    pub fn needs_approval(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<String> {
        match self.adapter(&call.argv) {
            Chosen::Contextual(a) => a.needs_approval(call, ctx),
            Chosen::Plain(_) => None,
        }
    }

    /// Builds the exec plan. `run_keys` are the run-mode keys policy allowed for this call; refs
    /// to other keys are left as they are. A contextual adapter gets an empty context here (and
    /// refuses); msd uses [`Runner::plan_in`].
    pub fn plan(
        &self,
        input: &RunInput,
        call: &RunCall,
        run_keys: &BTreeSet<KeyName>,
        vault: &dyn Vault,
    ) -> Result<Prepared, RunError> {
        self.plan_in(input, call, run_keys, &CallContext::empty(vault))
    }

    /// [`Runner::plan`] with the call's rule facts, for contextual adapters (L15 SPEC D1).
    pub fn plan_in(
        &self,
        input: &RunInput,
        call: &RunCall,
        run_keys: &BTreeSet<KeyName>,
        ctx: &CallContext<'_>,
    ) -> Result<Prepared, RunError> {
        let vault = ctx.vault;
        // The adapter sees which keys travel in the environment from the input itself, not from
        // whatever the caller put in the context.
        let ctx = &CallContext {
            vault,
            keys: ctx.keys.clone(),
            env_keys: input.env_keys.clone(),
        };
        let AdapterPlan {
            exec: mut plan,
            secrets,
            guard,
        } = match self.adapter(&call.argv) {
            Chosen::Contextual(a) => a.plan(call, ctx),
            // Only a contextual adapter can enforce a read-only rule (L15 review R10).
            Chosen::Plain(_) if ctx.keys.values().any(|f| f.read_only) => {
                return Err(RunError::denied(
                    "morsec: this key's rule is read-only, and only the psql and prisma adapters can enforce that, so this command is refused",
                ));
            }
            Chosen::Plain(a) => a.plan(call, vault).map(|exec| AdapterPlan {
                exec,
                secrets: Vec::new(),
                guard: None,
            }),
        }
        .map_err(|e| from_core(&e))?;
        let program = plan
            .program
            .to_str()
            .filter(|p| p.starts_with('/'))
            .ok_or_else(|| RunError::internal("morsec: the run adapter chose no absolute program"))?
            .to_owned();
        plan.program = self.cfg.resolver.resolve(&program)?;
        if plan.cwd != call.cwd {
            return Err(RunError::internal(
                "morsec: the run adapter changed the working directory",
            ));
        }

        // Each value is read once, kept in a zeroizing buffer for this call, and wiped when
        // the plan is built.
        let mut values: BTreeMap<KeyName, Zeroizing<Vec<u8>>> = BTreeMap::new();
        for k in input.keys().intersection(run_keys) {
            let v = vault
                .read_with(k, |b| Zeroizing::new(b.to_vec()))
                .map_err(|e| from_core(&e))?;
            values.insert(k.clone(), v);
        }
        let mut builder = Patterns::builder();
        for (k, v) in &values {
            builder.add(k, v);
        }
        for (k, v) in &secrets {
            builder.add(k, v);
        }

        let mut names: BTreeSet<OsString> = plan.env.iter().map(|(k, _)| k.clone()).collect();
        let path = (OsString::from("PATH"), self.cfg.resolver.path_var());
        for (k, v) in std::iter::once(path).chain(self.cfg.base_env.iter().cloned()) {
            if names.insert(k.clone()) {
                plan.env.push((k, EnvValue::Plain(v)));
            }
        }
        for (name, raw) in &input.env {
            if !names.insert(OsString::from(name)) {
                return Err(RunError::denied(format!(
                    "morsec: {name} is set by morsec for this command and can't carry a reference"
                )));
            }
            plan.env
                .push((OsString::from(name), substitute(raw, &values)));
        }
        Ok(Prepared {
            plan,
            arg0: OsString::from(&input.argv[0]),
            patterns: Arc::new(builder.build()),
            guard,
        })
    }

    /// Runs a prepared plan. Dropping the returned future kills the child's process group.
    pub async fn execute(&self, prepared: Prepared, io: ExecIo) -> Result<Exit, RunError> {
        let Prepared {
            plan,
            arg0,
            patterns,
            guard,
        } = prepared;
        // Kept until this function returns: the run is over (or was cancelled) by then.
        let _guard = guard;
        let mut cmd = tokio::process::Command::new(&plan.program);
        cmd.arg0(&arg0)
            .args(&plan.args)
            .env_clear()
            .current_dir(&plan.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        for (k, v) in &plan.env {
            match v {
                EnvValue::Plain(s) => cmd.env(k, s),
                EnvValue::Secret(b) => cmd.env(k, OsStr::from_bytes(b.expose())),
            };
        }
        let spawned = cmd.spawn();
        let shown = plan.program.display().to_string();
        // The plan's values are wiped here. (std's copy inside `Command` is freed, not wiped:
        // ARI42 GW-1 residual; the child holds the value anyway.)
        drop(cmd);
        drop(plan);
        let mut child = spawned
            .map_err(|e| RunError::internal(format!("morsec: could not start {shown}: {e}")))?;
        let group = GroupGuard::new(child.id());
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let ExecIo {
            stdin: mut input,
            output,
        } = io;

        let feed = async move {
            let mut w = stdin;
            while let Some(StdinEvent::Data(d)) = input.recv().await {
                if let Some(pipe) = w.as_mut()
                    && pipe.write_all(&d).await.is_err()
                {
                    // The child closed stdin; keep accepting (and dropping) input.
                    w = None;
                }
            }
            drop(w);
            std::future::pending::<()>().await
        };
        // Set once the child exited and its group was killed. From then on a pump waits at most
        // EXIT_GRACE for each read: a descendant that left the group (setsid) may hold the pipes
        // open. Time a pump spends handing output to a slow client doesn't count.
        let (exited_tx, exited_rx) = tokio::sync::watch::channel(false);
        let out = pump(
            stdout,
            OutStream::Stdout,
            patterns.clone(),
            output.clone(),
            exited_rx.clone(),
        );
        let err = pump(
            stderr,
            OutStream::Stderr,
            patterns,
            output.clone(),
            exited_rx,
        );
        let waited = async {
            let status = child.wait().await;
            // Background processes the command left behind would keep its environment (and
            // the value) alive, and keep the output pipes open.
            group.kill();
            let _ = exited_tx.send(true);
            status
        };
        let all = async { tokio::join!(waited, out, err).0 };
        let finished = tokio::time::timeout(self.cfg.max_runtime, async {
            tokio::select! {
                r = all => r,
                () = feed => unreachable!("the stdin feeder never finishes"),
            }
        })
        .await;
        match finished {
            Ok(status) => {
                use std::os::unix::process::ExitStatusExt;
                let st = status.map_err(|e| {
                    RunError::internal(format!("morsec: waiting for {shown} failed: {e}"))
                })?;
                Ok(Exit {
                    code: st.code(),
                    signal: st.signal(),
                })
            }
            Err(_) => {
                group.kill();
                let note = format!(
                    "\nmorsec: stopped {shown} after {} s (run-mode time limit)\n",
                    self.cfg.max_runtime.as_secs()
                );
                let _ = output.send((OutStream::Stderr, note.into_bytes())).await;
                Ok(Exit {
                    code: None,
                    signal: Some(9),
                })
            }
        }
    }

    /// Runs a prepared plan with no stdin and collects its output, each stream capped at
    /// `cap` bytes. Returns the exit, stdout, stderr and whether anything was cut.
    pub async fn execute_buffered(
        &self,
        prepared: Prepared,
        cap: usize,
    ) -> Result<(Exit, Vec<u8>, Vec<u8>, bool), RunError> {
        let (in_tx, in_rx) = mpsc::channel(1);
        drop(in_tx);
        let (out_tx, mut out_rx) = mpsc::channel::<(OutStream, Vec<u8>)>(16);
        let collect = async move {
            let (mut o, mut e, mut cut) = (Vec::new(), Vec::new(), false);
            while let Some((s, bytes)) = out_rx.recv().await {
                let buf = if s == OutStream::Stdout {
                    &mut o
                } else {
                    &mut e
                };
                let room = cap.saturating_sub(buf.len());
                if bytes.len() > room {
                    cut = true;
                }
                buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
            }
            (o, e, cut)
        };
        let run = self.execute(
            prepared,
            ExecIo {
                stdin: in_rx,
                output: out_tx,
            },
        );
        let (exit, (o, e, cut)) = tokio::join!(run, collect);
        Ok((exit?, o, e, cut))
    }
}

/// `raw` with every ref to a key in `values` replaced by its value. No ref to such a key: the
/// text as is.
fn substitute(raw: &str, values: &BTreeMap<KeyName, Zeroizing<Vec<u8>>>) -> EnvValue {
    let found: Vec<_> = SecretRef::find_all(raw)
        .into_iter()
        .filter(|(_, r)| values.contains_key(r.name()))
        .collect();
    if found.is_empty() {
        return EnvValue::Plain(OsString::from(raw));
    }
    let extra: usize = found
        .iter()
        .map(|(_, r)| values[r.name()].len())
        .sum::<usize>();
    // Sized up front so the buffer never reallocates and leaves an unwiped copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(raw.len() + extra));
    let mut pos = 0;
    for (range, r) in found {
        out.extend_from_slice(&raw.as_bytes()[pos..range.start]);
        out.extend_from_slice(&values[r.name()]);
        pos = range.end;
    }
    out.extend_from_slice(&raw.as_bytes()[pos..]);
    EnvValue::Secret(SecretBytes::new(std::mem::take(&mut *out)))
}

/// Reads one output stream through a redactor into `tx`. Stops when the stream ends, the
/// receiver is gone, or (after the child exited) no byte arrives within [`EXIT_GRACE`]; in that
/// last case a note on stderr says the output was cut.
async fn pump<R: AsyncRead + Unpin>(
    reader: Option<R>,
    stream: OutStream,
    patterns: Arc<Patterns>,
    tx: mpsc::Sender<(OutStream, Vec<u8>)>,
    mut exited: tokio::sync::watch::Receiver<bool>,
) {
    let Some(mut reader) = reader else { return };
    let mut red = StreamRedactor::new(patterns);
    let mut buf = Zeroizing::new(vec![0u8; OUTPUT_CHUNK]);
    let mut cut = false;
    loop {
        let read = if *exited.borrow() {
            match tokio::time::timeout(EXIT_GRACE, reader.read(&mut buf[..])).await {
                Ok(r) => r,
                Err(_) => {
                    cut = true;
                    break;
                }
            }
        } else {
            // `read` is cancel-safe: if the child exits first, nothing read is lost.
            tokio::select! {
                r = reader.read(&mut buf[..]) => r,
                _ = exited.changed() => continue,
            }
        };
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let out = red.push(&buf[..n]);
        if !out.is_empty() && tx.send((stream, out)).await.is_err() {
            return;
        }
    }
    let out = red.finish();
    if !out.is_empty() && tx.send((stream, out)).await.is_err() {
        return;
    }
    if cut {
        let note = "\nmorsec: output cut: the command exited but a process it started kept its output open\n";
        let _ = tx.send((OutStream::Stderr, note.as_bytes().to_vec())).await;
    }
}

/// Kills the child's process group when the run ends or is dropped.
struct GroupGuard {
    pgid: Option<rustix::process::Pid>,
    killed: AtomicBool,
}

impl GroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self {
            pgid: pid
                .and_then(|p| i32::try_from(p).ok())
                .and_then(rustix::process::Pid::from_raw),
            killed: AtomicBool::new(false),
        }
    }

    fn kill(&self) {
        if let Some(pgid) = self.pgid
            && !self.killed.swap(true, Ordering::SeqCst)
        {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}
