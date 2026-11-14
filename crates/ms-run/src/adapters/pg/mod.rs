//! Postgres adapters: `psql` and `prisma` (L15 SPEC).
//!
//! - [`PsqlAdapter`]: the key's ref is psql's connection argument. The URL is read from the
//!   vault and given to psql without its password; the password goes into a short-lived 0600
//!   passfile ([`passfile`]) and is redacted on its own. Read-only rules add
//!   `default_transaction_read_only=on` and first check that the role can't write
//!   ([`probe::role_check`]). Production writes get a `BEGIN … ROLLBACK` row-count preview
//!   ([`probe::preview`]).
//! - [`PrismaAdapter`]: Prisma takes the URL through L12's env channel; schema changes always
//!   need an approval and read-only keys allow only reading commands.
//!
//! Both are [`ContextAdapter`]s: they need the call's rule facts and refuse without them.

pub mod passfile;
pub mod prisma;
pub mod probe;
pub mod psql_args;
pub mod sql;
#[cfg(any(test, feature = "pg-test"))]
pub mod test_cluster;
pub mod url;

#[cfg(test)]
mod live_tests;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ms_core::{KeyName, Result, SecretRef};
use ms_vault::VaultExt;
use zeroize::Zeroizing;

use crate::context::{AdapterPlan, CallContext, ContextAdapter, KeyFacts};
use crate::error::{adapter_invalid, adapter_refuse};
use crate::resolve::Resolver;
use crate::{EffectPreview, EnvValue, ExecPlan, RunCall};

use passfile::Passfile;
use url::PgUrl;

fn utf8_argv(argv: &[OsString]) -> Result<Vec<String>> {
    argv.iter()
        .map(|a| a.to_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(|| adapter_invalid("an argument is not valid UTF-8"))
}

fn base_is(argv: &[OsString], name: &str) -> bool {
    argv.first()
        .and_then(|a| Path::new(a).file_name())
        .is_some_and(|n| n == name)
}

fn unknown(why: &str) -> EffectPreview {
    EffectPreview {
        summary: format!("rows changed: unknown ({why})"),
    }
}

/// The facts for `key`, or a refusal: a contextual adapter never guesses what a rule allows.
fn facts(ctx: &CallContext<'_>, key: &KeyName) -> Result<KeyFacts> {
    ctx.keys.get(key).copied().ok_or_else(|| {
        adapter_refuse(format!(
            "no rule facts were given for {key}, so the Postgres adapter refuses (fail closed)"
        ))
    })
}

/// A key's URL, parsed.
fn read_url(ctx: &CallContext<'_>, key: &KeyName) -> Result<PgUrl> {
    let value = ctx.vault.read_with(key, |b| Zeroizing::new(b.to_vec()))?;
    PgUrl::parse(&value).map_err(|m| adapter_refuse(format!("{key}: {m}")))
}

/// The passfile line for `url`, when it has a password.
fn passfile_line(url: &PgUrl) -> Result<Option<Zeroizing<Vec<u8>>>> {
    url.password()
        .map(|pw| passfile::line(&url.passfile_host(), url.user(), pw))
        .transpose()
        .map_err(adapter_refuse)
}

/// Runs the read-only role check for `url` with `psql`, in the URL's database and in every
/// other database the role can connect to: psql's `\c otherdb` reuses the password it already
/// has, so a role that can write anywhere on the server is refused.
fn check_read_only(resolver: &Resolver, psql: &Path, key: &KeyName, url: &PgUrl) -> Result<()> {
    let line = passfile_line(url)?;
    let target = |u: String| probe::Target {
        psql,
        path_var: resolver.path_var(),
        url: u,
        passfile_line: line.as_deref().map(|l| l.as_slice()),
    };
    let refuse = |m: String| adapter_refuse(format!("{key}: {m}"));
    let home = target(url.rewritten(true));
    probe::role_check(&home).map_err(refuse)?;
    for db in probe::databases(&home).map_err(refuse)? {
        probe::role_check(&target(url.rewritten_db(true, &db)))
            .map_err(|m| refuse(format!("in database {}: {m}", crate::printable(&db))))?;
    }
    Ok(())
}

/// `psql` with a key as its connection (SPEC D2, D3, D5).
#[derive(Debug, Clone)]
pub struct PsqlAdapter {
    resolver: Resolver,
}

impl PsqlAdapter {
    /// An adapter that resolves programs with `resolver`.
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    fn resolve(&self, argv0: &str) -> Result<PathBuf> {
        self.resolver
            .resolve(argv0)
            .map_err(|e| adapter_refuse(e.message.trim_start_matches("morsec: ")))
    }

    /// The checked args, the key's facts, and its URL.
    fn checked(
        &self,
        call: &RunCall,
        ctx: &CallContext<'_>,
    ) -> Result<(Vec<String>, psql_args::PsqlArgs, KeyFacts)> {
        let argv = utf8_argv(&call.argv)?;
        let args = psql_args::parse(&argv).map_err(adapter_refuse)?;
        let f = facts(ctx, &args.key)?;
        if !ctx.env_keys.is_empty() || ctx.keys.keys().any(|k| *k != args.key) {
            return Err(adapter_refuse(
                "psql takes a key only as its connection argument (psql ms://<key> …), not through an environment variable",
            ));
        }
        Ok((argv, args, f))
    }
}

impl ContextAdapter for PsqlAdapter {
    fn matches(&self, argv: &[OsString]) -> bool {
        base_is(argv, "psql")
    }

    fn plan(&self, call: &RunCall, ctx: &CallContext<'_>) -> Result<AdapterPlan> {
        let (argv, args, f) = self.checked(call, ctx)?;
        let program = self.resolve(&argv[0])?;
        let url = read_url(ctx, &args.key)?;
        if f.read_only {
            check_read_only(&self.resolver, &program, &args.key, &url)?;
        }
        let line = passfile_line(&url)?;
        let pass = line
            .as_deref()
            .map(|l| Passfile::create(l))
            .transpose()
            .map_err(adapter_refuse)?;
        let mut out: Vec<OsString> = vec!["-X".into()];
        for (i, a) in argv.iter().enumerate().skip(1) {
            if i == args.conn.index {
                out.push(format!("{}{}", args.conn.prefix, url.rewritten(f.read_only)).into());
            } else {
                out.push(a.into());
            }
        }
        let mut env = Vec::new();
        if let Some(p) = &pass {
            env.push((
                OsString::from("PGPASSFILE"),
                EnvValue::Plain(p.path().as_os_str().to_owned()),
            ));
        }
        let secrets = url
            .password()
            .map(|pw| vec![(args.key.clone(), Zeroizing::new(pw.to_vec()))])
            .unwrap_or_default();
        Ok(AdapterPlan {
            exec: ExecPlan {
                program,
                args: out,
                env,
                cwd: call.cwd.clone(),
            },
            secrets,
            guard: pass.map(|p| Box::new(p) as Box<dyn crate::context::RunGuard>),
        })
    }

    fn preview(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<EffectPreview> {
        let (argv, args, f) = match self.checked(call, ctx) {
            Ok(x) => x,
            Err(_) => return Some(unknown("the command would be refused")),
        };
        if f.read_only {
            return Some(unknown("the key is read-only, so a write would fail"));
        }
        let [cmd] = args.commands.as_slice() else {
            return Some(unknown(
                "interactive psql, a script or several -c: the statements aren't known in advance",
            ));
        };
        if args.files > 0 {
            return Some(unknown(
                "a script file: the statements aren't known in advance",
            ));
        }
        let simple = match sql::simple(cmd) {
            Ok(s) => s,
            Err(why) => return Some(unknown(why)),
        };
        let run = || -> std::result::Result<u64, String> {
            let program = self.resolver.resolve(&argv[0]).map_err(|e| e.message)?;
            let url = read_url(ctx, &args.key).map_err(|e| e.to_string())?;
            let line = passfile_line(&url).map_err(|e| e.to_string())?;
            let t = probe::Target {
                psql: &program,
                path_var: self.resolver.path_var(),
                url: url.rewritten(false),
                passfile_line: line.as_deref().map(|l| l.as_slice()),
            };
            probe::preview(&t, &simple)
        };
        Some(match run() {
            Ok(n) => EffectPreview {
                summary: format!(
                    "{n} row{} in {}",
                    if n == 1 { "" } else { "s" },
                    crate::printable(&simple.table)
                ),
            },
            Err(why) => unknown(&why),
        })
    }

    fn needs_approval(&self, _call: &RunCall, _ctx: &CallContext<'_>) -> Option<String> {
        None
    }
}

/// The Prisma CLI (SPEC D4).
#[derive(Debug, Clone)]
pub struct PrismaAdapter {
    resolver: Resolver,
}

impl PrismaAdapter {
    /// An adapter that resolves programs with `resolver`.
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    fn class(call: &RunCall) -> Option<prisma::Class> {
        let argv = utf8_argv(&call.argv).ok()?;
        let at = prisma::locate(&argv)?;
        Some(prisma::classify(&argv[at + 1..]))
    }
}

impl ContextAdapter for PrismaAdapter {
    fn matches(&self, argv: &[OsString]) -> bool {
        utf8_argv(argv)
            .ok()
            .is_some_and(|a| prisma::locate(&a).is_some())
    }

    fn plan(&self, call: &RunCall, ctx: &CallContext<'_>) -> Result<AdapterPlan> {
        let argv = utf8_argv(&call.argv)?;
        if argv.iter().any(|a| !SecretRef::find_all(a).is_empty()) {
            return Err(adapter_refuse(
                "a reference in a prisma argument would be visible to every process on this machine (ps); give Prisma the key through its URL variable instead, e.g. DATABASE_URL=ms://<key> prisma …",
            ));
        }
        if ctx.keys.is_empty() {
            return Err(adapter_refuse(
                "no rule facts were given for this prisma call, so the Postgres adapter refuses (fail closed)",
            ));
        }
        let Some(at) = prisma::locate(&argv) else {
            return Err(adapter_invalid("this isn't a prisma command"));
        };
        let class = prisma::classify(&argv[at + 1..]);
        for (key, f) in &ctx.keys {
            if !f.read_only {
                continue;
            }
            if let prisma::Class::Write(what) | prisma::Class::Schema(what) = &class {
                return Err(adapter_refuse(format!(
                    "{key} is read-only, and {what} can write to the database"
                )));
            }
            let psql = self.resolver.resolve("psql").map_err(|_| {
                adapter_refuse(format!(
                    "{key} is read-only, and morsec needs psql (in the trusted search path) to check its role can only read"
                ))
            })?;
            check_read_only(&self.resolver, &psql, key, &read_url(ctx, key)?)?;
        }
        let program = self
            .resolver
            .resolve(&argv[0])
            .map_err(|e| adapter_refuse(e.message.trim_start_matches("morsec: ")))?;
        Ok(AdapterPlan {
            exec: ExecPlan {
                program,
                args: argv[1..].iter().map(OsString::from).collect(),
                env: Vec::new(),
                cwd: call.cwd.clone(),
            },
            secrets: Vec::new(),
            guard: None,
        })
    }

    fn preview(&self, call: &RunCall, _ctx: &CallContext<'_>) -> Option<EffectPreview> {
        Some(match Self::class(call)? {
            prisma::Class::ReadOnly => unknown("a prisma command that only reads"),
            prisma::Class::Write(w) => unknown(&format!("{w} writes data morsec can't count")),
            prisma::Class::Schema(w) => unknown(&format!(
                "{w} changes the schema; morsec can't count its effect"
            )),
        })
    }

    fn needs_approval(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<String> {
        match Self::class(call)? {
            // A read-only key refuses it in `plan` anyway; don't ask a person first (review R7).
            prisma::Class::Schema(_) if ctx.keys.values().any(|f| f.read_only) => None,
            prisma::Class::Schema(w) => Some(format!(
                "{w} changes the database schema, so it always needs an approval"
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RunInput, Runner, RunnerConfig};
    use ms_core::{AgentKind, KeyMeta, Mode, SecretBytes, SessionId, Tier};
    use ms_vault::Vault;
    use ms_vault::memory::MemoryVault;
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::PermissionsExt;

    struct T {
        runner: Runner,
        vault: MemoryVault,
        cwd: PathBuf,
        _d: tempfile::TempDir,
    }

    /// A runner whose only program directory holds a fake `prisma` (prints its args and
    /// whether DATABASE_URL is set) and nothing else (no psql).
    fn setup() -> T {
        let d = tempfile::tempdir().unwrap();
        let bin = std::fs::canonicalize(d.path()).unwrap().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fake = bin.join("prisma");
        std::fs::write(
            &fake,
            "#!/bin/sh\necho \"prisma-ran $*\"\necho \"url=$DATABASE_URL\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolver = Resolver::new(vec![bin, "/bin".into()], Vec::new());
        let mut runner = Runner::new(RunnerConfig {
            resolver: resolver.clone(),
            base_env: Vec::new(),
            max_runtime: std::time::Duration::from_secs(10),
        });
        runner.register_contextual(Box::new(PsqlAdapter::new(resolver.clone())));
        runner.register_contextual(Box::new(PrismaAdapter::new(resolver)));
        let vault = MemoryVault::new();
        let k = KeyName::new("pg/x").unwrap();
        vault
            .put(
                &k,
                SecretBytes::from("postgres://u:VERYSECRETPW@127.0.0.1:1/db".to_owned()),
                KeyMeta {
                    name: k.clone(),
                    mode: Mode::Run,
                    tier: Tier::Test,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
        T {
            runner,
            vault,
            cwd: std::fs::canonicalize(d.path()).unwrap(),
            _d: d,
        }
    }

    impl T {
        fn plan(
            &self,
            argv: &[&str],
            env: &[(&str, &str)],
            read_only: bool,
        ) -> (
            std::result::Result<crate::Prepared, crate::RunError>,
            Option<String>,
        ) {
            let input = RunInput::new(
                argv.iter().map(|s| s.to_string()).collect(),
                self.cwd.clone(),
                env.iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            )
            .unwrap();
            let call = Runner::call(
                &input,
                self.cwd.clone(),
                SessionId {
                    agent: AgentKind::ClaudeCode,
                    pid: 1,
                    started_unix_ms: 1,
                },
            );
            let k = KeyName::new("pg/x").unwrap();
            let ctx = CallContext {
                vault: &self.vault,
                keys: BTreeMap::from([(
                    k.clone(),
                    KeyFacts {
                        tier: Tier::Test,
                        read_only,
                    },
                )]),
                // Deliberately empty: plan_in must take it from the input.
                env_keys: BTreeSet::new(),
            };
            let keys = BTreeSet::from([k]);
            let esc = self.runner.needs_approval(&call, &ctx);
            (self.runner.plan_in(&input, &call, &keys, &ctx), esc)
        }

        fn output(&self, p: crate::Prepared) -> String {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (_, out, _, _) = rt.block_on(self.runner.execute_buffered(p, 4096)).unwrap();
            String::from_utf8(out).unwrap()
        }
    }

    // protects=SPEC D4 with a fake prisma (Verify 5): `migrate deploy` asks for an approval on
    // a test-tier key, also behind a runner whose options take values (`pnpm --filter api exec`,
    // review R5), and gets the URL only through DATABASE_URL, redacted in its output; on a
    // read-only key a schema change is refused without asking anyone (R7) and a reading command
    // needs psql for the role check; fails_when=a migration runs unasked, a read-only key runs a
    // write, or the URL shows; no_claim=Prisma itself
    #[test]
    fn prisma_with_a_fake_binary() {
        let t = setup();
        let env = [("DATABASE_URL", "ms://pg/x")];
        let (p, esc) = t.plan(&["prisma", "migrate", "deploy"], &env, false);
        assert!(esc.is_some_and(|w| w.contains("schema")));
        let out = t.output(p.unwrap());
        assert!(out.contains("prisma-ran migrate deploy"), "{out}");
        assert!(
            out.contains("url=[redacted") && !out.contains("VERYSECRETPW"),
            "{out}"
        );

        let (_, esc) = t.plan(
            &[
                "pnpm", "--filter", "api", "exec", "prisma", "migrate", "deploy",
            ],
            &env,
            false,
        );
        assert!(
            esc.is_some(),
            "pnpm with a valued option slipped past the prisma adapter"
        );
        let (_, esc) = t.plan(&["prisma", "generate"], &env, false);
        assert!(esc.is_none());

        let (p, esc) = t.plan(&["prisma", "migrate", "deploy"], &env, true);
        assert!(
            esc.is_none(),
            "asked a person for a command that will be refused"
        );
        let e = p.unwrap_err().message;
        assert!(e.contains("read-only"), "{e}");
        let (p, _) = t.plan(&["prisma", "migrate", "status"], &env, true);
        let e = p.unwrap_err().message;
        assert!(e.contains("needs psql"), "{e}");
        let (p, _) = t.plan(&["prisma", "migrate", "status", "ms://pg/x"], &[], false);
        assert!(p.is_err());
    }

    // protects=SPEC D2 / review R2: psql refuses a key forwarded through the environment, even
    // the same key as its connection argument and even when the caller's context says there is
    // none; review R10: a read-only key never reaches the generic adapter; fails_when=the full
    // URL reaches psql's environment or a read-only key runs an arbitrary tool; no_claim=-
    #[test]
    fn psql_env_refs_and_generic_read_only_refused() {
        let t = setup();
        let (p, _) = t.plan(
            &["psql", "ms://pg/x", "-c", "select 1"],
            &[("DATABASE_URL", "ms://pg/x")],
            false,
        );
        let e = p.unwrap_err().message;
        assert!(e.contains("environment variable"), "{e}");
        let (p, _) = t.plan(&["echo", "hi"], &[("TOKEN", "ms://pg/x")], true);
        let e = p.unwrap_err().message;
        assert!(e.contains("read-only"), "{e}");
        let (p, _) = t.plan(&["echo", "hi"], &[("TOKEN", "ms://pg/x")], false);
        assert!(p.is_ok());
    }
}
