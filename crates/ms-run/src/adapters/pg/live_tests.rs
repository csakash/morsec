//! Live tests against a throwaway Postgres (SPEC "Verify"). One test function, so the scenarios
//! share one cluster and run one after another (the passfile directory is checked between them). They print whether they
//! ran ("VERIFIED" / "NOT VERIFIED") for the proof.
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ms_core::{AgentKind, KeyMeta, KeyName, Mode, SecretBytes, SessionId, Tier};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

use super::test_cluster::Cluster;
use super::{PsqlAdapter, probe, sql};
use crate::context::{CallContext, ContextAdapter, KeyFacts};
use crate::resolve::Resolver;
use crate::{RunInput, Runner, RunnerConfig};

struct Env {
    cluster: Cluster,
    vault: MemoryVault,
    runner: Runner,
    resolver: Resolver,
    cwd: PathBuf,
    _cwd_dir: tempfile::TempDir,
}

fn key(s: &str) -> KeyName {
    KeyName::new(s).unwrap()
}

fn session() -> SessionId {
    SessionId {
        agent: AgentKind::ClaudeCode,
        pid: 1,
        started_unix_ms: 1,
    }
}

impl Env {
    fn put(&self, name: &str, role: &str) {
        let k = key(name);
        self.vault
            .put(
                &k,
                SecretBytes::from(self.cluster.url(role)),
                KeyMeta {
                    name: k.clone(),
                    mode: Mode::Run,
                    tier: Tier::Production,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
    }

    fn ctx(&self, name: &str, read_only: bool) -> CallContext<'_> {
        CallContext {
            vault: &self.vault as &dyn Vault,
            keys: BTreeMap::from([(
                key(name),
                KeyFacts {
                    tier: Tier::Production,
                    read_only,
                },
            )]),
            env_keys: BTreeSet::new(),
        }
    }

    fn call(&self, argv: &[&str]) -> (RunInput, crate::RunCall) {
        let input = RunInput::new(
            argv.iter().map(|s| s.to_string()).collect(),
            self.cwd.clone(),
            Vec::new(),
        )
        .unwrap();
        let call = Runner::call(&input, self.cwd.clone(), session());
        (input, call)
    }

    /// Plans and runs; `Err` is the plan's refusal.
    fn run(
        &self,
        argv: &[&str],
        name: &str,
        read_only: bool,
    ) -> Result<(i32, String, String), String> {
        let (input, call) = self.call(argv);
        let ctx = self.ctx(name, read_only);
        let keys: BTreeSet<KeyName> = [key(name)].into();
        let prepared = self
            .runner
            .plan_in(&input, &call, &keys, &ctx)
            .map_err(|e| e.message)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (exit, out, err, _) = rt
            .block_on(self.runner.execute_buffered(prepared, 1 << 20))
            .unwrap();
        Ok((
            exit.shell_code(),
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        ))
    }

    fn counters(&self) -> String {
        self.cluster.admin(
            "shop",
            "SELECT string_agg(counter::text, ',' ORDER BY id) FROM orders",
        )
    }

    /// The morsec-pg passfile directory has no passfile left.
    fn no_passfiles(&self) {
        let p = std::env::temp_dir().join("morsec-pg");
        let left: Vec<_> = std::fs::read_dir(&p)
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "passfiles left behind: {left:?}");
    }
}

// protects=SPEC Verify 1–4 on a real server: a write on a read-only rule fails (GUC and
// privileges) and a role that can write is refused before psql starts; the password is never in
// any process's argv and the passfile is gone before the agent's first command; the preview
// counts rows and never commits, even when the statement smuggles a COMMIT past the lexer;
// fails_when=any of those regress; no_claim=the msd approval flow (msd run tests), other
// Postgres versions than the one installed
#[test]
fn live_postgres() {
    let Some(cluster) = Cluster::start() else {
        eprintln!("NOT VERIFIED: no Postgres server binaries found; live pg tests skipped");
        return;
    };
    let resolver = Resolver::new(vec![cluster.bin().to_path_buf()], Vec::new());
    let mut runner = Runner::new(RunnerConfig {
        resolver: resolver.clone(),
        base_env: Vec::new(),
        max_runtime: Duration::from_secs(60),
    });
    runner.register_contextual(Box::new(PsqlAdapter::new(resolver.clone())));
    let cwd_dir = tempfile::tempdir().unwrap();
    let env = Env {
        cluster,
        vault: MemoryVault::new(),
        runner,
        resolver,
        cwd: std::fs::canonicalize(cwd_dir.path()).unwrap(),
        _cwd_dir: cwd_dir,
    };
    env.put("pg/w", "writer");
    env.put("pg/r", "reader");
    env.put("pg/s", "sneaky");
    env.put("pg/x", "split");

    read_only_rules(&env);
    env.no_passfiles();
    password_never_in_argv(&env);
    env.no_passfiles();
    preview_never_commits(&env);
    env.no_passfiles();
    eprintln!(
        "VERIFIED: live pg tests ran against {}",
        env.cluster.bin().display()
    );
}

fn read_only_rules(env: &Env) {
    let before = env.counters();
    let (code, out, _) = env
        .run(
            &["psql", "ms://pg/r", "-Atc", "select count(*) from orders"],
            "pg/r",
            true,
        )
        .unwrap();
    assert_eq!((code, out.trim()), (0, "3"));

    let (code, _, err) = env
        .run(
            &[
                "psql",
                "ms://pg/r",
                "-c",
                "insert into orders values (9, 'x', 0)",
            ],
            "pg/r",
            true,
        )
        .unwrap();
    assert_ne!(code, 0);
    assert!(err.contains("read-only transaction"), "{err}");

    // Turning the GUC off doesn't help: the role has no write privilege.
    let (code, _, err) = env
        .run(
            &[
                "psql",
                "ms://pg/r",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "set default_transaction_read_only = off",
                "-c",
                "update orders set counter = 5",
            ],
            "pg/r",
            true,
        )
        .unwrap();
    assert_ne!(code, 0);
    assert!(err.contains("permission denied"), "{err}");

    // A role that can write (directly, through a membership, or in another database psql could
    // `\c` to) is refused before psql runs.
    for (k, who) in [("pg/w", "writer"), ("pg/s", "writer"), ("pg/x", "other")] {
        let e = env
            .run(&["psql", &format!("ms://{k}"), "-c", "select 1"], k, true)
            .unwrap_err();
        assert!(e.contains("read-only") && e.contains(who), "{k}: {e}");
    }
    assert_eq!(env.counters(), before, "a read-only run changed data");
}

fn password_never_in_argv(env: &Env) {
    let pw = env.cluster.password("writer");
    let encoded = env.cluster.url("writer");
    let encoded_pw = encoded
        .split_once("writer:")
        .and_then(|(_, r)| r.split_once('@'))
        .map(|(p, _)| p.to_owned())
        .unwrap();
    let port = env.cluster.port().to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let sampler = std::thread::spawn(move || {
        let mut seen = Vec::new();
        while !s.load(Ordering::SeqCst) {
            let o = std::process::Command::new("/bin/ps")
                .args(["-axww", "-o", "args="])
                .output()
                .unwrap();
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                if l.contains(&format!("127.0.0.1:{port}")) {
                    seen.push(l.to_owned());
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        seen
    });
    let (code, out, err) = env
        .run(
            &[
                "psql",
                "ms://pg/w",
                "-At",
                "-c",
                r#"\! ls "$PGPASSFILE" 2>&1 || echo passfile-gone"#,
                "-c",
                "select 'slept', pg_sleep(1.5)",
            ],
            "pg/w",
            false,
        )
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let seen = sampler.join().unwrap();
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("passfile-gone"),
        "the passfile was still there: {out}"
    );
    assert!(out.contains("slept"), "{out}");
    assert!(
        seen.iter()
            .any(|l| l.contains("postgres://writer@127.0.0.1")),
        "the sampler never saw psql: {seen:?}"
    );
    for l in &seen {
        assert!(
            !l.contains(&pw) && !l.contains(&encoded_pw),
            "password in argv: {l}"
        );
    }
    assert!(!out.contains(&pw) && !err.contains(&pw));
    eprintln!("ps samples with the psql child: {}", seen.len());
}

fn preview_never_commits(env: &Env) {
    let a = PsqlAdapter::new(env.resolver.clone());
    let before = env.counters();
    let preview = |argv: &[&str]| {
        let (_, call) = env.call(argv);
        a.preview(&call, &env.ctx("pg/w", false)).unwrap().summary
    };
    assert_eq!(
        preview(&[
            "psql",
            "ms://pg/w",
            "-c",
            "UPDATE orders SET counter = counter + 1 WHERE status = 'new'"
        ]),
        "2 rows in orders"
    );
    assert_eq!(
        preview(&[
            "psql",
            "ms://pg/w",
            "-c",
            "delete from orders where id = 3;"
        ]),
        "1 row in orders"
    );
    // Nothing is written, so triggers, cascades, defaults and constraints never run: tables
    // that have them preview like any other.
    assert_eq!(
        preview(&["psql", "ms://pg/w", "-c", "update audited set n = n + 1"]),
        "1 row in audited"
    );
    assert_eq!(
        preview(&["psql", "ms://pg/w", "-c", "delete from parent where id = 1"]),
        "1 row in parent"
    );
    assert_eq!(
        preview(&["psql", "ms://pg/w", "-c", "delete from tags where id = 1"]),
        "0 rows in tags"
    );
    // A column of a domain (or any non-built-in type) could run its input function or CHECK.
    let unknown = preview(&["psql", "ms://pg/w", "-c", "update gauges set v = 1"]);
    assert!(unknown.contains("outside pg_catalog"), "{unknown}");
    // A built-in function that runs SQL given as text, and a table with row security.
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "delete from orders where table_to_xml('orders', true, true, '') is not null",
    ]);
    assert!(unknown.contains("runs SQL"), "{unknown}");
    assert_eq!(
        preview(&[
            "psql",
            "ms://pg/w",
            "-c",
            "update orders set counter = 1 where status != 'paid'"
        ]),
        "2 rows in orders"
    );
    for (db, why) in [("userops", "operator"), ("usercasts", "casts")] {
        let k = format!("pg/{db}");
        let kk = key(&k);
        env.vault
            .put(
                &kk,
                SecretBytes::from(env.cluster.url_db("writer", db)),
                KeyMeta {
                    name: kk.clone(),
                    mode: Mode::Run,
                    tier: Tier::Production,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
        let (_, call) = env.call(&[
            "psql",
            &format!("ms://{k}"),
            "-c",
            "delete from t2 where id like '1'",
        ]);
        let u = a.preview(&call, &env.ctx(&k, false)).unwrap().summary;
        assert!(u.contains("unknown") && u.contains(why), "{db}: {u}");
    }
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "delete from secured where id = 1",
    ]);
    assert!(unknown.contains("row security"), "{unknown}");
    // The SET list is never evaluated; the WHERE clause is checked.
    assert_eq!(
        preview(&[
            "psql",
            "ms://pg/w",
            "-c",
            "update orders set status = random()::text where id = 2"
        ]),
        "1 row in orders"
    );
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "update orders set counter = 1 where random() < 2",
    ]);
    assert!(
        unknown.contains("unknown") && unknown.contains("volatile"),
        "{unknown}"
    );
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "update orders set counter = 1 where counter = 1::posint",
    ]);
    assert!(unknown.contains("pg_catalog"), "{unknown}");
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "update orders set counter = 1 where counter = posint '1'",
    ]);
    assert!(unknown.contains("pg_catalog"), "{unknown}");
    assert_eq!(
        preview(&[
            "psql",
            "ms://pg/w",
            "-c",
            "update orders set counter = '4'::int4 where id = '1'::int4"
        ]),
        "1 row in orders"
    );
    let unknown = preview(&[
        "psql",
        "ms://pg/w",
        "-c",
        "update orders set counter = 1; commit",
    ]);
    assert!(unknown.contains("unknown"), "{unknown}");
    let unknown = preview(&["psql", "ms://pg/w"]);
    assert!(unknown.contains("unknown"), "{unknown}");
    let ro = a
        .preview(
            &env.call(&["psql", "ms://pg/r", "-c", "update orders set counter = 1"])
                .1,
            &env.ctx("pg/r", true),
        )
        .unwrap()
        .summary;
    assert!(ro.contains("read-only"), "{ro}");

    // Even if the lexer were fooled, the server side can't commit: a statement that closes the
    // CTE, commits and opens another runs inside the DO block, where COMMIT is an error.
    let url = super::url::PgUrl::parse(env.cluster.url("writer").as_bytes()).unwrap();
    let line = super::passfile_line(&url).unwrap();
    let t = probe::Target {
        psql: &env.cluster.bin().join("psql"),
        path_var: env.resolver.path_var(),
        url: url.rewritten(false),
        passfile_line: line.as_deref().map(|l| l.as_slice()),
    };
    // Even if the lexer were fooled, the server side can't write: the filter runs as text inside
    // a DO block in a READ ONLY transaction, where COMMIT and writes are errors.
    for filter in [
        "true; COMMIT; DELETE FROM orders",
        "true; UPDATE orders SET counter = 100",
        "id IN (SELECT id FROM (DELETE FROM orders RETURNING id) d)",
        "nextval('tag_seq') > 0",
    ] {
        let smuggled = sql::Simple {
            table: "orders".into(),
            only: false,
            filter: Some(filter.into()),
            functions: Vec::new(),
            operators: Vec::new(),
            casts: Vec::new(),
        };
        let r = probe::preview(&t, &smuggled);
        assert!(r.is_err(), "{filter}: {r:?}");
        eprintln!("smuggled filter {filter:?}: {r:?}");
    }
    assert_eq!(
        env.cluster.admin("shop", "SELECT is_called FROM tag_seq"),
        "f",
        "a preview advanced a sequence"
    );
    assert_eq!(env.counters(), before, "a preview committed");
}
