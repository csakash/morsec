//! morsec's own psql runs: the read-only role check (SPEC D3) and the effect preview (D5).
//!
//! Both are fixed scripts fed on stdin to the trusted psql, with the key's URL (no password) and
//! a passfile of their own. Values that come from the agent (the statement, its table, function
//! and operator names) are passed as psql variables and reach the server only as quoted
//! literals (`:'name'`), never through psql's statement splitter.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::passfile::Passfile;

/// Longest a probe may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Most output bytes read from a probe.
const PROBE_OUTPUT: u64 = 64 * 1024;

/// The read-only role check: prints `ok`, or why the login role (or a role it can act as) can
/// write.
pub const ROLE_CHECK: &str = r#"\set ON_ERROR_STOP 1
WITH r AS (
  SELECT oid, rolname, rolsuper, rolcreaterole, rolcreatedb
  FROM pg_roles WHERE pg_has_role(current_user, oid, 'MEMBER')
)
SELECT coalesce((SELECT reason FROM (
  SELECT 1 AS o, format('role %I is a superuser', rolname) AS reason FROM r WHERE rolsuper
  UNION ALL SELECT 2, format('role %I can create roles', rolname) FROM r WHERE rolcreaterole
  UNION ALL SELECT 3, format('role %I can create databases', rolname) FROM r WHERE rolcreatedb
  UNION ALL SELECT 4, format('the login role is a member of %I', rolname) FROM r
    WHERE rolname IN ('pg_write_all_data', 'pg_write_server_files', 'pg_execute_server_program')
  UNION ALL SELECT 5, format('role %I can create schemas in this database', r.rolname) FROM r
    WHERE has_database_privilege(r.oid, current_database(), 'CREATE')
  UNION ALL SELECT 6, format('role %I can create objects in schema %I', r.rolname, n.nspname)
    FROM r, pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
      AND has_schema_privilege(r.oid, n.oid, 'CREATE')
  UNION ALL SELECT 7, format('role %I can write %I.%I', r.rolname, n.nspname, c.relname)
    FROM r, pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
      AND (has_table_privilege(r.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
           OR has_any_column_privilege(r.oid, c.oid, 'INSERT, UPDATE'))
  UNION ALL SELECT 8, format('role %I can advance sequence %I.%I', r.rolname, n.nspname, c.relname)
    FROM r, pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'S' AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
      AND has_sequence_privilege(r.oid, c.oid, 'UPDATE, USAGE')
  -- Every owned object, of any kind (pg_shdepend 'o'): in this database, and shared ones
  -- (databases, tablespaces). An owner can alter or drop what it owns, CASCADE included.
  UNION ALL SELECT 9, format('role %I owns objects (it could alter or drop them)', r.rolname) FROM r
    WHERE EXISTS (SELECT 1 FROM pg_shdepend s
                  WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = r.oid
                    AND s.deptype = 'o'
                    AND s.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
                    -- Temporary tables another session of this role holds are not a write path.
                    AND NOT (s.classid = 'pg_class'::regclass AND EXISTS (
                      SELECT 1 FROM pg_class c WHERE c.oid = s.objid AND c.relpersistence = 't')))
) x ORDER BY o LIMIT 1), 'ok') AS morsec_role_check;
"#;

/// The databases the login role can connect to, each name hex-encoded on its own line.
pub const DATABASES: &str = r#"\set ON_ERROR_STOP 1
SELECT encode(convert_to(datname, 'UTF8'), 'hex') FROM pg_database
WHERE datallowconn AND has_database_privilege(datname, 'CONNECT') ORDER BY datname;
"#;

/// Most databases the read-only check visits.
pub const MAX_DATABASES: usize = 64;

/// The effect preview: counts the rows the statement's `WHERE` clause matches, in a read-only
/// transaction that is rolled back. The statement itself never runs. Prints `morsec-count=N`; a
/// refusal raises `morsec-why: …`.
pub const PREVIEW: &str = r#"\set ON_ERROR_STOP 1
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL standard_conforming_strings = on;
SELECT set_config('morsec.filter', :'filter', true), set_config('morsec.tbl', :'tbl', true),
  set_config('morsec.only', :'only', true), set_config('morsec.fns', :'fns', true),
  set_config('morsec.ops', :'ops', true), set_config('morsec.casts', :'casts', true) \g /dev/null
DO $morsec$
DECLARE
  t oid := to_regclass(current_setting('morsec.tbl'));
  filter text := current_setting('morsec.filter');
  fns text[] := array_remove(string_to_array(current_setting('morsec.fns'), ','), '');
  ops text[] := array_remove(string_to_array(current_setting('morsec.ops'), ' '), '');
  casts text[] := array_remove(string_to_array(current_setting('morsec.casts'), ','), '');
  q text;
  n bigint;
BEGIN
  IF t IS NULL THEN RAISE EXCEPTION 'morsec-why: the table was not found'; END IF;
  IF (SELECT relkind FROM pg_class WHERE oid = t) NOT IN ('r', 'p') THEN
    RAISE EXCEPTION 'morsec-why: the target is not a table'; END IF;
  -- Row security policies are evaluated by the count; foreign children would connect out.
  IF (SELECT relrowsecurity FROM pg_class WHERE oid = t) THEN
    RAISE EXCEPTION 'morsec-why: the table has row security'; END IF;
  IF EXISTS (WITH RECURSIVE kids(rel) AS (
               SELECT inhrelid FROM pg_inherits WHERE inhparent = t
               UNION SELECT i.inhrelid FROM pg_inherits i JOIN kids ON i.inhparent = kids.rel)
             SELECT 1 FROM kids JOIN pg_class c ON c.oid = kids.rel WHERE c.relkind NOT IN ('r', 'p')) THEN
    RAISE EXCEPTION 'morsec-why: the table has a child or partition that is not a plain table'; END IF;
  -- Column types decide which input functions the filter runs: built-in types, or enums (whose
  -- input and comparison functions are built in).
  IF EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_type y ON y.oid = a.atttypid
             JOIN pg_namespace n ON n.oid = y.typnamespace
             WHERE a.attrelid = t AND a.attnum > 0 AND NOT a.attisdropped
               AND n.nspname <> 'pg_catalog' AND y.typtype <> 'e') THEN
    RAISE EXCEPTION 'morsec-why: the table has a column of a type outside pg_catalog'; END IF;
  -- An untyped literal can resolve to any type, and an explicit or function-style cast
  -- (`m::int4`, `int4(m)`, `to_json(m)`) can pick a user cast: every cast in the database must
  -- be built in.
  IF EXISTS (SELECT 1 FROM pg_cast c
             LEFT JOIN pg_proc p ON p.oid = c.castfunc
             WHERE (c.oid >= 16384
                    OR (p.oid IS NOT NULL AND (p.pronamespace <> 'pg_catalog'::regnamespace
                                               OR p.provolatile = 'v')))) THEN
    RAISE EXCEPTION 'morsec-why: the database has casts that are not built in'; END IF;
  -- Functions: built-in, not volatile, never one that runs SQL given as text.
  IF EXISTS (SELECT 1 FROM unnest(fns) f WHERE NOT EXISTS (
               SELECT 1 FROM pg_proc p WHERE p.proname = f AND p.pronamespace = 'pg_catalog'::regnamespace)) THEN
    RAISE EXCEPTION 'morsec-why: its WHERE clause calls a function that is not built in'; END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p WHERE p.proname = ANY (fns)
             AND (p.provolatile = 'v' OR p.pronamespace <> 'pg_catalog'::regnamespace
                  OR p.proname LIKE '%to\_xml%' OR p.proname IN ('ts_stat'))) THEN
    RAISE EXCEPTION 'morsec-why: its WHERE clause calls a volatile function, one that runs SQL, or one that is not built in'; END IF;
  -- Operators: the ones written, plus every comparison and pattern operator (implied by IN,
  -- NOT IN, BETWEEN, LIKE, CASE, …). Every operator with one of those names, whatever its
  -- argument types, must be built in and not volatile.
  IF EXISTS (SELECT 1 FROM unnest(ops) o WHERE NOT EXISTS (SELECT 1 FROM pg_operator WHERE oprname = o)) THEN
    RAISE EXCEPTION 'morsec-why: an operator in its WHERE clause is not known'; END IF;
  IF EXISTS (SELECT 1 FROM pg_operator o JOIN pg_proc p ON p.oid = o.oprcode
             WHERE o.oprname = ANY (ops || ARRAY['=', '<>', '<', '>', '<=', '>=', '~~', '~~*',
                                                  '!~~', '!~~*', '~', '~*', '!~', '!~*'])
               AND (p.provolatile = 'v' OR p.pronamespace <> 'pg_catalog'::regnamespace
                    OR o.oprnamespace <> 'pg_catalog'::regnamespace)) THEN
    RAISE EXCEPTION 'morsec-why: an operator its WHERE clause may use is volatile or not built in'; END IF;
  IF EXISTS (SELECT 1 FROM unnest(casts) c WHERE to_regtype(c) IS NULL OR NOT EXISTS (
               SELECT 1 FROM pg_type y JOIN pg_namespace n ON n.oid = y.typnamespace
               WHERE y.oid = to_regtype(c) AND n.nspname = 'pg_catalog')) THEN
    RAISE EXCEPTION 'morsec-why: its WHERE clause casts to a type outside pg_catalog'; END IF;
  q := 'SELECT count(*) FROM '
    || CASE WHEN current_setting('morsec.only') = 'on' THEN 'ONLY ' ELSE '' END
    || t::regclass::text;
  IF filter <> '' THEN q := q || ' WHERE ' || filter; END IF;
  EXECUTE q INTO n;
  PERFORM set_config('morsec.count', n::text, true);
END
$morsec$;
SELECT 'morsec-count=' || current_setting('morsec.count');
ROLLBACK;
"#;

/// What a probe printed.
#[derive(Debug)]
pub struct Output {
    /// Exit status was success.
    pub ok: bool,
    /// Stdout.
    pub stdout: String,
    /// Stderr.
    pub stderr: String,
}

/// A connection for probes: the URL without its password, and the password (if any) to put in
/// a fresh passfile for each probe.
pub struct Target<'a> {
    /// The psql to run.
    pub psql: &'a Path,
    /// `PATH` for it.
    pub path_var: OsString,
    /// URL without a password.
    pub url: String,
    /// Passfile line, when the URL had a password.
    pub passfile_line: Option<&'a [u8]>,
}

impl std::fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("psql", &self.psql)
            .field("url", &self.url)
            .field("passfile_line", &self.passfile_line.map(|_| "[hidden]"))
            .finish_non_exhaustive()
    }
}

/// Runs `script` with `vars` against `t`.
pub fn run(t: &Target<'_>, script: &str, vars: &[(&str, &str)]) -> Result<Output, String> {
    let passfile = match t.passfile_line {
        Some(l) => Some(Passfile::create(l)?),
        None => None,
    };
    let mut cmd = Command::new(t.psql);
    cmd.env_clear()
        .env("PATH", &t.path_var)
        .env("PGAPPNAME", "morsec-check")
        .args([
            "-X",
            "-q",
            "-A",
            "-t",
            "--no-readline",
            "-v",
            "ON_ERROR_STOP=1",
        ]);
    if let Some(h) = std::env::var_os("HOME") {
        // ~/.postgresql holds the user's TLS roots and client certificates.
        cmd.env("HOME", h);
    }
    if let Some(p) = &passfile {
        cmd.env("PGPASSFILE", p.path());
    }
    for (k, v) in vars {
        cmd.arg("-v").arg(format!("{k}={v}"));
    }
    cmd.arg("-d")
        .arg(&t.url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", t.psql.display()))?;
    let mut stdin = child.stdin.take();
    let script = script.to_owned();
    let writer = std::thread::spawn(move || {
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(script.as_bytes());
        }
    });
    let reader = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(r) = r {
                let _ = r.take(PROBE_OUTPUT).read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "psql took longer than {} s",
                    PROBE_TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("waiting for psql failed: {e}")),
        }
    };
    drop(passfile);
    let _ = writer.join();
    Ok(Output {
        ok: status.success(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// The first `ERROR:` line of psql's stderr, without the prefix.
pub fn first_error(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find_map(|l| l.split_once("ERROR:").map(|(_, m)| m.trim()))
}

/// Runs the role check: `Ok(())` when the role can't write.
pub fn role_check(t: &Target<'_>) -> Result<(), String> {
    let o = run(t, ROLE_CHECK, &[])?;
    let answer = o.stdout.trim();
    if o.ok && answer == "ok" {
        return Ok(());
    }
    if o.ok && !answer.is_empty() {
        return Err(format!(
            "the key's rule is read-only, but {}. Use a role that can only read (for example one granted pg_read_all_data and nothing else)",
            crate::printable(answer)
        ));
    }
    Err(format!(
        "the key's rule is read-only and morsec could not check that its role can only read ({})",
        crate::printable(first_error(&o.stderr).unwrap_or("the check failed"))
    ))
}

/// The databases the role behind `t` can connect to.
pub fn databases(t: &Target<'_>) -> Result<Vec<String>, String> {
    let o = run(t, DATABASES, &[])?;
    if !o.ok {
        return Err(format!(
            "morsec could not list the databases the role can connect to ({})",
            crate::printable(first_error(&o.stderr).unwrap_or("the query failed"))
        ));
    }
    let mut out = Vec::new();
    for l in o.stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let bytes: Option<Vec<u8>> = (0..l.len())
            .step_by(2)
            .map(|i| l.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
            .collect();
        let name = bytes
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or("the database list was not what morsec expected")?;
        out.push(name);
    }
    if out.len() > MAX_DATABASES {
        return Err(format!(
            "the role can connect to {} databases; morsec checks at most {MAX_DATABASES} for read-only access",
            out.len()
        ));
    }
    Ok(out)
}

/// Runs the preview of `s`: the row count, or why it is unknown.
pub fn preview(t: &Target<'_>, s: &super::sql::Simple) -> Result<u64, String> {
    let fns = s.functions.join(",");
    let ops = s.operators.join(" ");
    let casts = s.casts.join(",");
    let o = run(
        t,
        PREVIEW,
        &[
            ("filter", s.filter.as_deref().unwrap_or("")),
            ("tbl", &s.table),
            ("only", if s.only { "on" } else { "" }),
            ("fns", &fns),
            ("ops", &ops),
            ("casts", &casts),
        ],
    )?;
    if let Some(e) = first_error(&o.stderr) {
        if let Some(why) = e.strip_prefix("morsec-why: ") {
            return Err(why.to_owned());
        }
        return Err(format!(
            "the statement failed in the preview: {}",
            crate::printable(e)
        ));
    }
    let counts: Vec<&str> = o
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("morsec-count="))
        .collect();
    match (o.ok, counts.as_slice()) {
        (true, [n]) => n
            .parse()
            .map_err(|_| "the preview printed something unexpected".to_owned()),
        _ => Err("the preview didn't finish".to_owned()),
    }
}
