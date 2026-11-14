//! A throwaway Postgres for tests (feature `pg-test`, and this crate's own tests).
//!
//! `initdb` into a temp dir, start on a free loopback port with the socket in that dir, stop
//! (`-m immediate`) on drop. Needs `postgres`, `initdb`, `pg_ctl` and `psql` in one directory:
//! `$MORSEC_TEST_PG_BIN`, Postgres.app, Homebrew's `postgresql@N`, Debian's
//! `/usr/lib/postgresql/N/bin`, or `PATH`. [`Cluster::start`] returns `None` (and the caller
//! records "not verified") when there is none.
//!
//! Databases and roles made by [`Cluster::start`]:
//! - database `shop`, owned by `writer`: `orders(id, status, counter)` with rows 1–3, and
//!   `audited(id, n)` with a user trigger;
//! - `writer`: owns everything; `reader`: `SELECT` only; `sneaky`: `SELECT` only but a member of
//!   `writer` (so it can write through that membership); `split`: `SELECT` only in `shop` but
//!   `INSERT` on `other.t` (psql could `\c other`);
//! - `parent` ← `child` ← `grandchild` (cascading FKs; a user trigger on `grandchild`), a domain
//!   `posint`; `gauges.v` of domain `voldom` (CHECK calls a volatile function); `tagged.tag_id`
//!   → `tags` `ON DELETE SET DEFAULT` with a `nextval` default.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A running throwaway cluster.
#[derive(Debug)]
pub struct Cluster {
    dir: tempfile::TempDir,
    bin: PathBuf,
    port: u16,
    /// Per-cluster password suffix, so each run's passwords are fresh.
    tag: String,
}

const ADMIN_PW: &str = "admin-test-pw";

fn has_all(dir: &Path) -> bool {
    ["postgres", "initdb", "pg_ctl", "psql"]
        .iter()
        .all(|b| dir.join(b).is_file())
}

/// Where the Postgres server binaries are, if anywhere.
pub fn find_bin() -> Option<PathBuf> {
    let mut c: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("MORSEC_TEST_PG_BIN") {
        c.push(p.into());
    }
    c.push("/Applications/Postgres.app/Contents/Versions/latest/bin".into());
    for v in (13..=19).rev() {
        c.push(format!("/opt/homebrew/opt/postgresql@{v}/bin").into());
        c.push(format!("/usr/local/opt/postgresql@{v}/bin").into());
        c.push(format!("/usr/lib/postgresql/{v}/bin").into());
    }
    if let Some(path) = std::env::var_os("PATH") {
        c.extend(std::env::split_paths(&path));
    }
    c.into_iter()
        .find(|d| has_all(d))
        .and_then(|d| std::fs::canonicalize(d).ok())
}

impl Cluster {
    /// Starts a cluster, or `None` when no Postgres server is installed.
    pub fn start() -> Option<Self> {
        let bin = find_bin()?;
        let dir = tempfile::Builder::new().prefix("mspg").tempdir().ok()?;
        let pwfile = dir.path().join("pw");
        std::fs::write(&pwfile, ADMIN_PW).ok()?;
        let data = dir.path().join("data");
        let ok = Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(&data)
            .args([
                "-U",
                "admin",
                "--auth=scram-sha-256",
                "-E",
                "UTF8",
                "--no-sync",
            ])
            .arg(format!("--pwfile={}", pwfile.display()))
            .output()
            .ok()?;
        assert!(
            ok.status.success(),
            "initdb: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let st = Command::new(bin.join("pg_ctl"))
            .arg("-D")
            .arg(&data)
            .arg("-o")
            .arg(format!(
                "-p {port} -k {} -c listen_addresses=127.0.0.1 -c fsync=off",
                dir.path().display()
            ))
            .arg("-l")
            .arg(dir.path().join("log"))
            .args(["-w", "start"])
            .output()
            .ok()?;
        assert!(
            st.status.success(),
            "pg_ctl: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        let tag = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let c = Self {
            dir,
            bin,
            port,
            tag,
        };
        c.admin(
            "postgres",
            &format!(
                "CREATE ROLE writer LOGIN PASSWORD '{w}';
                 CREATE ROLE reader LOGIN PASSWORD '{r}';
                 CREATE ROLE sneaky LOGIN PASSWORD '{s}' IN ROLE writer;
                 CREATE ROLE split LOGIN PASSWORD '{x}';",
                w = c.password("writer"),
                r = c.password("reader"),
                s = c.password("sneaky"),
                x = c.password("split"),
            ),
        );
        c.admin("postgres", "CREATE DATABASE shop OWNER writer");
        c.admin(
            "shop",
            "SET ROLE writer;
             CREATE TABLE orders (id int PRIMARY KEY, status text NOT NULL, counter int NOT NULL);
             INSERT INTO orders VALUES (1, 'new', 0), (2, 'new', 0), (3, 'paid', 0);
             CREATE TABLE audited (id int PRIMARY KEY, n int NOT NULL);
             INSERT INTO audited VALUES (1, 0);
             CREATE FUNCTION audit_trg() RETURNS trigger LANGUAGE plpgsql AS
               $$ BEGIN RETURN NEW; END $$;
             CREATE TRIGGER audited_t BEFORE UPDATE ON audited FOR EACH ROW EXECUTE FUNCTION audit_trg();
             CREATE TABLE parent (id int PRIMARY KEY);
             CREATE TABLE child (id int PRIMARY KEY, parent_id int REFERENCES parent ON DELETE CASCADE);
             CREATE TABLE grandchild (id int PRIMARY KEY, child_id int REFERENCES child ON DELETE CASCADE);
             CREATE TRIGGER grandchild_t BEFORE DELETE ON grandchild FOR EACH ROW EXECUTE FUNCTION audit_trg();
             INSERT INTO parent VALUES (1);
             CREATE DOMAIN posint AS int CHECK (VALUE >= 0);
             CREATE FUNCTION vol_ok(int) RETURNS bool LANGUAGE plpgsql VOLATILE AS
               $$ BEGIN RETURN true; END $$;
             CREATE DOMAIN voldom AS int CHECK (vol_ok(VALUE));
             CREATE TABLE gauges (id int PRIMARY KEY, v voldom);
             CREATE TABLE secured (id int PRIMARY KEY);
             ALTER TABLE secured ENABLE ROW LEVEL SECURITY;
             CREATE TABLE tags (id int PRIMARY KEY);
             CREATE SEQUENCE tag_seq;
             CREATE TABLE tagged (id int PRIMARY KEY,
               tag_id int DEFAULT nextval('tag_seq') REFERENCES tags ON DELETE SET DEFAULT);
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader, sneaky, split;
             RESET ROLE;
             REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
        );
        // `split` can only read in shop, but can write in `other`.
        c.admin("postgres", "CREATE DATABASE other");
        c.admin(
            "other",
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC;
             CREATE TABLE t (id int); GRANT INSERT ON t TO split;",
        );
        // Databases with a non-built-in operator, or a user cast (here an explicit one), that a
        // filter could reach: every preview there is unknown.
        for (db, sql) in [
            (
                "userops",
                "CREATE TYPE e AS ENUM ('1');
                 CREATE FUNCTION f(int4, e) RETURNS bool LANGUAGE sql STABLE AS 'SELECT true';
                 CREATE OPERATOR ~~ (leftarg = int4, rightarg = e, function = f);",
            ),
            (
                "usercasts",
                "CREATE TYPE e AS ENUM ('1');
                 CREATE FUNCTION g(e) RETURNS int4 LANGUAGE sql VOLATILE AS 'SELECT 1';
                 CREATE CAST (e AS int4) WITH FUNCTION g(e);",
            ),
        ] {
            c.admin("postgres", &format!("CREATE DATABASE {db}"));
            c.admin(
                db,
                &format!(
                    "REVOKE CREATE ON SCHEMA public FROM PUBLIC; {sql}
                     CREATE TABLE t2 (id int); GRANT SELECT ON t2 TO writer;"
                ),
            );
        }
        Some(c)
    }

    /// The password of `role` in this cluster: has `@`, `:`, `/`, `%` and a backslash, to
    /// exercise URL and passfile escaping.
    pub fn password(&self, role: &str) -> String {
        format!("pw@{role}:x/y%z\\{}", self.tag)
    }

    /// `postgres://role:<password>@127.0.0.1:<port>/shop`, the password %-encoded.
    pub fn url(&self, role: &str) -> String {
        self.url_db(role, "shop")
    }

    /// Like [`Cluster::url`] for database `db`.
    pub fn url_db(&self, role: &str, db: &str) -> String {
        let pw: String = self
            .password(role)
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        format!("postgres://{role}:{pw}@127.0.0.1:{}/{db}", self.port)
    }

    /// The directory with `psql` and the server binaries.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Runs `sql` as the superuser in `db`; returns stdout (`-At`). Panics on failure.
    pub fn admin(&self, db: &str, sql: &str) -> String {
        let o = Command::new(self.bin.join("psql"))
            .env_clear()
            .env("PGPASSWORD", ADMIN_PW)
            .args([
                "-X",
                "-q",
                "-At",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "127.0.0.1",
            ])
            .arg("-p")
            .arg(self.port.to_string())
            .args(["-U", "admin", "-d", db, "-c", sql])
            .output()
            .expect("psql");
        assert!(
            o.status.success(),
            "admin SQL failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(self.dir.path().join("data"))
            .args(["-m", "immediate", "stop"])
            .output();
    }
}
