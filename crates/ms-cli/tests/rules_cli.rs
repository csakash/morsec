//! `ms rules` end to end, on the built binary.

use std::path::{Path, PathBuf};
use std::process::Command;

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

const RULES: &str = r#"
version = 4

[keys."stripe/test"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com", "*.stripe.com"]

[keys."pg/production"]
mode = "run"
tier = "production"
commands = [["psql", "-c", "*"], ["pg_dump", "**"]]
session_ttl_secs = 600
"#;

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo")).unwrap();
        std::fs::create_dir(dir.path().join("repo/.git")).unwrap();
        std::fs::write(dir.path().join("rules.toml"), RULES).unwrap();
        Self { dir }
    }
    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }
    fn repo(&self) -> PathBuf {
        self.path("repo")
    }
    /// Runs `ms rules --rules <fixture> <args>` in `cwd`; returns (code, stdout, stderr).
    fn run(&self, cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(ms())
            .arg("rules")
            .arg("--rules")
            .arg(self.path("rules.toml"))
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }
}

// protects=`ms rules` lists keys and `ms rules <name>` shows the rule, marked as not MAC-checked;
// fails_when=a key, mode, tier or target is missing, or the unverified label is absent;
// no_claim=MAC verification (msd does it, L07)
#[test]
fn list_and_show() {
    let f = Fixture::new();
    let (code, out, err) = f.run(&f.repo(), &[]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("rules version 4"), "{out}");
    assert!(
        out.contains("MAC not checked by ms; msd verifies it"),
        "{out}"
    );
    assert!(out.contains("project rules: none"), "{out}");
    assert!(
        out.contains("stripe/test") && out.contains("2 host(s)"),
        "{out}"
    );
    assert!(
        out.contains("pg/production") && out.contains("production"),
        "{out}"
    );

    let (code, out, _) = f.run(&f.repo(), &["pg/production"]);
    assert_eq!(code, 0);
    assert!(out.contains("every use needs an approval"), "{out}");
    assert!(out.contains(r#"["psql", "-c", "*"]"#), "{out}");
    assert!(out.contains("600 s"), "{out}");

    let (code, _, err) = f.run(&f.repo(), &["nope"]);
    assert_eq!(code, 1);
    assert!(err.contains("no key named nope"), "{err}");
    let (code, _, err) = f.run(&f.repo(), &["Bad Name"]);
    assert_eq!(code, 1);
    assert!(err.contains("invalid key name"), "{err}");
}

// protects=the project .morsec.toml is found up to the git root and only tightens what is shown;
// fails_when=the merged view widens anything, or a broken project file leaves keys usable;
// no_claim=the daemon's own merge (it calls the same ms_rules::effective)
#[test]
fn project_file_tightens_and_broken_file_disables() {
    let f = Fixture::new();
    std::fs::write(
        f.repo().join(".morsec.toml"),
        "[keys.\"stripe/test\"]\nhosts = [\"api.stripe.com\", \"evil.net\"]\ntier = \"production\"\n",
    )
    .unwrap();
    let sub = f.repo().join("src");
    std::fs::create_dir(&sub).unwrap();
    let (code, out, err) = f.run(&sub, &["stripe/test"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("project rules:") && out.contains(".morsec.toml"),
        "{out}"
    );
    assert!(out.contains("api.stripe.com"), "{out}");
    assert!(
        !out.contains("evil.net") && !out.contains("*.stripe.com"),
        "{out}"
    );
    assert!(out.contains("tier       production"), "{out}");

    let (_, out, _) = f.run(&sub, &["stripe/test", "--no-project"]);
    assert!(
        out.contains("*.stripe.com") && out.contains("tier       test"),
        "{out}"
    );

    std::fs::write(f.repo().join(".morsec.toml"), "this is [ not toml").unwrap();
    let (code, out, err) = f.run(&sub, &[]);
    assert_eq!(code, 0);
    assert!(err.contains("is not valid"), "{err}");
    assert!(out.contains("every key is disabled"), "{out}");
    assert_eq!(out.matches("nothing allowed").count(), 2, "{out}");
}

// protects=`ms rules --check` validates project files; fails_when=a bad file passes or a good one
// fails; no_claim=other file kinds
#[test]
fn check_project_file() {
    let f = Fixture::new();
    let good = f.path("good.toml");
    std::fs::write(&good, "[keys.\"pg/production\"]\nread_only = true\n").unwrap();
    let out = Command::new(ms())
        .args(["rules", "--check"])
        .arg(&good)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("restricts 1 key(s)"));

    let bad = f.path("bad.toml");
    std::fs::write(&bad, "[keys.\"pg/production\"]\nhostz = []\n").unwrap();
    let out = Command::new(ms())
        .args(["rules", "--check"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("hostz"));
}

// protects=a proposed change is classified tighten vs loosen against the user rule and is never
// written (ms has no MAC key); fails_when=a loosening is called tightening, the file changes, or
// the exit isn't 69; no_claim=the approval flow (L07/L11)
#[test]
fn proposals_are_classified_and_not_written() {
    let f = Fixture::new();
    let cases: &[(&[&str], &str)] = &[
        (
            &["stripe/test", "--add-host", "paste.example.net"],
            "loosens",
        ),
        (
            &["stripe/test", "--remove-host", "*.stripe.com"],
            "tightens",
        ),
        (&["pg/production", "--tier", "test"], "loosens"),
        (&["pg/production", "--ttl", "60", "--read-only"], "tightens"),
        (
            &["pg/production", "--add-command", r#"["sh", "-c", "*"]"#],
            "loosens",
        ),
        (
            &["pg/production", "--remove-command", r#"["pg_dump", "**"]"#],
            "tightens",
        ),
    ];
    for (args, want) in cases {
        let (code, out, err) = f.run(&f.repo(), args);
        assert_eq!(code, 69, "{args:?}: {err}");
        assert!(
            out.contains(&format!("this change {want}")),
            "{args:?}: {out}"
        );
        assert!(err.contains("L07"), "{err}");
        assert_eq!(
            std::fs::read_to_string(f.path("rules.toml")).unwrap(),
            RULES
        );
    }
    let (code, _, err) = f.run(&f.repo(), &["stripe/test", "--add-host", "a.com:443"]);
    assert_eq!(code, 1);
    assert!(err.contains("not a lowercase DNS name"), "{err}");
    let (code, _, err) = f.run(&f.repo(), &["stripe/test", "--add-command", "psql"]);
    assert_eq!(code, 1);
    assert!(err.contains("JSON array"), "{err}");
    let (code, _, err) = f.run(&f.repo(), &["stripe/test", "--add-command", r#"["curl"]"#]);
    assert_eq!(code, 1);
    assert!(
        err.contains("your proposed change is not valid")
            && err.contains("only allowed on a run-mode key")
            && !err.contains("--check"),
        "{err}"
    );
    let (code, _, err) = f.run(&f.repo(), &["--tier", "test"]);
    assert_eq!(code, 1);
    assert!(err.contains("say which key"), "{err}");
}

// protects=terminal escapes in a rules or project file never reach the terminal; fails_when=an
// ESC, BEL or bidi override is printed; no_claim=the approval dialog (L11)
#[test]
fn output_is_terminal_safe() {
    let f = Fixture::new();
    std::fs::write(
        f.repo().join(".morsec.toml"),
        "[keys.\"stripe/test\"]\nhosts = [\"\u{1b}]0;pwned\u{7}\u{202e}\"]\n",
    )
    .unwrap();
    let (_, out, err) = f.run(&f.repo(), &[]);
    for s in [&out, &err] {
        assert!(
            !s.chars().any(|c| c != '\n' && c.is_control()) && !s.contains('\u{202e}'),
            "{s:?}"
        );
    }
}

// protects=a missing rules file fails with the ms init hint; fails_when=it prints an empty list or
// exits 0; no_claim=the default path on Linux
#[test]
fn missing_rules_file() {
    let f = Fixture::new();
    let out = Command::new(ms())
        .args(["rules", "--rules"])
        .arg(f.path("absent.toml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ms init"));
}
