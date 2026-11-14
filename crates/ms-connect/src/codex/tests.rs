//! Tests for the Codex connector. Every test works in a temp HOME; nothing touches `~/.codex`.

use std::path::Path;

use super::*;

const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n";
const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBmorsecCA\n-----END CERTIFICATE-----\n";
const PORT: u16 = 4401;

struct Env {
    _d: tempfile::TempDir,
    c: CodexConnector,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut paths = Paths::for_home(&home, None);
    paths.system_roots = d.path().join("roots.pem");
    std::fs::write(&paths.system_roots, PEM).unwrap();
    let mut c = CodexConnector::new(paths, "/opt/homebrew/bin/ms");
    c.ca_pem = Some(CA.into());
    Env { _d: d, c }
}

fn cfg(env: &[(&str, &str)]) -> ConnectCfg {
    ConnectCfg {
        proxy_port: PORT,
        allowed_domains: vec![],
        env: env
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect(),
        shim_dir: None,
    }
}

fn write_config(c: &CodexConnector, text: &str) {
    std::fs::create_dir_all(c.paths.config.parent().unwrap()).unwrap();
    std::fs::write(&c.paths.config, text).unwrap();
}

fn config(c: &CodexConnector) -> Option<String> {
    std::fs::read_to_string(&c.paths.config).ok()
}

fn connect(c: &CodexConnector, cf: &ConnectCfg) -> Planned {
    let p = c.try_plan(cf).unwrap();
    c.apply(&p.diff).unwrap();
    p
}

fn disconnect(c: &CodexConnector) -> RemovePlan {
    let p = c.plan_remove().unwrap().unwrap();
    c.apply_remove(&p).unwrap();
    p
}

/// Compares with a golden file, or writes it when `UPDATE_GOLDEN=1`.
fn golden(name: &str, text: &str) {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/codex")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&p, text).unwrap();
    }
    let want = std::fs::read_to_string(&p).unwrap_or_default();
    assert_eq!(
        text, want,
        "golden {name} differs (UPDATE_GOLDEN=1 to rewrite)"
    );
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/codex")
            .join(name),
    )
    .unwrap()
}

// protects=SPEC acceptance 1 (golden TOML round trips): for a missing file, an empty file, a
// typical config, a complex hand-edited one and one with no final newline, connect writes the
// golden text and disconnect gives back the exact original bytes (or removes a file connect
// created); fails_when=a byte differs, a comment or ordering is lost, or a file is left behind
#[test]
fn golden_round_trips() {
    for (name, input) in [
        ("missing", None),
        ("empty", Some(String::new())),
        ("typical", Some(fixture("typical.toml"))),
        ("complex", Some(fixture("complex.toml"))),
        ("no-newline", Some(fixture("no-newline.toml"))),
    ] {
        let mut e = env();
        if let Some(t) = &input {
            write_config(&e.c, t);
        }
        e.c.opts.with_mcp = true;
        e.c.mcp_refs = match name {
            "typical" => {
                vec![McpRef::parse("github:GITHUB_PERSONAL_ACCESS_TOKEN=ms://github/pat").unwrap()]
            }
            "complex" => vec![McpRef::parse("pg:PGPASSWORD=ms://pg/app").unwrap()],
            _ => vec![],
        };
        connect(&e.c, &cfg(&[("STRIPE_API_KEY", "ms://stripe/test")]));
        let written = config(&e.c).unwrap();
        golden(
            &format!("{name}.connected.toml"),
            &written.replace(e.c.paths.home.to_str().unwrap(), "$HOME"),
        );
        // Every original line is still there, in order (comments and layout kept), except
        // the values a reference replaced.
        if let Some(t) = &input {
            let mut it = written.lines();
            for l in t
                .lines()
                .filter(|l| !l.contains("CANARY") && !l.contains("/etc/corp/ca.pem"))
            {
                assert!(it.any(|w| w == l), "{name}: lost line {l:?}");
            }
        }
        // Connected text is valid for Codex's parser shape: it parses.
        written.parse::<DocumentMut>().unwrap();
        let p = disconnect(&e.c);
        let back = config(&e.c);
        match name {
            // A reference replaced a value of the user's: that value is gone, by design.
            "typical" | "complex" => {
                assert!(p.notes.iter().any(|n| n.contains("didn't keep it")));
                let back = back.unwrap();
                assert!(!back.contains("CANARY"));
                assert!(!back.contains("ms://"));
                assert!(!back.contains("MORSEC") && !back.contains("127.0.0.1"));
                // Everything else is exactly as it was: the original minus that one key.
                let mut want: DocumentMut = input.clone().unwrap().parse().unwrap();
                let (server, key) = if name == "typical" {
                    ("github", "GITHUB_PERSONAL_ACCESS_TOKEN")
                } else {
                    ("pg", "PGPASSWORD")
                };
                want["mcp_servers"][server]["env"]
                    .as_table_like_mut()
                    .unwrap()
                    .remove(key);
                assert_eq!(back, want.to_string(), "{name}");
            }
            _ => assert_eq!(back, input, "{name}: not byte-identical"),
        }
        assert!(!e.c.paths.state.exists() && !e.c.paths.bundle.exists());
    }
}

// protects=SPEC D4 for the files with no value of the user's replaced: apply then remove is
// byte-identical, including the ms MCP server and an --env ref; fails_when=any byte differs
#[test]
fn apply_remove_byte_identical() {
    for name in ["typical.toml", "complex.toml", "no-newline.toml"] {
        let e = {
            let mut e = env();
            e.c.opts.with_mcp = true;
            e
        };
        let t = fixture(name);
        write_config(&e.c, &t);
        let mut c = e.c.clone();
        if name == "complex.toml" {
            // A local server with no value under the name: an Added record, so exact restore.
            c.mcp_refs = vec![McpRef::parse("pg:PG_API_KEY=ms://pg/key").unwrap()];
        }
        connect(&c, &cfg(&[("STRIPE_API_KEY", "ms://stripe/test")]));
        assert_ne!(config(&c).unwrap(), t);
        let p = disconnect(&c);
        assert!(p.notes.is_empty(), "{name}: {:?}", p.notes);
        assert_eq!(config(&c).unwrap(), t, "{name}");
    }
}

// protects=SPEC acceptance 2 / D2 (L08 F2): a re-run with the same inputs writes nothing and
// keeps one record per path; changing an --env reference updates its one record; the
// previous refs and --with-mcp carry over; fails_when=a re-run writes or duplicates a record
#[test]
fn rerun_is_idempotent_one_record_per_path() {
    let mut e = env();
    write_config(&e.c, &fixture("typical.toml"));
    e.c.opts.with_mcp = true;
    e.c.mcp_refs =
        vec![McpRef::parse("github:GITHUB_PERSONAL_ACCESS_TOKEN=ms://github/pat").unwrap()];
    let cf = cfg(&[("STRIPE_API_KEY", "ms://stripe/test")]);
    connect(&e.c, &cf);
    let first = config(&e.c).unwrap();
    let state1 = std::fs::read_to_string(&e.c.paths.state).unwrap();
    for _ in 0..3 {
        assert!(e.c.try_plan(&cf).unwrap().diff.changes.is_empty());
    }
    // As the CLI does: previous refs and options carried, nothing passed again.
    let mut again = e.c.clone();
    again.mcp_refs = e.c.previous_mcp_refs().unwrap();
    again.opts = e.c.previous_options().unwrap();
    let carried = cfg(&[]);
    let carried = ConnectCfg {
        env: e.c.previous_env_refs().unwrap(),
        ..carried
    };
    assert_eq!(
        carried.env,
        vec![("STRIPE_API_KEY".into(), "ms://stripe/test".into())]
    );
    assert!(again.try_plan(&carried).unwrap().diff.changes.is_empty());
    assert_eq!(std::fs::read_to_string(&e.c.paths.state).unwrap(), state1);

    // Change the GitHub reference: still one record for that path.
    e.c.mcp_refs =
        vec![McpRef::parse("github:GITHUB_PERSONAL_ACCESS_TOKEN=ms://github/other").unwrap()];
    connect(&e.c, &cf);
    let st = e.c.read_state().unwrap().unwrap();
    let mut paths: Vec<_> = st.edits.records.iter().map(|r| r.path.clone()).collect();
    let n = paths.len();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), n, "duplicate records");
    let s = config(&e.c).unwrap();
    assert!(s.contains("ms://github/other") && !s.contains("ms://github/pat"));
    assert_ne!(s, first);
    // Changing the port updates the proxy records in place too.
    connect(
        &e.c,
        &ConnectCfg {
            proxy_port: 4999,
            ..cf.clone()
        },
    );
    assert_eq!(e.c.read_state().unwrap().unwrap().edits.records.len(), n);
    assert!(config(&e.c).unwrap().contains("http://127.0.0.1:4999"));
    assert!(!config(&e.c).unwrap().contains("127.0.0.1:4401"));
}

// protects=SPEC acceptance 3 / D5: edits Codex makes between connect and disconnect (a new
// trust entry, a notice, `codex mcp add` reformatting mcp_servers) are kept, and morsec's keys
// are removed by content; fails_when=a Codex edit is lost or a morsec key is left behind
#[test]
fn codex_edits_between_connect_and_disconnect_are_kept() {
    let mut e = env();
    let t = fixture("no-newline.toml");
    write_config(&e.c, &t);
    e.c.opts.with_mcp = true;
    connect(&e.c, &cfg(&[]));
    // Codex rewrites the file with toml_edit: adds a project, and rewrites the ms server inline.
    let mut d: DocumentMut = config(&e.c).unwrap().parse().unwrap();
    let ms = d["mcp_servers"]["ms"].clone();
    let inline = ms.as_table().unwrap().clone().into_inline_table();
    d["mcp_servers"]["ms"] = Item::Value(Value::InlineTable(inline));
    d["projects"] = toml_edit::table();
    d["projects"]["/w"] = toml_edit::table();
    d["projects"]["/w"]["trust_level"] = toml_edit::value("trusted");
    std::fs::write(&e.c.paths.config, d.to_string()).unwrap();
    // verify() still sees the server (content, not layout).
    assert!(e.c.verify().iter().all(|c| c.ok), "{:?}", e.c.verify());
    let p = disconnect(&e.c);
    assert!(
        p.notes
            .iter()
            .any(|n| n.contains("edited after ms connect"))
    );
    let back = config(&e.c).unwrap();
    assert!(back.contains("trust_level = \"trusted\""));
    for gone in [
        "MORSEC_CONNECTED",
        "127.0.0.1",
        "ms mcp",
        "/usr/bin/env",
        "mcp_servers",
        "shell_environment_policy",
    ] {
        assert!(!back.contains(gone), "{gone} left in {back}");
    }
    assert!(back.starts_with("model = \"o3\"\n[tui]\ntheme = \"dark\""));
}

// protects=SPEC acceptance 4 / D6 / D7 (L08 S1): a value of the user's that a reference
// replaces is never written to the state file, the bundle or the preview, and the user is
// told disconnect won't bring it back; --env and --mcp-env take only ms:// references with
// safe names; fails_when=a canary reaches morsec's files or a raw value is accepted
#[test]
fn user_values_never_kept_and_refs_only() {
    let mut e = env();
    write_config(&e.c, &fixture("complex.toml"));
    e.c.mcp_refs = vec![McpRef::parse("pg:PGPASSWORD=ms://pg/app").unwrap()];
    let p = connect(&e.c, &cfg(&[]));
    assert!(
        p.warnings
            .iter()
            .any(|w| w.contains("doesn't keep the old value"))
    );
    let state = std::fs::read_to_string(&e.c.paths.state).unwrap();
    let bundle = std::fs::read_to_string(&e.c.paths.bundle).unwrap();
    assert!(!state.contains("CANARY") && !bundle.contains("CANARY"));
    assert!(!config(&e.c).unwrap().contains("CANARY"));
    // The preview of that change (changed lines only, as `ms connect` prints them) hides the
    // old value.
    let safe = e.c.display_safe(Some(&cfg(&[])));
    let before = fixture("complex.toml");
    let after = config(&e.c).unwrap();
    use crate::claude::diff::{Line, changed_lines, significant};
    let shown: Vec<String> = significant(changed_lines(&before, &after).unwrap())
        .into_iter()
        .map(|l| match l {
            Line::Removed(_, t) | Line::Added(_, t) => {
                tedit::redact_line(t, &|s| safe.iter().any(|x| x == s))
            }
        })
        .collect();
    assert!(shown.iter().all(|l| !l.contains("CANARY")));
    assert!(shown.iter().any(|l| l == "PGPASSWORD = \"…\""));

    for bad in [
        "pg:PGPASSWORD=hunter2",
        "pg:LD_PRELOAD=ms://a/b",
        "pg:HTTPS_PROXY=ms://a/b",
        "pg=X",
        ":X=ms://a/b",
        "ms:X=ms://a/b",
    ] {
        assert!(McpRef::parse(bad).is_err(), "{bad}");
    }
    let e2 = env();
    for (n, v) in [
        ("K", "sk-live-123"),
        ("PATH", "ms://a/b"),
        ("CODEX_HOME", "ms://a/b"),
    ] {
        let r = e2.c.try_plan(&cfg(&[(n, v)]));
        assert!(r.is_err(), "{n}={v}");
    }
}

// protects=SPEC acceptance 5 / D8: refusals change nothing (symlink, invalid TOML, CRLF, a
// non-table shell_environment_policy, a proxy of the user's without --force, --mcp-env on an
// unknown or remote server, msd down); fails_when=any file is written
#[test]
fn refusals_change_nothing() {
    let cases: Vec<(&str, &str, Vec<McpRef>, &str)> = vec![
        ("bad", "model = \n", vec![], "not valid TOML"),
        ("crlf", "model = \"o3\"\r\n", vec![], "CRLF"),
        (
            "nontable",
            "shell_environment_policy = \"core\"\n",
            vec![],
            "needs it to be a table",
        ),
        (
            "proxy",
            "[shell_environment_policy.set]\nHTTPS_PROXY = \"http://corp:8080\"\n",
            vec![],
            "--force",
        ),
        (
            "unknown",
            "",
            vec![McpRef::parse("gh:T=ms://g/t").unwrap()],
            "no MCP server",
        ),
        (
            "remote",
            "[mcp_servers.linear]\nurl = \"https://x\"\n",
            vec![McpRef::parse("linear:T=ms://l/t").unwrap()],
            "local servers",
        ),
        (
            "ms",
            "[mcp_servers.ms]\ncommand = \"mine\"\n",
            vec![],
            "--force",
        ),
    ];
    for (name, text, refs, want) in cases {
        let mut e = env();
        write_config(&e.c, text);
        e.c.mcp_refs = refs;
        e.c.opts.with_mcp = name == "ms";
        let r = e.c.try_plan(&cfg(&[]));
        let msg = r.err().map(|x| x.to_string()).unwrap_or_default();
        assert!(msg.contains(want), "{name}: {msg}");
        assert_eq!(config(&e.c).as_deref(), Some(text));
        assert!(!e.c.paths.state.exists());
    }
    // A symlinked config.toml is refused, never followed or replaced.
    let e = env();
    let real = e.c.paths.home.join("real.toml");
    std::fs::write(&real, "model = \"o3\"\n").unwrap();
    std::fs::create_dir_all(e.c.paths.config.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &e.c.paths.config).unwrap();
    assert!(
        e.c.try_plan(&cfg(&[]))
            .unwrap_err()
            .to_string()
            .contains("symlink")
    );
    assert!(
        std::fs::symlink_metadata(&e.c.paths.config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // msd down: no port.
    let e = env();
    assert!(
        e.c.try_plan(&ConnectCfg {
            proxy_port: 0,
            ..cfg(&[])
        })
        .is_err()
    );
    // A file changed after the plan: apply refuses and writes nothing.
    let e = env();
    write_config(&e.c, "");
    let p = e.c.try_plan(&cfg(&[])).unwrap();
    write_config(&e.c, "model = \"x\"\n");
    assert!(e.c.apply(&p.diff).is_err());
    assert!(!e.c.paths.state.exists());
}

// protects=--force replaces a proxy of the user's and disconnect puts it back exactly; a proxy
// URL with credentials is replaced but never stored; a re-run after --force needs no --force
// again only while morsec's value is in place; fails_when=the old proxy is lost, or a
// credential reaches the state file
#[test]
fn force_keeps_plain_values_and_drops_credentials() {
    let t = "[shell_environment_policy.set]\nHTTPS_PROXY = \"http://corp:8080\" # corp\n";
    let mut e = env();
    write_config(&e.c, t);
    e.c.opts.force = true;
    connect(&e.c, &cfg(&[]));
    assert!(
        std::fs::read_to_string(&e.c.paths.state)
            .unwrap()
            .contains("corp:8080")
    );
    e.c.opts.force = false;
    assert!(e.c.try_plan(&cfg(&[])).unwrap().diff.changes.is_empty());
    disconnect(&e.c);
    assert_eq!(config(&e.c).unwrap(), t);

    let t = "[shell_environment_policy.set]\nHTTPS_PROXY = \"http://bob:CANARYpw@corp:8080\"\n";
    let mut e = env();
    write_config(&e.c, t);
    e.c.opts.force = true;
    connect(&e.c, &cfg(&[]));
    assert!(
        !std::fs::read_to_string(&e.c.paths.state)
            .unwrap()
            .contains("CANARY")
    );
    disconnect(&e.c);
    assert!(!config(&e.c).unwrap().contains("CANARY"));
}

// protects=SPEC acceptance 6 / MCP-4: the ms MCP server runs under `env -i` with only HOME,
// PATH (and MORSEC_SOCKET), so it never inherits Codex's environment; local MCP servers that
// get a reference also get the proxy and CA variables (Codex starts them with a cleared env);
// fails_when=the entry runs ms directly or other variables reach it
#[test]
fn mcp4_minimal_env() {
    let mut e = env();
    e.c.opts.with_mcp = true;
    e.c.socket_env = Some("/tmp/dev.sock".into());
    write_config(&e.c, "[mcp_servers.gh]\ncommand = \"gh-mcp\"\n");
    e.c.mcp_refs = vec![McpRef::parse("gh:GH_TOKEN=ms://gh/t").unwrap()];
    connect(&e.c, &cfg(&[]));
    let d: DocumentMut = config(&e.c).unwrap().parse().unwrap();
    let ms = &d["mcp_servers"]["ms"];
    assert_eq!(ms["command"].as_str(), Some("/usr/bin/env"));
    let args: Vec<&str> = ms["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let home = format!("HOME={}", e.c.paths.home.display());
    assert_eq!(
        args,
        vec![
            "-i",
            home.as_str(),
            "PATH=/usr/bin:/bin",
            "MORSEC_SOCKET=/tmp/dev.sock",
            "/opt/homebrew/bin/ms",
            "mcp"
        ]
    );
    assert!(ms.get("env").is_none());
    let gh = d["mcp_servers"]["gh"]["env"].as_table_like().unwrap();
    assert_eq!(gh.get("GH_TOKEN").and_then(Item::as_str), Some("ms://gh/t"));
    assert_eq!(
        gh.get("HTTPS_PROXY").and_then(Item::as_str),
        Some("http://127.0.0.1:4401")
    );
    assert!(gh.get("SSL_CERT_FILE").is_some());
    assert!(e.c.verify().iter().all(|c| c.ok), "{:?}", e.c.verify());

    // Run the entry the way Codex does (cleared env plus its safelist) with canaries around:
    // env -i drops them all.
    let out = std::process::Command::new("/usr/bin/env")
        .env_clear()
        .env("OPENAI_API_KEY", "sk-CANARY")
        .env("HOME", "/x")
        .args(["-i", home.as_str(), "PATH=/usr/bin:/bin", "/usr/bin/env"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("CANARY"));
    assert_eq!(s.lines().count(), 2);
}

// protects=SPEC acceptance 7 / SDLC-2: connect never writes a sandbox, approval, feature,
// permission or network setting, whatever the input; it warns about the weaker settings it
// finds and about the sandbox network being off; fails_when=a forbidden key appears in a
// write or a warning is missing
#[test]
fn sdlc2_never_loosens_and_warns() {
    let weak = format!(
        "sandbox_mode = \"{FULL_ACCESS}\"\napproval_policy = \"{NEVER_ASK}\"\n[features]\nnetwork_proxy = true\n[shell_environment_policy]\ninclude_only = [\"PATH\"]\n[profiles.p.shell_environment_policy]\ninherit = \"none\"\n"
    );
    for t in ["", "model = \"o3\"\n", weak.as_str()] {
        let mut e = env();
        write_config(&e.c, t);
        e.c.opts.with_mcp = true;
        let p = e.c.try_plan(&cfg(&[("A_KEY", "ms://a/b")])).unwrap();
        let st = p
            .diff
            .changes
            .iter()
            .find(|c| c.path == e.c.paths.state)
            .unwrap();
        let v = json::parse(&st.after).unwrap();
        for r in v.get("records").unwrap().as_array().unwrap() {
            let first = r.get("path").unwrap().as_array().unwrap()[0]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                ["shell_environment_policy", "mcp_servers"].contains(&first.as_str()),
                "wrote {first}"
            );
        }
        // Nothing in the written config adds a sandbox, approval, feature, permission or
        // network setting (review R6: check the text, not only the records).
        let written = &p
            .diff
            .changes
            .iter()
            .find(|c| c.path == e.c.paths.config)
            .unwrap()
            .after;
        for k in [
            "network_access",
            "sandbox_mode",
            "approval_policy",
            "[features",
            "[permissions",
            "sandbox_workspace_write",
        ] {
            assert_eq!(written.matches(k).count(), t.matches(k).count(), "{k}");
        }
        let w = p.warnings.join("\n");
        if t.is_empty() {
            assert!(w.contains("network turned off"));
        }
        if t == weak {
            for want in [
                "sandbox_mode",
                "approval_policy",
                "own network proxy",
                "include_only",
                "profile \"p\"",
            ] {
                assert!(w.contains(want), "missing {want}: {w}");
            }
            assert!(!w.contains("network turned off"));
        }
    }
}

// protects=SPEC D8 / SDLC-4: files morsec writes are private (config.toml and state 0600,
// an existing config keeps its mode); only the config, state and bundle are touched;
// verify() reports drift; fails_when=a mode widens or a check misses a removed key
#[test]
fn sdlc4_modes_scope_and_drift() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let p = connect(&e.c, &cfg(&[]));
    let touched: Vec<_> = p.diff.changes.iter().map(|c| c.path.clone()).collect();
    assert_eq!(
        touched,
        vec![
            e.c.paths.state.clone(),
            e.c.paths.bundle.clone(),
            e.c.paths.config.clone()
        ]
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&e.c.paths.config), 0o600);
    assert_eq!(mode(&e.c.paths.state), 0o600);
    assert!(e.c.verify().iter().all(|c| c.ok));
    let edited = config(&e.c)
        .unwrap()
        .replace("127.0.0.1:4401", "127.0.0.1:9");
    std::fs::write(&e.c.paths.config, edited).unwrap();
    let bad: Vec<_> = e.c.verify().into_iter().filter(|c| !c.ok).collect();
    assert_eq!(bad.len(), 1);
    assert!(bad[0].name.contains("proxy"));
    disconnect(&e.c);
    assert!(e.c.verify().iter().all(|c| !c.ok));
    assert!(e.c.plan_remove().unwrap().is_none());

    let e = env();
    write_config(&e.c, "model = \"o3\"\n");
    std::fs::set_permissions(&e.c.paths.config, std::fs::Permissions::from_mode(0o640)).unwrap();
    connect(&e.c, &cfg(&[]));
    assert_eq!(mode(&e.c.paths.config), 0o640);
}

// protects=CA files the user's config already named stay trusted (folded into the bundle)
// and come back on disconnect; fails_when=the user's CA path is lost
#[test]
fn user_ca_folded_and_restored() {
    let e = env();
    let ca = e.c.paths.home.join("corp.pem");
    std::fs::write(
        &ca,
        "-----BEGIN CERTIFICATE-----\nMIIBcorp\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let t = format!(
        "[shell_environment_policy.set]\nSSL_CERT_FILE = \"{}\"\n",
        ca.display()
    );
    write_config(&e.c, &t);
    connect(&e.c, &cfg(&[]));
    let b = std::fs::read_to_string(&e.c.paths.bundle).unwrap();
    assert!(b.contains("MIIBcorp") && b.contains("MIIBmorsecCA") && b.contains("MIIBroot"));
    disconnect(&e.c);
    assert_eq!(config(&e.c).unwrap(), t);
}

// protects=property: for generated configs built from TOML pieces Codex users write, connect
// then disconnect is byte-identical and a second connect writes nothing; fails_when=any
// generated layout breaks exact restore or idempotence
#[test]
fn prop_round_trip() {
    use proptest::prelude::*;
    let piece = prop::sample::select(vec![
        "model = \"o3\"\n",
        "# a comment\n",
        "\n",
        "[tui]\ntheme = 'dark'\n",
        "[shell_environment_policy]\ninherit = \"all\"\n",
        "shell_environment_policy.exclude = [\"AWS_*\"]\n",
        "[shell_environment_policy.set]\nFOO = \"bar\"   # c\n",
        "[mcp_servers.x]\ncommand = \"x\"\nargs = []\n",
        "[mcp_servers.y]\nurl = \"https://y\"\n",
        "[[skills.config]]\nname = \"s\"\n",
        "[projects.\"/p\"]\ntrust_level = \"trusted\"\n",
    ]);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(64));
    runner
        .run(&prop::collection::vec(piece, 0..6), |pieces| {
            let t: String = pieces.concat();
            // Skip combinations that are invalid TOML (a table defined twice).
            if t.parse::<DocumentMut>().is_err() {
                return Ok(());
            }
            let mut e = env();
            write_config(&e.c, &t);
            e.c.opts.with_mcp = true;
            let p = e.c.try_plan(&cfg(&[("A_KEY", "ms://a/b")])).unwrap();
            e.c.apply(&p.diff).unwrap();
            prop_assert!(
                e.c.try_plan(&cfg(&[("A_KEY", "ms://a/b")]))
                    .unwrap()
                    .diff
                    .changes
                    .is_empty()
            );
            let r = e.c.plan_remove().unwrap().unwrap();
            e.c.apply_remove(&r).unwrap();
            prop_assert_eq!(config(&e.c).unwrap(), t);
            Ok(())
        })
        .unwrap();
}

#[test]
fn userinfo_detection() {
    assert!(has_userinfo("http://a:b@h:1"));
    assert!(has_userinfo("a@h"));
    assert!(!has_userinfo("http://h:1/p@x"));
    assert!(!has_userinfo("http://127.0.0.1:4401"));
}

// protects=a config with no final newline: disconnect takes connect's newline back off when the
// file is unchanged (byte-exact), but keeps the newline of text Codex appended since;
// fails_when=Codex's appended line loses its newline
#[test]
fn final_newline_only_removed_when_unchanged() {
    let e = env();
    write_config(&e.c, "model = \"o3\"");
    connect(&e.c, &cfg(&[]));
    let mut t = config(&e.c).unwrap();
    t.push_str("\n[projects.\"/w\"]\ntrust_level = \"trusted\"\n");
    std::fs::write(&e.c.paths.config, &t).unwrap();
    disconnect(&e.c);
    assert_eq!(
        config(&e.c).unwrap(),
        "model = \"o3\"\n\n[projects.\"/w\"]\ntrust_level = \"trusted\"\n"
    );
}

// protects=review R1 (SPEC D6/D10): after --force replaced a proxy, a user who puts their own
// value back must not have it replaced by a plain re-run (which an agent may run): only a value
// morsec itself left is replaceable without --force; fails_when=the plain re-run overwrites it
#[test]
fn restored_user_value_needs_force_again() {
    let t = "[shell_environment_policy.set]\nHTTPS_PROXY = \"http://corp:8080\"\n";
    let mut e = env();
    write_config(&e.c, t);
    e.c.opts.force = true;
    connect(&e.c, &cfg(&[]));
    e.c.opts.force = false;
    let edited = config(&e.c).unwrap().replace(
        "HTTPS_PROXY = \"http://127.0.0.1:4401\"",
        "HTTPS_PROXY = \"http://corp:8080\"",
    );
    std::fs::write(&e.c.paths.config, &edited).unwrap();
    let r = e.c.try_plan(&cfg(&[]));
    assert!(r.unwrap_err().to_string().contains("--force"));
    assert_eq!(config(&e.c).unwrap(), edited);
}

// protects=review R3: a proxy --force replaced without keeping it (it held credentials) is
// re-pointed on a re-run (new msd port) without --force, and the record stays one redacted
// record; fails_when=the re-run asks for --force over morsec's own old value
#[test]
fn redacted_forced_value_follows_port_changes() {
    let mut e = env();
    write_config(
        &e.c,
        "[shell_environment_policy.set]\nHTTPS_PROXY = \"http://u:CANARY@corp:1\"\n",
    );
    e.c.opts.force = true;
    connect(&e.c, &cfg(&[]));
    e.c.opts.force = false;
    connect(
        &e.c,
        &ConnectCfg {
            proxy_port: 4999,
            ..cfg(&[])
        },
    );
    let s = config(&e.c).unwrap();
    assert!(s.contains("HTTPS_PROXY = \"http://127.0.0.1:4999\""));
    let st = std::fs::read_to_string(&e.c.paths.state).unwrap();
    assert!(!st.contains("CANARY") && !st.contains("4401"));
    disconnect(&e.c);
    assert!(!config(&e.c).unwrap().contains("HTTPS_PROXY"));
}

// protects=review R2: a server given --mcp-env earlier and removed from Codex since doesn't
// break a plain re-run (its carried reference is dropped with a note); a server named on this
// run must exist; fails_when=the re-run fails or a new unknown server is accepted
#[test]
fn carried_ref_for_removed_server_is_dropped() {
    let mut e = env();
    write_config(&e.c, "[mcp_servers.gh]\ncommand = \"gh-mcp\"\n");
    e.c.mcp_refs = vec![McpRef::parse("gh:GH_TOKEN=ms://gh/t").unwrap()];
    connect(&e.c, &cfg(&[]));
    // `codex mcp remove gh`.
    let mut d: DocumentMut = config(&e.c).unwrap().parse().unwrap();
    d["mcp_servers"].as_table_like_mut().unwrap().remove("gh");
    std::fs::write(&e.c.paths.config, d.to_string()).unwrap();
    let mut again = e.c.clone();
    again.mcp_refs = e.c.previous_mcp_refs().unwrap();
    assert!(again.mcp_refs.iter().all(|r| r.carried));
    let p = again.try_plan(&cfg(&[])).unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("is gone")));
    again.apply(&p.diff).unwrap();
    assert!(again.previous_mcp_refs().unwrap().is_empty());
    again.mcp_refs = vec![McpRef::parse("gh:GH_TOKEN=ms://gh/t").unwrap()];
    assert!(again.try_plan(&cfg(&[])).is_err());
}

// protects=review R4: a config the user deleted after connect, re-created by a re-run, is
// removed again by disconnect; fails_when=an empty config.toml is left behind
#[test]
fn deleted_config_is_recreated_and_removed() {
    let e = env();
    write_config(&e.c, "model = \"o3\"\n");
    connect(&e.c, &cfg(&[]));
    std::fs::remove_file(&e.c.paths.config).unwrap();
    connect(&e.c, &cfg(&[]));
    assert!(config(&e.c).unwrap().contains("MORSEC_CONNECTED"));
    disconnect(&e.c);
    assert!(!e.c.paths.config.exists());
}

// protects=review R7: after an edit inside a table morsec created, an unchanged re-run doesn't
// reorder the recorded tables, so the state file is not rewritten; fails_when=it is
#[test]
fn rerun_after_edit_keeps_created_order() {
    let mut e = env();
    write_config(&e.c, "[mcp_servers.gh]\ncommand = \"gh-mcp\"\n");
    e.c.mcp_refs = vec![McpRef::parse("gh:GH_TOKEN=ms://gh/t").unwrap()];
    connect(&e.c, &cfg(&[]));
    let mut d: DocumentMut = config(&e.c).unwrap().parse().unwrap();
    d["mcp_servers"]["gh"]["env"]["USER_ADDED"] = toml_edit::value("1");
    std::fs::write(&e.c.paths.config, d.to_string()).unwrap();
    let st = std::fs::read_to_string(&e.c.paths.state).unwrap();
    let p = e.c.try_plan(&cfg(&[])).unwrap();
    let new_state = p.diff.changes.iter().find(|c| c.path == e.c.paths.state);
    let created = |t: &str| json::parse(t).unwrap().get("created").cloned();
    if let Some(c) = new_state {
        assert_eq!(created(&c.after), created(&st));
    }
}
