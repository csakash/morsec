//! Live check against the installed Codex CLI (opt-in: `MORSEC_LIVE_CODEX=1`, needs `codex` on
//! PATH; no sign-in and no model call). SPEC acceptance 8.
//!
//! For each golden input it runs the connector into a throwaway `CODEX_HOME` and asks Codex
//! itself: `codex --strict-config` (rejects any key this Codex doesn't know),
//! `codex mcp get ms --json`, and `codex sandbox -- /usr/bin/env` (the variables a command Codex
//! runs really sees). A negative control proves `--strict-config` would have caught a bad key.
//! The real `~/.codex` is never read or written: HOME and CODEX_HOME point into a temp dir.

#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ms_connect::codex::{CodexConnector, McpRef, Options, Paths};
use ms_connect::{ConnectCfg, Connector};

fn golden(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/codex")
            .join(name),
    )
    .unwrap()
}

/// Loads `config.toml` the strict way: `codex --strict-config` rejects any key this Codex
/// doesn't know while loading, before anything else. Only `codex` itself (the TUI) takes the flag,
/// so with no terminal it then stops with "stdin is not a terminal": that is the pass case. Returns
/// the load error, if any.
fn strict_load(home: &Path, codex_home: &Path) -> Option<String> {
    let (_, out) = codex(home, codex_home, &["--strict-config"]);
    assert!(
        out.contains("Error loading config.toml") || out.contains("stdin is not a terminal"),
        "unexpected codex output: {out}"
    );
    out.contains("Error loading config.toml").then_some(out)
}

fn codex(home: &Path, codex_home: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("codex")
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("CODEX_HOME", codex_home)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("codex on PATH");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

// protects=the live card check: Codex itself accepts every key morsec writes (strict config),
// reads the ms server as the env -i stdio entry, and passes the marker, proxy, CA variables and
// references to the commands it runs; fails_when=Codex rejects, ignores or drops anything
// morsec writes; no_claim=traffic through msd (needs network on in the sandbox and a daemon)
#[test]
fn codex_accepts_the_block() {
    if std::env::var_os("MORSEC_LIVE_CODEX").is_none() {
        eprintln!("skipped: set MORSEC_LIVE_CODEX=1 to run against the installed codex");
        return;
    }
    let (ok, v) = codex(Path::new("/"), Path::new("/nonexistent"), &["--version"]);
    eprintln!("live against: {}", v.trim());
    assert!(ok);
    for (name, refs) in [
        ("missing", vec![]),
        (
            "typical.toml",
            vec!["github:GITHUB_PERSONAL_ACCESS_TOKEN=ms://github/pat"],
        ),
        ("complex.toml", vec!["pg:PGPASSWORD=ms://pg/app"]),
        ("no-newline.toml", vec![]),
    ] {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let ch = home.join(".codex");
        std::fs::create_dir_all(&ch).unwrap();
        if name != "missing" {
            std::fs::write(ch.join("config.toml"), golden(name)).unwrap();
        }
        let mut c = CodexConnector::new(Paths::for_home(&home, Some(&ch)), "/usr/local/bin/ms");
        c.opts = Options {
            with_mcp: true,
            force: false,
        };
        c.mcp_refs = refs.iter().map(|r| McpRef::parse(r).unwrap()).collect();
        let cfg = ConnectCfg {
            proxy_port: 4401,
            allowed_domains: vec![],
            env: vec![("STRIPE_API_KEY".into(), "ms://stripe/test".into())],
            shim_dir: None,
        };
        let p = c.try_plan(&cfg).unwrap();
        c.apply(&p.diff).unwrap();

        if let Some(e) = strict_load(&home, &ch) {
            panic!("{name}: strict config rejected the file:\n{e}");
        }
        let (ok, out) = codex(&home, &ch, &["mcp", "get", "ms", "--json"]);
        assert!(ok, "{name}: {out}");
        assert!(
            out.contains("\"/usr/bin/env\"") && out.contains("\"-i\""),
            "{name}: {out}"
        );
        let (ok, out) = codex(
            &home,
            &ch,
            &[
                "sandbox",
                "-c",
                "sandbox_mode=\"workspace-write\"",
                "--",
                "/usr/bin/env",
            ],
        );
        assert!(ok, "{name}: {out}");
        for want in [
            "MORSEC_CONNECTED=codex",
            "HTTPS_PROXY=http://127.0.0.1:4401",
            "http_proxy=http://127.0.0.1:4401",
            "STRIPE_API_KEY=ms://stripe/test",
            "NODE_EXTRA_CA_CERTS=",
        ] {
            assert!(
                out.lines().any(|l| l.starts_with(want)),
                "{name}: no {want} in\n{out}"
            );
        }
        if let Some(r) = refs.first() {
            let server = r.split(':').next().unwrap();
            let (ok, out) = codex(&home, &ch, &["mcp", "get", server, "--json"]);
            assert!(ok, "{name}: {out}");
            assert!(
                out.contains("ms://") && out.contains("127.0.0.1:4401"),
                "{name}: {out}"
            );
            assert!(!out.contains("CANARY"), "{name}");
        }
        c.remove().unwrap();
        assert_eq!(strict_load(&home, &ch), None, "{name} after disconnect");
    }
    // Negative control: strict config does reject an unknown key.
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("config.toml"), "morsec_unknown_key = 1\n").unwrap();
    assert!(
        strict_load(d.path(), d.path()).is_some_and(|e| e.contains("morsec_unknown_key")),
        "strict config accepted an unknown key"
    );
}
