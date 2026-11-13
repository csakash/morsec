//! Live check against the installed Claude Code (opt-in: `MORSEC_LIVE_CLAUDE=1`, needs `claude`
//! on PATH; no sign-in and no model call). SPEC "The live check the card puts in tests/e2e".
//!
//! For each golden case it runs the connector into a throwaway `CLAUDE_CONFIG_DIR` and asks
//! `claude doctor`, which lists every settings entry Claude Code rejects, and `claude mcp get ms`.
//! A negative control proves doctor would have reported a bad entry. The real `~/.claude` is
//! never read or written: HOME and CLAUDE_CONFIG_DIR both point into a temp dir.

#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ms_connect::claude::{ClaudeConnector, Options, Paths};
use ms_connect::{ConnectCfg, Connector};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/claude")
}

fn doctor(home: &Path, cfg: &Path) -> String {
    let out = Command::new("claude")
        .arg("doctor")
        .current_dir(home)
        .env("HOME", home)
        .env("CLAUDE_CONFIG_DIR", cfg)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("claude on PATH");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

// protects=the live card check: Claude Code itself accepts every key, hook and MCP entry the
// connector writes (no "Invalid settings"), and reads the ms server as the env -i stdio entry;
// fails_when=Claude Code rejects or ignores anything morsec writes; no_claim=runtime behaviour of
// the sandbox proxy (needs a signed-in session)
#[test]
fn claude_code_accepts_the_block() {
    if std::env::var_os("MORSEC_LIVE_CLAUDE").is_none() {
        eprintln!("skipped: set MORSEC_LIVE_CLAUDE=1 to run against the installed claude");
        return;
    }
    for case in ["empty", "typical", "complex"] {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let cfg_dir = home.join(".claude");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let g = golden_dir().join(case);
        if let Ok(t) = std::fs::read_to_string(g.join("settings.before.json")) {
            let corp = d.path().join("corp.pem");
            std::fs::copy(golden_dir().join("roots.pem"), &corp).unwrap();
            std::fs::write(
                cfg_dir.join("settings.json"),
                t.replace("CORP_CA_PATH", corp.to_str().unwrap()),
            )
            .unwrap();
        }
        if let Ok(t) = std::fs::read_to_string(g.join("claude.before.json")) {
            std::fs::write(cfg_dir.join(".claude.json"), t).unwrap();
        }
        let mut paths = Paths::for_home(&home, Some(&cfg_dir));
        paths.system_roots = golden_dir().join("roots.pem");
        let mut c = ClaudeConnector::new(paths, "/opt/homebrew/bin/ms", "/tmp/msd.sock");
        c.opts = Options {
            with_mcp: true,
            wrap: case == "complex",
            statusline: true,
            force: false,
        };
        let mut env = c.ca_env().unwrap();
        env.push(("STRIPE_API_KEY".into(), "ms://stripe/test".into()));
        let cfg = ConnectCfg {
            proxy_port: 4101,
            allowed_domains: vec!["api.stripe.com".into(), "*.stripe.com".into()],
            env,
            shim_dir: Some(c.paths.shims.clone()),
        };
        let p = c.try_plan(&cfg).unwrap();
        c.apply(&p.diff).unwrap();
        let text = doctor(&home, &cfg_dir);
        assert!(text.contains("Claude Code doctor"), "{text}");
        assert!(!text.contains("Invalid settings"), "{case}:\n{text}");
        let mcp = Command::new("claude")
            .args(["mcp", "get", "ms"])
            .current_dir(&home)
            .env("HOME", &home)
            .env("CLAUDE_CONFIG_DIR", &cfg_dir)
            .output()
            .unwrap();
        let mcp = String::from_utf8_lossy(&mcp.stdout);
        assert!(
            mcp.contains("User config") && mcp.contains("Command: /usr/bin/env"),
            "{case}: {mcp}"
        );

        // Negative control: the same doctor run reports a bad entry.
        let s = std::fs::read_to_string(cfg_dir.join("settings.json")).unwrap();
        std::fs::write(
            cfg_dir.join("settings.json"),
            s.replace("\"httpProxyPort\": 4101", "\"httpProxyPort\": \"4101\""),
        )
        .unwrap();
        assert!(
            doctor(&home, &cfg_dir).contains("Invalid settings"),
            "{case}: doctor did not flag a bad entry, so the check above proves nothing"
        );
    }
}
