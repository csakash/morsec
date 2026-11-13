//! The Claude Code connector against real files in a temp HOME (never the real `~/.claude`).
//!
//! Goldens live in `tests/golden/claude/<case>/`: `settings.before.json` and `claude.before.json`
//! are inputs (absent = no file); `*.after.json` and `bundle.pem` are the expected outputs, with
//! the temp home written as `$HOME` and the corporate CA path as `CORP_CA_PATH`. Regenerate with
//! `UPDATE_GOLDEN=1 cargo test -p ms-connect --test claude`, then review the diff.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};

use ms_connect::claude::json::{self, Value};
use ms_connect::claude::{ClaudeConnector, Options, Paths, check_ref_env};
use ms_connect::{ConnectCfg, Connector};

const MS: &str = "/opt/homebrew/bin/ms";
const SOCKET: &str = "/Users/u/Library/Application Support/morsec/msd.sock";
const CA: &str = "-----BEGIN CERTIFICATE-----\nTU9SU0VDLUNB\n-----END CERTIFICATE-----\n";
const CORP: &str = "-----BEGIN CERTIFICATE-----\nQ09SUC1DQQ==\n-----END CERTIFICATE-----\n";

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/claude")
}

struct Home {
    dir: tempfile::TempDir,
    corp: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let corp = dir.path().join("corp-ca.pem");
        std::fs::write(&corp, CORP).unwrap();
        Self { dir, corp }
    }
    fn home(&self) -> &Path {
        self.dir.path()
    }
    fn connector(&self, opts: Options) -> ClaudeConnector {
        let mut paths = Paths::for_home(self.home(), None);
        paths.system_roots = golden_dir().join("roots.pem");
        let mut c = ClaudeConnector::new(paths, MS, SOCKET);
        c.ca_pem = Some(CA.into());
        c.opts = opts;
        c
    }
    fn cfg(&self, c: &ClaudeConnector) -> ConnectCfg {
        let mut env = c.ca_env().unwrap();
        env.push(("STRIPE_API_KEY".into(), "ms://stripe/test".into()));
        ConnectCfg {
            proxy_port: 4101,
            allowed_domains: vec!["api.stripe.com".into(), "*.stripe.com".into()],
            env,
            shim_dir: Some(c.paths.shims.clone()),
        }
    }
    fn settings(&self) -> PathBuf {
        self.home().join(".claude/settings.json")
    }
    fn claude_json(&self) -> PathBuf {
        self.home().join(".claude.json")
    }
    fn read(&self, p: &Path) -> Option<String> {
        std::fs::read_to_string(p).ok()
    }
    /// Puts a case's inputs in place.
    fn load(&self, case: &str) {
        let g = golden_dir().join(case);
        if let Ok(t) = std::fs::read_to_string(g.join("settings.before.json")) {
            std::fs::create_dir_all(self.home().join(".claude")).unwrap();
            std::fs::write(self.settings(), self.fill(&t)).unwrap();
        }
        if let Ok(t) = std::fs::read_to_string(g.join("claude.before.json")) {
            std::fs::write(self.claude_json(), self.fill(&t)).unwrap();
        }
    }
    fn fill(&self, t: &str) -> String {
        t.replace("CORP_CA_PATH", self.corp.to_str().unwrap())
            .replace("$HOME", self.home().to_str().unwrap())
    }
    fn unfill(&self, t: &str) -> String {
        t.replace(self.corp.to_str().unwrap(), "CORP_CA_PATH")
            .replace(self.home().to_str().unwrap(), "$HOME")
    }
    fn snapshot(&self) -> (Option<String>, Option<String>) {
        (self.read(&self.settings()), self.read(&self.claude_json()))
    }
}

fn check_golden(case: &str, name: &str, actual: Option<String>) {
    let p = golden_dir().join(case).join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        match &actual {
            Some(t) => std::fs::write(&p, t).unwrap(),
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
        return;
    }
    let expected = std::fs::read_to_string(&p).ok();
    assert_eq!(
        actual, expected,
        "{case}/{name} differs from the golden (UPDATE_GOLDEN=1 to regenerate, then review)"
    );
}

fn connect(h: &Home, opts: Options) -> Vec<String> {
    let c = h.connector(opts);
    let planned = c.try_plan(&h.cfg(&c)).unwrap();
    c.apply(&planned.diff).unwrap();
    planned.warnings
}

fn cases() -> [(&'static str, Options); 3] {
    [
        ("empty", Options::default()),
        (
            "typical",
            Options {
                statusline: true,
                ..Options::default()
            },
        ),
        (
            "complex",
            Options {
                with_mcp: true,
                wrap: true,
                statusline: true,
                force: false,
            },
        ),
    ]
}

// protects=SPEC acceptance 1: golden diffs for an empty, a typical and a complex settings file
// (and ~/.claude.json with --with-mcp --wrap); fails_when=the block, merge, ordering, indent or
// bundle differs from the reviewed goldens; no_claim=Claude Code accepting the file (live check)
#[test]
fn goldens() {
    for (case, opts) in cases() {
        let h = Home::new();
        h.load(case);
        let warnings = connect(&h, opts);
        check_golden(
            case,
            "settings.after.json",
            h.read(&h.settings()).map(|t| h.unfill(&t)),
        );
        check_golden(
            case,
            "claude.after.json",
            h.read(&h.claude_json()).map(|t| h.unfill(&t)),
        );
        check_golden(
            case,
            "bundle.pem",
            h.read(&h.home().join(".morsec/ca-bundle.pem"))
                .map(|t| h.unfill(&t)),
        );
        check_golden(
            case,
            "warnings.txt",
            Some(h.unfill(&warnings.join("\n")) + "\n"),
        );
    }
}

// protects=SPEC acceptance 2 and the card's "disconnect restores the original exactly": connect
// then disconnect gives byte-identical files for every golden and for odd formatting;
// fails_when=any byte differs or a morsec file is left behind
#[test]
fn round_trip_is_byte_identical() {
    let odd = [
        "{\n    \"a\": 1\n}",
        "{\n\t\"a\": [1, 2, 3],\n\t\"b\": {}\n}\n",
        "{\"compact\":true,\"n\":1.0e-7}",
        "{\r\n  \"crlf\": true\r\n}\r\n",
        "  {\n  \"leading\": \"ws\", \"x\": \"\\u00e9\\/\"\n}\n\n",
        "{}",
    ];
    for (case, opts) in cases() {
        let h = Home::new();
        h.load(case);
        let before = h.snapshot();
        connect(&h, opts);
        assert_ne!(h.snapshot(), before, "{case}: nothing was written");
        h.connector(opts).remove().unwrap();
        assert_eq!(h.snapshot(), before, "{case}: not restored exactly");
        assert!(!h.home().join(".morsec/connect/claude-code.json").exists());
        assert!(!h.home().join(".morsec/ca-bundle.pem").exists());
    }
    for text in odd {
        let h = Home::new();
        std::fs::create_dir_all(h.home().join(".claude")).unwrap();
        std::fs::write(h.settings(), text).unwrap();
        connect(&h, Options::default());
        h.connector(Options::default()).remove().unwrap();
        assert_eq!(h.read(&h.settings()).as_deref(), Some(text));
    }
}

// protects=SPEC acceptance 3: connect is idempotent; a second identical run changes no file and
// keeps the original bytes in the state; fails_when=a second run rewrites anything or loses the
// original
#[test]
fn connect_is_idempotent() {
    for (case, opts) in cases() {
        let h = Home::new();
        h.load(case);
        let before = h.snapshot();
        connect(&h, opts);
        let once = h.snapshot();
        let state = h.read(&h.home().join(".morsec/connect/claude-code.json"));
        let c = h.connector(opts);
        let again = c.try_plan(&h.cfg(&c)).unwrap();
        assert!(again.diff.changes.is_empty(), "{case}: {:?}", again.diff);
        connect(&h, opts);
        assert_eq!(h.snapshot(), once);
        assert_eq!(
            h.read(&h.home().join(".morsec/connect/claude-code.json")),
            state
        );
        // A changed port updates in place; disconnect still restores the first original.
        let mut cfg = h.cfg(&c);
        cfg.proxy_port = 4201;
        let p = c.try_plan(&cfg).unwrap();
        c.apply(&p.diff).unwrap();
        assert!(h.read(&h.settings()).unwrap().contains("4201"));
        c.remove().unwrap();
        assert_eq!(h.snapshot(), before, "{case}");
    }
}

// protects=SPEC acceptance 4 (D7): a user edit made after connect survives disconnect, and every
// morsec change is still removed; fails_when=the user's edit is lost or a morsec key remains
#[test]
fn user_edits_survive_disconnect() {
    let h = Home::new();
    h.load("typical");
    connect(&h, Options::default());
    let text = h.read(&h.settings()).unwrap();
    let mut v = json::parse(&text).unwrap();
    v.set("theme", Value::str("dark"));
    v.get_mut("env").unwrap().set("MY_VAR", Value::str("1"));
    std::fs::write(h.settings(), json::print_doc(&v, "  ", true)).unwrap();
    let c = h.connector(Options::default());
    let plan = c.plan_remove().unwrap().unwrap();
    assert!(
        plan.notes.iter().any(|n| n.contains("kept yours")),
        "{:?}",
        plan.notes
    );
    c.apply_remove(&plan).unwrap();
    let after = h.read(&h.settings()).unwrap();
    let v = json::parse(&after).unwrap();
    assert_eq!(v.get("theme"), Some(&Value::str("dark")));
    assert_eq!(
        v.at(&["env".into(), "MY_VAR".into()]),
        Some(&Value::str("1"))
    );
    for gone in [
        "MORSEC_CONNECTED",
        "SSL_CERT_FILE",
        "STRIPE_API_KEY",
        "httpProxyPort",
        "msd.sock",
        "--session-env",
    ] {
        assert!(!after.contains(gone), "{gone} left in:\n{after}");
    }
    let orig = json::parse(
        &std::fs::read_to_string(golden_dir().join("typical/settings.before.json")).unwrap(),
    )
    .unwrap();
    let mut expect = orig;
    expect.set("theme", Value::str("dark"));
    expect
        .get_mut("env")
        .unwrap()
        .set("MY_VAR", Value::str("1"));
    assert_eq!(v, expect);
    // A key morsec set and the user then changed is left as the user has it.
    let h = Home::new();
    connect(&h, Options::default());
    let t = h.read(&h.settings()).unwrap().replace("4101", "9999");
    std::fs::write(h.settings(), &t).unwrap();
    let c = h.connector(Options::default());
    let plan = c.plan_remove().unwrap().unwrap();
    assert!(
        plan.notes.iter().any(|n| n.contains("httpProxyPort")),
        "{:?}",
        plan.notes
    );
    c.apply_remove(&plan).unwrap();
    assert!(h.read(&h.settings()).unwrap().contains("9999"));
}

// protects=SPEC acceptance 5 (D8): refusals change nothing and say why: symlinked settings,
// invalid JSON, duplicate keys, a non-object root, the user's own proxy port, a foreign
// mcpServers.ms; fails_when=any of them writes a file or succeeds silently
#[test]
fn refusals_change_nothing() {
    let cases: [(&str, &str, Options); 6] = [
        ("{\"a\": 1,}", "not valid JSON", Options::default()),
        (
            "{\"env\": {\"X\": \"1\", \"X\": \"2\"}}",
            "appears twice",
            Options::default(),
        ),
        ("[1, 2]", "must hold a JSON object", Options::default()),
        (
            "{\"env\": \"oops\"}",
            "an object was expected",
            Options::default(),
        ),
        (
            "{\"sandbox\": {\"network\": {\"httpProxyPort\": 8080}}}",
            "--force",
            Options::default(),
        ),
        (
            "{\"sandbox\": {\"network\": {\"allowedDomains\": \"x\"}}}",
            "a list was expected",
            Options::default(),
        ),
    ];
    for (text, why, opts) in cases {
        let h = Home::new();
        std::fs::create_dir_all(h.home().join(".claude")).unwrap();
        std::fs::write(h.settings(), text).unwrap();
        let c = h.connector(opts);
        let e = c.try_plan(&h.cfg(&c)).unwrap_err().to_string();
        assert!(e.contains(why), "{text}: {e}");
        assert_eq!(h.read(&h.settings()).as_deref(), Some(text));
        assert!(!h.home().join(".morsec").exists());
        // The trait's infallible plan() gives an empty diff, never a partial one.
        assert!(c.plan(&h.cfg(&c)).changes.is_empty());
    }
    // --force takes over the user's proxy port, and disconnect gives it back.
    let h = Home::new();
    std::fs::create_dir_all(h.home().join(".claude")).unwrap();
    let mine = "{\"sandbox\": {\"network\": {\"httpProxyPort\": 8080}}}";
    std::fs::write(h.settings(), mine).unwrap();
    let forced = Options {
        force: true,
        ..Options::default()
    };
    connect(&h, forced);
    assert!(h.read(&h.settings()).unwrap().contains("4101"));
    h.connector(forced).remove().unwrap();
    assert_eq!(h.read(&h.settings()).as_deref(), Some(mine));

    // A symlinked settings file is refused, never followed or replaced.
    let h = Home::new();
    std::fs::create_dir_all(h.home().join(".claude")).unwrap();
    let real = h.home().join("dotfiles-settings.json");
    std::fs::write(&real, "{}").unwrap();
    std::os::unix::fs::symlink(&real, h.settings()).unwrap();
    let c = h.connector(Options::default());
    assert!(
        c.try_plan(&h.cfg(&c))
            .unwrap_err()
            .to_string()
            .contains("symlink")
    );
    assert!(
        std::fs::symlink_metadata(h.settings())
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // A foreign mcpServers.ms is refused.
    let h = Home::new();
    std::fs::write(
        h.claude_json(),
        "{\"mcpServers\": {\"ms\": {\"command\": \"x\"}}}",
    )
    .unwrap();
    let c = h.connector(Options {
        with_mcp: true,
        ..Options::default()
    });
    assert!(
        c.try_plan(&h.cfg(&c))
            .unwrap_err()
            .to_string()
            .contains("--force")
    );

    // A raw value in --env is refused before anything is read or written.
    let h = Home::new();
    let c = h.connector(Options::default());
    let mut cfg = h.cfg(&c);
    cfg.env
        .push(("OPENAI_API_KEY".into(), "sk-live-123".into()));
    assert!(c.try_plan(&cfg).unwrap_err().to_string().contains("ms://"));
    assert!(!h.settings().exists());
}

// protects=apply is compare-and-swap: a file changed between plan and apply is not overwritten;
// fails_when=apply clobbers a concurrent edit
#[test]
fn apply_refuses_a_file_changed_since_plan() {
    let h = Home::new();
    h.load("typical");
    let c = h.connector(Options::default());
    let p = c.try_plan(&h.cfg(&c)).unwrap();
    std::fs::write(h.settings(), "{\"concurrent\": true}").unwrap();
    assert!(
        c.apply(&p.diff)
            .unwrap_err()
            .to_string()
            .contains("changed while")
    );
    assert_eq!(
        h.read(&h.settings()).as_deref(),
        Some("{\"concurrent\": true}")
    );
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

// protects=SDLC-2 (SPEC acceptance 7): the plan turns the sandbox on and routes it through msd,
// never writes a bypass, auto-approve, escape-hatch or exclusion setting, never sets proxy
// variables that would reroute Claude Code itself (D1), and warns about the user's own weak
// settings without changing them; fails_when=any of those keys is written or a warning is missing
#[test]
fn sdlc2_sandbox_on_and_no_bypass() {
    let h = Home::new();
    h.load("complex");
    let w = connect(
        &h,
        Options {
            with_mcp: true,
            wrap: true,
            statusline: true,
            force: false,
        },
    );
    let text = h.read(&h.settings()).unwrap();
    let v = json::parse(&text).unwrap();
    let at = |p: &[&str]| {
        v.at(&p.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .cloned()
    };
    assert_eq!(at(&["sandbox", "enabled"]), Some(Value::Bool(true)));
    assert_eq!(
        at(&["sandbox", "network", "httpProxyPort"]),
        Some(Value::int(4101))
    );
    // The user's own weakening settings are reported, not changed.
    assert!(w.iter().any(|m| m.contains("bypassPermissions")), "{w:?}");
    assert!(w.iter().any(|m| m.contains("excludedCommands")), "{w:?}");
    assert_eq!(
        at(&["permissions", "defaultMode"]),
        Some(Value::str("bypassPermissions"))
    );
    // Nothing morsec added weakens anything.
    let h2 = Home::new();
    connect(
        &h2,
        Options {
            with_mcp: true,
            wrap: true,
            statusline: true,
            force: false,
        },
    );
    let mut files = Vec::new();
    walk(h2.home(), &mut files);
    for f in files {
        let t = std::fs::read_to_string(&f).unwrap();
        for bad in [
            "bypassPermissions",
            "dangerously",
            "skip-permissions",
            "allowUnsandboxedCommands",
            "excludedCommands",
            "autoAllowBashIfSandboxed",
            "defaultMode",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "allowAllUnixSockets",
            "permissions",
        ] {
            assert!(!t.contains(bad), "{} contains {bad}", f.display());
        }
    }
}

// protects=SDLC-4 (SPEC acceptance 8): only user-scope files under HOME are written (never a
// project's .claude/ or .mcp.json, whatever the cwd), and verify() reports drift when the proxy
// port or the sandbox flag is edited; fails_when=a file outside HOME/.claude*, HOME/.morsec is
// written, or drift goes unreported
#[test]
fn sdlc4_user_scope_only_and_drift_reported() {
    let h = Home::new();
    let project = h.home().join("repo");
    std::fs::create_dir_all(project.join(".claude")).unwrap();
    let c = h.connector(Options {
        with_mcp: true,
        wrap: true,
        statusline: true,
        force: false,
    });
    let p = c.try_plan(&h.cfg(&c)).unwrap();
    for ch in &p.diff.changes {
        let rel = ch.path.strip_prefix(h.home()).unwrap();
        let top = rel
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_str()
            .unwrap();
        assert!(
            [".claude", ".claude.json", ".morsec"].contains(&top),
            "writes {}",
            ch.path.display()
        );
    }
    c.apply(&p.diff).unwrap();
    assert_eq!(
        std::fs::read_dir(project.join(".claude")).unwrap().count(),
        0
    );
    assert!(!project.join(".mcp.json").exists());

    assert!(c.verify().iter().all(|k| k.ok), "{:?}", c.verify());
    let t = h.read(&h.settings()).unwrap();
    std::fs::write(
        h.settings(),
        t.replace("\"httpProxyPort\": 4101", "\"httpProxyPort\": 9"),
    )
    .unwrap();
    let bad: Vec<_> = c.verify().into_iter().filter(|k| !k.ok).collect();
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].name.contains("proxy") && bad[0].detail.contains("ms connect claude-code"));
    std::fs::write(
        h.settings(),
        t.replace("\"enabled\": true", "\"enabled\": false"),
    )
    .unwrap();
    assert!(
        c.verify()
            .iter()
            .any(|k| !k.ok && k.name.contains("sandbox on"))
    );
    std::fs::write(h.claude_json(), "{}").unwrap();
    assert!(c.verify().iter().any(|k| !k.ok && k.name.contains("MCP")));
    // Not connected.
    let h = Home::new();
    let v = h.connector(Options::default()).verify();
    assert!(!v[0].ok && v[0].detail.contains("not connected"));
}

/// A fake `ms` that records its environment; a script run by /bin/sh (system shells can't be
/// copied on macOS).
fn env_recorder(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let out = dir.join("env.out");
    let script = dir.join("fake-ms");
    std::fs::write(
        &script,
        format!("#!/bin/sh\n/usr/bin/env > '{}'\n", out.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, out)
}

// protects=MCP-4 (SPEC acceptance 9, D4): the `ms mcp` server entry, spawned the way Claude Code
// spawns a stdio server (its command and args, with the parent's full environment plus the
// entry's env), gives the server only HOME, PATH and MORSEC_SOCKET: no provider key, token or
// other inherited variable; fails_when=any parent variable reaches the server
#[test]
fn mcp4_server_gets_a_minimal_env() {
    let h = Home::new();
    let (fake_ms, out) = env_recorder(h.home());
    let mut paths = Paths::for_home(h.home(), None);
    paths.system_roots = golden_dir().join("roots.pem");
    let mut c = ClaudeConnector::new(paths, fake_ms.to_str().unwrap(), SOCKET);
    c.socket_env = Some("/tmp/morsec-dev-4100/msd.sock".into());
    let entry = c.mcp_entry().unwrap();
    let cmd = entry.get("command").and_then(Value::as_str).unwrap();
    let args: Vec<String> = entry
        .get("args")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect();
    let st = std::process::Command::new(cmd)
        .args(&args)
        .env("ANTHROPIC_API_KEY", "sk-ant-CANARY-provider-key")
        .env("CLAUDE_CODE_OAUTH_TOKEN", "CANARY-oauth")
        .env("AWS_SECRET_ACCESS_KEY", "CANARY-aws")
        .env("STRIPE_API_KEY", "ms://stripe/test")
        .status()
        .unwrap();
    assert!(st.success());
    let got = std::fs::read_to_string(&out).unwrap();
    assert!(!got.contains("CANARY"), "{got}");
    let mut names: Vec<&str> = got.lines().filter_map(|l| l.split('=').next()).collect();
    names.sort_unstable();
    // /bin/sh adds PWD (and may add SHLVL, _) itself; nothing comes from the parent.
    let allowed = [
        "HOME",
        "MORSEC_SOCKET",
        "OLDPWD",
        "PATH",
        "PWD",
        "SHLVL",
        "_",
    ];
    assert!(names.iter().all(|n| allowed.contains(n)), "{names:?}");
    assert!(got.contains(&format!("HOME={}", h.home().display())));
    assert!(got.contains("PATH=/usr/bin:/bin"));
    assert!(got.contains("MORSEC_SOCKET=/tmp/morsec-dev-4100/msd.sock"));
    assert_eq!(entry.get("env"), Some(&Value::object()));
}

// protects=--wrap (D3): every plain command hook and local stdio MCP server runs through
// `ms run --` with its argv intact (shell form via /bin/sh -c), while http and PowerShell hooks,
// remote servers and morsec's own hook are left alone; disconnect restores them exactly;
// fails_when=an argv element is lost or reordered, or a non-command entry is wrapped
#[test]
fn wrap_keeps_argv_and_restores() {
    let h = Home::new();
    h.load("complex");
    let before = h.snapshot();
    let opts = Options {
        with_mcp: true,
        wrap: true,
        statusline: false,
        force: false,
    };
    connect(&h, opts);
    let v = json::parse(&h.read(&h.settings()).unwrap()).unwrap();
    let pre = v
        .at(&["hooks".into(), "PreToolUse".into()])
        .unwrap()
        .as_array()
        .unwrap()[0]
        .get("hooks")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    let argv = |h: &Value| -> Vec<String> {
        h.get("args").and_then(Value::as_array).map_or(vec![], |a| {
            a.iter().map(|x| x.as_str().unwrap().to_owned()).collect()
        })
    };
    assert_eq!(pre[0].get("command"), Some(&Value::str(MS)));
    assert_eq!(
        argv(&pre[0]),
        ["run", "--", "/bin/sh", "-c", "echo 'pre' | tee -a /tmp/log"]
    );
    assert_eq!(pre[0].get("timeout"), Some(&Value::int(30)));
    assert_eq!(
        argv(&pre[1]),
        ["run", "--", "node", "/opt/hooks/check.js", "--strict"]
    );
    assert_eq!(pre[2].get("type"), Some(&Value::str("http")));
    assert_eq!(pre[3].get("command"), Some(&Value::str("Write-Host hi")));
    let ss = v
        .at(&["hooks".into(), "SessionStart".into()])
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(ss.len(), 2);
    assert_eq!(
        argv(&ss[1].get("hooks").unwrap().as_array().unwrap()[0]),
        ["connect", "claude-code", "--session-env"]
    );

    let cj = json::parse(&h.read(&h.claude_json()).unwrap()).unwrap();
    let srv = |p: &[&str]| {
        cj.at(&p.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .unwrap()
            .clone()
    };
    assert_eq!(
        argv(&srv(&["mcpServers", "db"])),
        ["run", "--", "npx", "-y", "@bytebase/dbhub"]
    );
    assert_eq!(
        argv(&srv(&["mcpServers", "local"])),
        ["run", "--", "/opt/mcp/server"]
    );
    assert!(srv(&["mcpServers", "github"]).get("url").is_some());
    assert_eq!(srv(&["mcpServers", "github"]).get("args"), None);
    assert_eq!(
        argv(&srv(&[
            "projects",
            "/Users/u/repo",
            "mcpServers",
            "repo-tool"
        ])),
        ["run", "--", "python3", "tools/server.py"]
    );
    assert_eq!(
        srv(&["mcpServers", "ms"]).get("command"),
        Some(&Value::str("/usr/bin/env"))
    );

    // ~/.claude.json is rewritten by Claude Code all the time: an unrelated change there is
    // kept, and morsec's own entries still come out.
    let mut cj2 = cj.clone();
    cj2.set("numStartups", Value::int(43));
    std::fs::write(h.claude_json(), json::print_doc(&cj2, "  ", true)).unwrap();
    h.connector(opts).remove().unwrap();
    assert_eq!(h.read(&h.settings()), before.0);
    let mut expect = json::parse(before.1.as_deref().unwrap()).unwrap();
    expect.set("numStartups", Value::int(43));
    assert_eq!(
        json::parse(&h.read(&h.claude_json()).unwrap()).unwrap(),
        expect
    );
}

// protects=--with-mcp with no ~/.claude.json creates one holding only the server, and
// disconnect leaves an empty object; re-connect without --with-mcp removes the server;
// fails_when=the server lingers after it is no longer requested
#[test]
fn mcp_toggle() {
    let h = Home::new();
    let opts = Options {
        with_mcp: true,
        ..Options::default()
    };
    connect(&h, opts);
    assert!(h.read(&h.claude_json()).unwrap().contains("\"ms\""));
    connect(&h, Options::default());
    assert!(!h.read(&h.claude_json()).unwrap().contains("\"ms\""));
    h.connector(Options::default()).remove().unwrap();
    assert!(!h.settings().exists());
}

// protects=the bundle holds system roots, the daemon's CA (from Status, not ca.pem) and only the
// certificate blocks of a CA file the user's settings named; fails_when=a key or other non-cert
// text from that file is copied
#[test]
fn bundle_copies_only_certificates() {
    let h = Home::new();
    std::fs::write(
        &h.corp,
        format!("-----BEGIN PRIVATE KEY-----\nU0VDUkVU\n-----END PRIVATE KEY-----\n{CORP}"),
    )
    .unwrap();
    h.load("complex");
    connect(&h, Options::default());
    let b = h.read(&h.home().join(".morsec/ca-bundle.pem")).unwrap();
    assert!(
        b.contains("Q09SUC1DQQ==")
            && b.contains("TU9SU0VDLUNB")
            && b.contains("U1lTVEVNLVJPT1QtMQ==")
    );
    assert!(!b.contains("PRIVATE") && !b.contains("U0VDUkVU"));
    // The CA variables point at the bundle; disconnect puts the user's own path back.
    h.connector(Options::default()).remove().unwrap();
    assert!(
        h.read(&h.settings())
            .unwrap()
            .contains(h.corp.to_str().unwrap())
    );
}

#[test]
fn env_names_and_refs() {
    assert!(check_ref_env("GITHUB_TOKEN", "ms://github/ci").is_ok());
    assert!(check_ref_env("GITHUB_TOKEN", "ghp_xxx").is_err());
}
