//! The dashboard's actions end to end (L33 dash-actions): a dev msd (`common::Fx`), a real
//! `ms init`, curl as the browser from outside the agent tree, and a fake `claude` that tries the
//! same from inside one.

// `--test-touch-id`, `--test-open-to` and `--test-pasteboard-to` exist only in debug builds.
#![cfg(debug_assertions)]

mod common;

use common::{Fx, parse_url, session_script};

const STRIPE: &str = concat!("sk_test_", "51ACTSvalueACTSvalueACTSvalue00");
const OAI: &str = concat!("sk-", "proj-", "ACTSoaiACTSoaiACTSoaiACTSoai0123");
const SESSION: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const NEW: &str = concat!("sk_test_", "51ACTSnewACTSnewACTSnewACTS000");
const ADDED: &str = concat!("sk_live_", "ACTSaddedACTSaddedACTSadded00");

fn env_text() -> String {
    format!(
        "STRIPE_SECRET_KEY={STRIPE}\nOPENAI_API_KEY=\"{OAI}\"\nSESSION_SECRET={SESSION}\nPORT=3000\n"
    )
}

fn no_values(what: &str, text: &str) {
    for v in [STRIPE, OAI, SESSION, NEW, ADDED] {
        assert!(!text.contains(v), "{what} holds a value: {text}");
        assert!(
            !text.contains(&v[v.len() - 12..]),
            "{what} holds part of a value"
        );
    }
}

/// Every action route with a body it accepts.
const ROUTES: &[(&str, &str, &str)] = &[
    ("stop", "/api/stop", "{}"),
    ("start", "/api/start", "{}"),
    ("approve", "/api/approvals/apr-0/approve", "{}"),
    ("deny", "/api/approvals/apr-0/deny", "{}"),
    ("dismiss", "/api/warnings/w-0/dismiss", "{}"),
    ("recheck", "/api/agents/recheck", "{}"),
    ("scan", "/api/scan/run", "{}"),
    ("check", "/api/projects/check-path", "{\"path\":\"/tmp\"}"),
    (
        "rules",
        "/api/keys/shop%2Fsession-secret/rules",
        "{\"edit\":{\"add_host\":\"api.example.com\"}}",
    ),
    ("show", "/api/keys/shop%2Fstripe-secret-key/show", "{}"),
    ("copy", "/api/keys/shop%2Fstripe-secret-key/copy", "{}"),
    (
        "replace",
        "/api/keys/shop%2Fstripe-secret-key/replace",
        "{\"value\":\"x\"}",
    ),
    (
        "add",
        "/api/keys",
        "{\"key\":\"a/b\",\"value\":\"x\",\"mode\":\"swap\",\"tier\":\"test\"}",
    ),
    (
        "delete",
        "/api/keys/shop%2Fstripe-secret-key/delete",
        "{\"force\":true}",
    ),
    ("undokey", "/api/keys/shop%2Fstripe-secret-key/undo", "{}"),
    ("undo", "/api/projects/shop/undo", "{}"),
];

// protects=SPEC criterion 18, T-93 (an agent with Automation over a browser, or curl in its
// session): a fake `claude` that posts to every action route, with a real session cookie and
// CSRF token the user's browser got, never gets a byte back, nothing changes, and msd records
// a blocked receipt charged to the claude-code session; fails_when=any action route answers the
// agent's process tree; no_claim=a detached same-user process (T-04, T-93 residual)
#[test]
fn agent_tree_cannot_act() {
    let fx = Fx::new();
    let root = fx.init_shop(&env_text());
    let base = fx.base();
    let (code, out) = fx.outside(&root, r#""$MS" dashboard shop"#);
    assert_eq!(code, 0, "{out}");
    let (port, token) = parse_url(&fx.url());
    let agent = fx.fake_agent();
    // The user signs in; the agent reuses the session it read from the browser.
    let (code, out) = fx.outside(
        &base,
        &format!(
            "PORT={port}; TOKEN={token}\n{}echo \"COOKIE=$COOKIE CSRF=$CSRF\"",
            session_script(&base)
        ),
    );
    assert_eq!(code, 0, "{out}");
    let cookie = out
        .split("COOKIE=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_owned();
    let csrf = out.split("CSRF=").nth(1).unwrap().trim().to_owned();
    let mut script = String::new();
    for (name, path, body) in ROUTES {
        script.push_str(&format!(
            "'{agent}' curl -s -o '{base}/agent-{name}.out' -w '{name}=%{{http_code}} ' -H 'Host: 127.0.0.1:{port}' -H 'Origin: http://127.0.0.1:{port}' -H 'Content-Type: application/json' -H 'Cookie: ms_dash={cookie}' -H 'X-Morsec-CSRF: {csrf}' -H 'Sec-Fetch-Site: same-origin' --data '{body}' http://127.0.0.1:{port}{path}\n",
            agent = agent.display(),
            base = base.display(),
        ));
    }
    let (_, out) = fx.outside(&base, &script);
    for (name, _, _) in ROUTES {
        assert!(out.contains(&format!("{name}=000")), "{name}: {out}");
        let got = std::fs::read(base.join(format!("agent-{name}.out"))).unwrap_or_default();
        assert!(got.is_empty(), "{name}: {}", String::from_utf8_lossy(&got));
    }
    assert_eq!(
        std::fs::read_to_string(root.join(".env"))
            .unwrap()
            .matches("ms://shop/")
            .count(),
        3,
        "nothing was undone"
    );
    assert!(!base.join("paste.txt").exists(), "nothing was copied");
    let r = fx.receipts();
    assert!(r.contains("a connection from an agent session"), "{r}");
    assert!(r.contains("claude_code"), "{r}");
    assert!(
        !r.contains("{\"other\":\"dashboard\"}"),
        "no action ran under the browser's session"
    );
    for t in [
        "dashboard: show",
        "dashboard: copy",
        "dashboard: undo",
        "dashboard: stop",
    ] {
        assert!(!r.contains(t), "{t} ran");
    }
}

// protects=SPEC criteria 9 to 19 and 22 end to end: after a real `ms init`, the user's browser
// (curl, outside the agent) takes every action through the dashboard: rules, show, copy,
// replace, add, delete, undo, stop, start, scan, re-check, check-path; Touch ID (the test
// stand-in) is raised by msd; only Show's answer holds a value; the copy reaches the test
// pasteboard with its markers and no value; the receipts, msd's log, every other answer and
// `ms undo`'s IPC reply hold no value; fails_when=any canary appears outside Show's answer or an
// action fails; no_claim=the real Touch ID sheet, pasteboard and browser (manual QA)
#[test]
fn dashboard_actions_end_to_end() {
    let fx = Fx::new();
    let root = fx.init_shop(&env_text());
    let base = fx.base();
    let (code, out) = fx.outside(&root, r#""$MS" dashboard shop"#);
    assert_eq!(code, 0, "{out}");
    let (port, token) = parse_url(&fx.url());
    let steps = format!(
        r#"PORT={port}; TOKEN={token}
{session}
post rules /api/keys/shop%2Fsession-secret/rules '{{"edit":{{"add_host":"api.example.com"}}}}'
post tighten /api/keys/shop%2Fsession-secret/rules '{{"edit":{{"remove_host":"api.example.com"}}}}'
post show /api/keys/shop%2Fstripe-secret-key/show '{{}}'
post copy /api/keys/shop%2Fstripe-secret-key/copy '{{}}'
post replace /api/keys/shop%2Fopenai-api-key/replace '{{"value":"{NEW}"}}'
post add /api/keys '{{"key":"loose/added","value":"{ADDED}","mode":"swap","tier":"test"}}'
post addagain /api/keys '{{"key":"loose/added","value":"{ADDED}","mode":"swap","tier":"test"}}'
post delete-ref /api/keys/shop%2Fsession-secret/delete '{{"force":false}}'
post delete /api/keys/loose%2Fadded/delete '{{"force":false}}'
post check /api/projects/check-path '{{"path":"{root}"}}'
post checkhome /api/projects/check-path '{{"path":"{home}"}}'
post recheck /api/agents/recheck '{{}}'
post undokey /api/keys/shop%2Fstripe-secret-key/undo '{{}}'
post stop /api/stop '{{}}'
post showstopped /api/keys/shop%2Fsession-secret/show '{{}}'
post start /api/start '{{}}'
post scan /api/scan/run '{{}}'
sleep 1
get scanview /api/scan
get home /api/home
get activity '/api/activity?since=30d&agent=dashboard'
get secret /api/keys/shop%2Fsession-secret
"#,
        session = session_script(&base),
        root = root.display(),
        home = base.join("home").display(),
    );
    let (code, out) = fx.outside(&base, &steps);
    assert_eq!(code, 0, "{out}");
    let act = base.join("act");
    let read = |n: &str| {
        (
            std::fs::read_to_string(act.join(format!("{n}.code"))).unwrap_or_default(),
            std::fs::read_to_string(act.join(format!("{n}.json"))).unwrap_or_default(),
        )
    };
    let want = [
        ("rules", "200"),
        ("tighten", "200"),
        ("show", "200"),
        ("copy", "200"),
        ("replace", "200"),
        ("add", "200"),
        ("addagain", "400"),
        ("delete-ref", "409"),
        ("delete", "200"),
        ("check", "200"),
        ("checkhome", "200"),
        ("recheck", "200"),
        ("undokey", "200"),
        ("stop", "200"),
        ("showstopped", "409"),
        ("start", "200"),
        ("scan", "202"),
        ("scanview", "200"),
        ("home", "200"),
        ("activity", "200"),
        ("secret", "200"),
    ];
    let mut others = String::new();
    for (n, code) in want {
        let (got, body) = read(n);
        assert_eq!(got, code, "{n}: {body}");
        if n != "show" {
            others.push_str(&body);
            others.push('\n');
        }
    }
    let (_, show) = read("show");
    let v: serde_json::Value = serde_json::from_str(&show).unwrap();
    assert_eq!(v["value"], STRIPE);
    assert_eq!(v["hide_after_ms"], 15000);
    assert!(read("checkhome").1.contains("home folder"));
    assert!(read("check").1.contains("ms init"));
    assert!(read("addagain").1.contains("ms set loose/added"));
    assert!(
        read("delete-ref").1.contains("shop .env:3"),
        "{}",
        read("delete-ref").1
    );
    let env = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(
        env.starts_with(&format!("STRIPE_SECRET_KEY={STRIPE}\n")),
        "{env}"
    );

    // The copy went to msd's (test) pasteboard with every marker, never as the value.
    let paste = std::fs::read_to_string(base.join("paste.txt")).unwrap();
    assert!(
        paste.contains("\"concealed\"") && paste.contains("\"transient\""),
        "{paste}"
    );
    assert!(paste.contains("current-host-only"), "{paste}");
    no_values("pasteboard file", &paste);

    // Undo over IPC: its reply has names only.
    let (code, out) = fx.at_terminal(&root, &[], r#""$MS" undo shop"#);
    assert_eq!(code, 0, "{out}");
    no_values("ms undo", &out);

    no_values("action answers", &others);
    let r = fx.receipts();
    for t in [
        "dashboard: show value",
        "dashboard: copy value",
        "dashboard: replace value",
        "dashboard: add key",
        "dashboard: delete key",
        "dashboard: undo",
        "dashboard: stop",
        "dashboard: start",
        "dashboard: scan",
        "dashboard: rules change (loosen)",
        "dashboard: rules change (tighten)",
    ] {
        assert!(r.contains(t), "no receipt for {t}");
    }
    no_values("receipts", &r);
    no_values("msd log", &fx.log());
}
