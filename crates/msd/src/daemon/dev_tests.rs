// L34 `ms dev` tests, included into `daemon::tests::dev_tests` so they share its harness.

use crate::daemon::dev::{dev_session_id, run_env};
use std::collections::BTreeMap;
use std::path::Path;

/// A project `shop` with a test-tier Stripe swap key and a run-mode database URL (tiers as
/// given), its first rules saved with one approval.
fn dev_shop(h: &H, stripe: Tier, db: Tier) -> ms_projects::record::ProjectRecord {
    h.put(STRIPE_KEY, stripe);
    put_mode(h, DB_KEY, Mode::Run, db);
    let rec = project(h, &[(STRIPE_KEY, Some("stripe")), (DB_KEY, Some("pg"))]);
    let rules = proposal(h, &rec);
    let r = h.approved(|| save(h, &rec, &rules));
    assert!(is_ok(&r), "{r:?}");
    rec
}

fn dev_start(h: &H, argv: &[&str], cwd: &Path) -> (ResponseBody, Vec<SecretBytes>) {
    h.d.handle_values(
        &peer(),
        RequestBody::DevStart {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: cwd.to_path_buf(),
        },
        None,
    )
}

fn started(r: &ResponseBody) -> (String, String, Vec<String>) {
    match r {
        ResponseBody::DevStarted {
            session,
            credential,
            env,
            ..
        } => (session.clone(), credential.clone(), env.clone()),
        other => panic!("{other:?}"),
    }
}

/// The dev session `terminal()` (pid 43, started 1) gets.
fn dev_id() -> SessionId {
    dev_session_id(43, 1)
}

fn swap_as(h: &H, s: &SessionId, key: &str, host: &str) -> Decision {
    h.d.decide(
        s,
        &Request::Swap {
            key: KeyName::new(key).unwrap(),
            host: host.into(),
        },
    )
    .0
}

// protects=L34 SPEC criterion 1 / design §8 "Agent starts ms dev to get raw run-mode values":
// DevStart from an agent session is Denied with no value, no session and no approval asked, and
// DevEnd from an agent is Denied too; fails_when=an agent gets a value, a credential or a prompt;
// no_claim=a detached same-user process (not an agent session; SPEC residual, T-82)
#[test]
fn dev_refused_in_agent_session() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let asked = h.auth.reasons().len();
    let (r, values) = dev_start(h.as_(agent()), &["npm", "run", "dev"], Path::new(&rec.root));
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    assert!(msg(&r).contains("agent session"), "{r:?}");
    assert!(values.is_empty());
    assert_eq!(h.d.dev.len(), 0);
    assert_eq!(h.auth.reasons().len(), asked, "no approval was asked");
    let r = h.as_(agent()).req(RequestBody::DevEnd {
        session: "x".into(),
    });
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    // The plain request path never serves DevStart (values can't go back on it).
    let r = h.as_(terminal()).req(RequestBody::DevStart {
        argv: vec!["npm".into()],
        cwd: PathBuf::from(&rec.root),
    });
    assert_eq!(code(&r), Some(ErrorCode::Protocol), "{r:?}");
    assert_eq!(h.d.dev.len(), 0);
}

// protects=L34 SPEC criterion 2 (design §7.1): msd refuses DevStart whose argv[0] is a coding
// agent, by bare name or by path; a lookalike name is not refused; fails_when=claude, codex,
// cursor-agent or gemini get a dev session; no_claim=symlinks and PATH lookup (ms dev's own
// check, crates/ms-cli/src/dev.rs::dev_refused_for_agent_binary)
#[test]
fn dev_refused_for_agent_binary() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let root = PathBuf::from(&rec.root);
    for argv0 in [
        "claude",
        "codex",
        "cursor-agent",
        "gemini",
        "/usr/local/bin/claude",
        "./node_modules/.bin/codex",
    ] {
        let (r, values) = dev_start(&h, &[argv0, "-p", "hi"], &root);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{argv0}: {r:?}");
        assert!(values.is_empty());
    }
    assert_eq!(h.d.dev.len(), 0);
    let (r, _) = dev_start(&h, &["claude-helper"], &root);
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    let (r, _) = dev_start(&h, &[], &root);
    assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
}

// protects=L34 SPEC criteria 3-4 (design §7.4): a dev session swaps its project's keys to their
// hosts (test tier: allowed), never another key (NoSuchKey) or another host; the credential maps
// to the session; receipts record the start and the env value under other("ms-dev"); a session
// msd doesn't hold is denied; fails_when=a dev session reaches a key outside its project or a
// host its rule doesn't name; no_claim=the process-tree binding (proxy::tests) and the live swap
// (e2e)
#[test]
fn dev_swaps_refs_for_child_tree() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    h.put("stripe/other", Tier::Test);
    let (r, _) = dev_start(&h, &["npm", "run", "dev"], Path::new(&rec.root));
    let (_, cred, _) = started(&r);
    assert!(ms_session::is_dev_proxy_user(&cred), "{cred}");
    assert_eq!(h.d.dev_by_credential(&cred), Some(dev_id()));
    assert!(matches!(&r, ResponseBody::DevStarted { swapped, .. } if swapped == &[STRIPE_KEY]));
    let dev = dev_id();
    assert_eq!(
        swap_as(&h, &dev, STRIPE_KEY, "api.stripe.com"),
        Decision::Allow
    );
    assert!(matches!(
        swap_as(&h, &dev, STRIPE_KEY, "evil.example"),
        Decision::Deny {
            reason: Reason::HostNotAllowed
        }
    ));
    assert!(matches!(
        swap_as(&h, &dev, "stripe/other", "api.stripe.com"),
        Decision::Deny {
            reason: Reason::NoSuchKey
        }
    ));
    let stranger = dev_session_id(4242, 9);
    assert!(matches!(
        swap_as(&h, &stranger, STRIPE_KEY, "api.stripe.com"),
        Decision::Deny {
            reason: Reason::Stopped
        }
    ));
    let receipts = h.receipts_text();
    assert!(receipts.contains("ms dev: project shop started"), "{receipts}");
    assert!(receipts.contains("ms-dev"), "{receipts}");
    assert!(!receipts.contains(CANARY));
}

// protects=L34 SPEC criterion 5 (design §7.5): the session ends with DevEnd from the same ms dev
// process (another process, even outside any agent, is refused), when the reaper finds the ms dev
// process gone, on ms stop, and on an msd restart; an ended session's credential maps to nothing
// and its swaps are denied; fails_when=a credential outlives its ms dev process, a stop or a
// restart; no_claim=the 2 s timer itself (main.rs reap_dev_sessions; e2e checks after exit)
#[test]
fn dev_session_ends_with_child() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let root = PathBuf::from(&rec.root);
    let start = |h: &H| {
        let (r, _) = dev_start(h.as_(terminal()), &["npm", "run", "dev"], &root);
        started(&r)
    };

    let (id, cred, _) = start(&h);
    let other = Caller::Unattributed {
        pid: 44,
        started_unix_ms: 1,
    };
    let r = h.as_(other).req(RequestBody::DevEnd {
        session: id.clone(),
    });
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    assert!(h.d.dev_by_credential(&cred).is_some());
    let r = h.as_(terminal()).req(RequestBody::DevEnd { session: id });
    assert!(is_ok(&r), "{r:?}");
    assert_eq!(h.d.dev_by_credential(&cred), None);
    assert!(matches!(
        swap_as(&h, &dev_id(), STRIPE_KEY, "api.stripe.com"),
        Decision::Deny { .. }
    ));

    let (_, cred, _) = start(&h);
    assert_eq!(h.d.reap_dev(|pid, st| (pid, st) == (43, 1)), 0);
    assert_eq!(h.d.reap_dev(|pid, st| (pid, st) == (43, 2)), 1, "restarted");
    assert_eq!(h.d.dev_by_credential(&cred), None);

    let (_, cred, _) = start(&h);
    assert!(is_ok(&h.req(RequestBody::Stop)));
    assert_eq!(h.d.dev_by_credential(&cred), None);
    let r = h.approved(|| h.req(RequestBody::Start { at_terminal: false }));
    assert!(is_ok(&r), "{r:?}");

    let (_, cred, _) = start(&h);
    let h = restart(h);
    assert_eq!(h.d.dev_by_credential(&cred), None);
    assert_eq!(h.d.dev.len(), 0);
}

// protects=L34 SPEC criterion 6 (design §7.3): DevStart returns values only for run-mode keys of
// the cwd's project, as names in the JSON reply and values beside it; a swap key's value and the
// value of another project's run key never come back; a subfolder of the project works, a folder
// in no project is refused; run_env takes only keys whose rule root holds the cwd, picks the root
// .env on a clash, and skips names that steer programs; fails_when=a swap key, another project's
// key or a key whose root doesn't hold the cwd is handed out, or a value appears in the reply's
// JSON; no_claim=the wire format (ms-ipc values_follow_dev_started_as_raw_frames)
#[test]
fn dev_run_mode_values_only_for_project_keys() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    // A second project with its own run key, in a sibling folder.
    put_mode(&h, "web/database-url", Mode::Run, Tier::Test);
    let mut web = project(&h, &[("web/database-url", Some("pg"))]);
    let web_root = h.dir.path().join("web");
    std::fs::create_dir_all(&web_root).unwrap();
    web.slug = "web".into();
    web.display = "web".into();
    web.root = std::fs::canonicalize(&web_root)
        .unwrap()
        .display()
        .to_string();
    let rules = proposal(&h, &web);
    assert!(is_ok(&h.approved(|| save(&h, &web, &rules))));

    let sub = PathBuf::from(&rec.root).join("apps/api");
    std::fs::create_dir_all(&sub).unwrap();
    let (r, values) = dev_start(&h, &["npm", "run", "dev"], &sub);
    let (_, _, env) = started(&r);
    assert_eq!(env, ["VAR_1"], "only the shop database URL: {r:?}");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].expose(), CANARY.as_bytes());
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains(CANARY), "{json}");
    assert!(h.receipts_text().contains("ms dev: npm (environment)"));

    let outside = h.dir.path().join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let (r, values) = dev_start(&h, &["npm", "run", "dev"], &outside);
    assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
    assert!(values.is_empty());

    // run_env on its own: roots, clashes and denied names.
    use ms_projects::record::*;
    let root = PathBuf::from("/p/shop");
    let k = |s: &str| KeyName::new(s).unwrap();
    let mut rules = Rules::default();
    let mut run = KeyRule::new(Mode::Run, Tier::Test);
    run.roots = vec![root.clone()];
    for key in ["shop/a", "shop/b", "shop/c", "shop/path"] {
        rules.keys.insert(k(key), run.clone());
    }
    let mut elsewhere = run.clone();
    elsewhere.roots = vec![PathBuf::from("/p/other")];
    rules.keys.insert(k("shop/far"), elsewhere);
    let mut swap = KeyRule::new(Mode::Swap, Tier::Test);
    swap.hosts = vec![ms_rules::HostPattern::parse("api.stripe.com").unwrap()];
    rules.keys.insert(k("shop/swap"), swap);
    let line = |var: &str, key: &str| SecretRecord {
        var: var.into(),
        line: 1,
        key: k(key),
        quote: Quote::None,
        action: SecretAction::Import,
        provider: None,
    };
    let file = |path: &str, secrets| FileRecord {
        path: path.into(),
        git_history_commits: None,
        secrets,
    };
    let rec = ProjectRecord {
        slug: "shop".into(),
        display: "shop".into(),
        root: root.display().to_string(),
        created_unix_ms: 1,
        scan: ScanRecord::default(),
        files: vec![
            file(
                "apps/web/.env",
                vec![
                    line("DATABASE_URL", "shop/b"),
                    line("CACHE_URL", "shop/a"),
                    line("QUEUE_URL", "shop/b"),
                ],
            ),
            file(
                ".env",
                vec![
                    line("DATABASE_URL", "shop/a"),
                    line("STRIPE_SECRET_KEY", "shop/swap"),
                    line("FAR_URL", "shop/far"),
                    line("PATH", "shop/path"),
                ],
            ),
            file(".env.local", vec![line("QUEUE_URL", "shop/c")]),
        ],
        findings: Vec::new(),
        hints: Vec::new(),
    };
    let mut notes = Vec::new();
    let got = run_env(&rec, &rules, &root.join("apps/web"), &mut notes);
    let want: BTreeMap<String, KeyName> = [
        ("CACHE_URL".to_string(), k("shop/a")),
        ("DATABASE_URL".to_string(), k("shop/a")),
    ]
    .into();
    assert_eq!(got, want, "{notes:?}");
    assert!(notes.iter().any(|n| n.starts_with("QUEUE_URL")), "{notes:?}");
    assert!(notes.iter().any(|n| n.starts_with("PATH")), "{notes:?}");
    assert!(
        run_env(&rec, &rules, Path::new("/p/other"), &mut notes)
            .keys()
            .all(|v| v == "FAR_URL")
    );
    let mut tampered = rules.clone();
    tampered.tampered = true;
    assert!(run_env(&rec, &tampered, &root, &mut notes).is_empty());
}

// protects=L34 SPEC criterion 7 (design §7.2, AUTH-3): a project with a production key asks one
// Touch ID per ms dev run, bound to the command (the sheet's argv names the project, the root,
// the production keys and the exact command); every production swap of that run is approved with
// that token and no new prompt; a key outside the project is still denied; a denial starts
// nothing and hands out no value; a run with only test keys asks nothing; fails_when=no approval
// is asked, one is asked per swap, the token covers another command or key, or a denied run gets
// values; no_claim=the real LocalAuthentication sheet (manual, PROOF)
#[test]
fn dev_production_needs_one_approval() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Production, Tier::Production);
    let live = h.d.rules();
    assert_eq!(live.keys[&KeyName::new(STRIPE_KEY).unwrap()].tier, Tier::Production);
    let root = PathBuf::from(&rec.root);

    // Denied: nothing starts.
    let (r, _) = h.answered(APPROVER_PID, false, None, || {
        let (r, values) = dev_start(&h, &["npm", "run", "dev"], &root);
        assert!(values.is_empty());
        r
    });
    assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
    assert_eq!(h.d.dev.len(), 0);

    // Approved once.
    let seen = std::sync::Mutex::new(None);
    let before = h.auth.reasons().len();
    let r = std::thread::scope(|sc| {
        sc.spawn(|| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if let ResponseBody::Approval { pending: Some(p) } =
                    h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None)
                {
                    *lock(&seen) = Some(p.request.clone());
                    let _ = h.d.handle(
                        &peer_pid(APPROVER_PID),
                        RequestBody::ApprovalDecide {
                            id: p.id,
                            approve: true,
                            scope: None,
                        },
                        None,
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        dev_start(&h, &["npm", "run", "dev"], &root)
    });
    let (r, values) = r;
    let (_, _, env) = started(&r);
    assert_eq!(env, ["VAR_1"]);
    assert_eq!(values.len(), 1);
    assert_eq!(h.auth.reasons().len(), before + 1, "exactly one Touch ID");
    let req = lock(&seen).clone().expect("an approval was asked");
    let shown = req.argv_display.join(" ");
    assert!(
        shown.starts_with(&format!("ms dev --project shop --root {}", rec.root)),
        "{shown}"
    );
    assert!(shown.contains(STRIPE_KEY) && shown.contains(DB_KEY), "{shown}");
    assert!(shown.ends_with("-- npm run dev"), "{shown}");
    assert_eq!(req.argv_hash, ms_rules::argv_hash(&req.argv_display));

    // Production swaps of this run use that approval: no new prompt.
    let dev = dev_id();
    let approver = h.d.approver();
    for _ in 0..3 {
        let Decision::NeedsApproval { request } =
            swap_as(&h, &dev, STRIPE_KEY, "api.stripe.com")
        else {
            panic!("production needs approval");
        };
        assert!(matches!(
            approver.ask(&request, Duration::from_millis(200)),
            ApprovalOutcome::Approved(_)
        ));
    }
    assert_eq!(h.auth.reasons().len(), before + 1, "no prompt per swap");
    assert!(h.receipts_text().contains("\"approved\""));

    // Another session's production swap is not covered: it asks a person (and times out here).
    let Decision::NeedsApproval { request } = h.swap(STRIPE_KEY, "api.stripe.com") else {
        panic!("production needs approval");
    };
    assert!(!matches!(
        approver.ask(&request, Duration::from_millis(100)),
        ApprovalOutcome::Approved(_)
    ));

    // Test keys only: nothing asked.
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let n = h.auth.reasons().len();
    let (r, _) = dev_start(&h, &["npm", "run", "dev"], Path::new(&rec.root));
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    assert_eq!(h.auth.reasons().len(), n);
}
