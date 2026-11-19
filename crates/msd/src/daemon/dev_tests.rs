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

/// Runs `f` while a person answers the approval it raises with `approve`, after `during` has
/// run on the pending request. Returns `f`'s result and the request the person saw.
fn with_person<T: Send>(
    h: &H,
    approve: bool,
    during: impl FnOnce(&PendingApproval) + Send,
    f: impl FnOnce() -> T + Send,
) -> (T, Option<ApprovalRequest>) {
    let seen = std::sync::Mutex::new(None);
    let out = std::thread::scope(|sc| {
        sc.spawn(|| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if let ResponseBody::Approval { pending: Some(p) } =
                    h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None)
                {
                    *lock(&seen) = Some(p.request.clone());
                    during(&p);
                    let _ = h.d.handle(
                        &peer_pid(APPROVER_PID),
                        RequestBody::ApprovalDecide {
                            id: p.id,
                            approve,
                            scope: None,
                        },
                        None,
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        f()
    });
    (out, lock(&seen).clone())
}

/// `DevStart`, approved by the person (every run asks once: review D-A).
fn dev_start(h: &H, argv: &[&str], cwd: &Path) -> (ResponseBody, Vec<SecretBytes>) {
    with_person(h, true, |_| {}, || dev_start_raw(h, argv, cwd)).0
}

/// `DevStart` with nobody answering (for requests refused before any approval).
fn dev_start_raw(h: &H, argv: &[&str], cwd: &Path) -> (ResponseBody, Vec<SecretBytes>) {
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
// DevEnd from an agent is Denied too; a sandboxed peer (an agent command that double-forked out
// of its tree) is refused the same way (review D-A); fails_when=an agent gets a value, a
// credential or a prompt; no_claim=a detached, unsandboxed same-user process (it must pass the
// person's approval: T-82), the real sandbox_check (ms-session live sandboxed_process_is_detected)
#[test]
fn dev_refused_in_agent_session() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let asked = h.auth.reasons().len();
    let (r, values) = dev_start_raw(h.as_(agent()), &["npm", "run", "dev"], Path::new(&rec.root));
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    assert!(msg(&r).contains("agent session"), "{r:?}");
    assert!(values.is_empty());
    assert_eq!(h.d.dev.len(), 0);
    assert_eq!(h.auth.reasons().len(), asked, "no approval was asked");
    // Review D-A: an agent's command that double-forked out of its tree is unattributed, but
    // still in the agent's sandbox: refused before any approval is asked.
    h.d.set_sandbox_probe(|_| true);
    let (r, values) = dev_start_raw(h.as_(terminal()), &["npm", "run", "dev"], Path::new(&rec.root));
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    assert!(msg(&r).contains("sandboxed"), "{r:?}");
    assert!(values.is_empty());
    assert_eq!(h.auth.reasons().len(), asked, "no approval was asked");
    h.d.set_sandbox_probe(|_| false);
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
// agent, by bare name, by path or by an agent's install path (versioned native Claude Code, npm
// packages: review N2); a lookalike name is not refused; fails_when=claude, codex,
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
        "/Users/a/.local/share/claude/versions/2.0.5",
        "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js",
    ] {
        let (r, values) = dev_start_raw(&h, &[argv0, "-p", "hi"], &root);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{argv0}: {r:?}");
        assert!(values.is_empty());
    }
    assert_eq!(h.d.dev.len(), 0);
    let (r, _) = dev_start(&h, &["claude-helper"], &root);
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    let (r, _) = dev_start_raw(&h, &[], &root);
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
// process gone, on ms stop, and on an msd restart, and each end leaves a receipt; ms stop while
// the approval is pending starts nothing (review R2); an ended session's credential maps to
// nothing and its swaps are denied; fails_when=a credential outlives its ms dev process, a stop or a
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

    assert!(h.receipts_text().contains("ended (the command exited)"));

    let (_, cred, _) = start(&h);
    assert_eq!(h.d.reap_dev(|pid, st| (pid, st) == (43, 1)), 0);
    assert_eq!(h.d.reap_dev(|pid, st| (pid, st) == (43, 2)), 1, "restarted");
    assert_eq!(h.d.dev_by_credential(&cred), None);
    assert!(h.receipts_text().contains("ended (its process is gone)"));
    // Review round 2 F5: liveness is asked once per session, so a flaky answer can't remove a
    // session without its end receipt.
    let (_, cred, _) = start(&h);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let removed = h.d.reap_dev(|_, _| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 2 == 1
    });
    assert_eq!(removed, 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(h.d.dev_by_credential(&cred), None);

    // Review R2: ms stop while the person is still deciding: nothing starts, no value is sent.
    let ((r, values), _) = with_person(
        &h,
        true,
        |_| {
            let stop = h.d.handle(&peer_pid(APPROVER_PID), RequestBody::Stop, None);
            assert!(is_ok(&stop), "{stop:?}");
        },
        || dev_start_raw(h.as_(terminal()), &["npm", "run", "dev"], &root),
    );
    assert!(code(&r).is_some(), "{r:?}");
    assert!(values.is_empty());
    assert_eq!(h.d.dev.len(), 0);
    let r = h.approved(|| h.req(RequestBody::Start { at_terminal: false }));
    assert!(is_ok(&r), "{r:?}");

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
// in no project is refused; run_env takes only keys with the rule ms init gives (the project root
// alone, no commands, not read-only, no other variable: review S2), picks the root .env on a
// clash, and skips names that steer programs; an empty value is not sent (review R4); fails_when=a swap key, another project's
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

    // Review R4: an empty value is skipped with a note, not sent as a (refused) empty frame.
    let db = KeyName::new(DB_KEY).unwrap();
    let meta = KeyMeta {
        name: db.clone(),
        mode: Mode::Run,
        tier: Tier::Test,
        created_unix_ms: 1,
    };
    h.d.vault().delete(&db).unwrap();
    h.d.vault().put(&db, SecretBytes::new(Vec::new()), meta).unwrap();
    let (r, values) = dev_start(&h, &["npm", "run", "dev"], &sub);
    assert!(values.is_empty(), "{r:?}");
    assert!(
        matches!(&r, ResponseBody::DevStarted { env, notes, .. } if env.is_empty() && notes.iter().any(|n| n.contains("empty")))
    , "{r:?}");

    let outside = h.dir.path().join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let (r, values) = dev_start_raw(&h, &["npm", "run", "dev"], &outside);
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
    // Review S2: run rules changed by hand are never released by ms dev.
    let mut with_cmd = run.clone();
    with_cmd.commands = vec![ms_rules::CommandPattern::parse(&["psql".to_string()]).unwrap()];
    rules.keys.insert(k("shop/cmd"), with_cmd);
    let mut ro = run.clone();
    ro.read_only = true;
    rules.keys.insert(k("shop/ro"), ro);
    let mut two_roots = run.clone();
    two_roots.roots.push(PathBuf::from("/"));
    rules.keys.insert(k("shop/wide"), two_roots);
    let mut env_other = run.clone();
    env_other.env = vec!["OTHER_VAR".into()];
    rules.keys.insert(k("shop/envo"), env_other);
    let mut env_same = run.clone();
    env_same.env = vec!["SAME_URL".into()];
    rules.keys.insert(k("shop/envs"), env_same);
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
                    line("CMD_URL", "shop/cmd"),
                    line("RO_URL", "shop/ro"),
                    line("WIDE_URL", "shop/wide"),
                    line("ENVO_URL", "shop/envo"),
                    line("SAME_URL", "shop/envs"),
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
        ("SAME_URL".to_string(), k("shop/envs")),
    ]
    .into();
    assert_eq!(got, want, "{notes:?}");
    for var in [
        "QUEUE_URL",
        "PATH",
        "FAR_URL",
        "CMD_URL",
        "RO_URL",
        "WIDE_URL",
        "ENVO_URL",
    ] {
        assert!(notes.iter().any(|n| n.starts_with(var)), "{var}: {notes:?}");
    }
    assert!(run_env(&rec, &rules, Path::new("/p/other"), &mut notes).is_empty());
    let mut tampered = rules.clone();
    tampered.tampered = true;
    assert!(run_env(&rec, &tampered, &root, &mut notes).is_empty());
}

// protects=L34 review round 2 F1: the Touch ID reason is capped, so the command comes first on
// ms dev's sheet: with many keys and a long root the whole command is still in the reason msd
// renders; a huge command is cut on the sheet with a marker and its full SHA-256, and the
// approval still binds the full command; fails_when=the command is cut off by the key list, or a
// cut command loses its binding; no_claim=the real LAContext sheet's own layout (manual)
#[test]
fn dev_sheet_shows_the_command_first() {
    let h = fresh();
    let long = h.dir.path().join(format!("{}/shop", "a-rather-long-folder-name".repeat(6)));
    std::fs::create_dir_all(&long).unwrap();
    let root = std::fs::canonicalize(&long).unwrap();
    let mut keys = Vec::new();
    for i in 0..8 {
        let k = format!("shop/database-url-{i}");
        put_mode(&h, &k, Mode::Run, Tier::Test);
        keys.push(k);
    }
    let pairs: Vec<(&str, Option<&str>)> = keys.iter().map(|k| (k.as_str(), Some("pg"))).collect();
    let mut rec = project(&h, &pairs);
    rec.root = root.display().to_string();
    let rules = proposal(&h, &rec);
    assert!(is_ok(&h.approved(|| save(&h, &rec, &rules))));

    let cmd = ["npm", "run", "dev", "--", "--port", "3000"];
    let (r, _) = dev_start(&h, &cmd, &root);
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    let reason = h.auth.reasons().last().cloned().unwrap();
    let quoted = cmd
        .iter()
        .map(|a| ms_approve::render::quoted(a))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(reason.contains(&quoted), "{reason}");

    // A huge command: cut with a marker on the sheet, bound in full.
    let big: Vec<String> = (0..40).map(|i| format!("--flag-number-{i}=value")).collect();
    let mut argv = vec!["node"];
    argv.extend(big.iter().map(String::as_str));
    let ((r, _), seen) = with_person(&h, true, |_| {}, || dev_start_raw(&h, &argv, &root));
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    let shown = seen.unwrap().argv_display.join(" ");
    let full: Vec<String> = argv.iter().map(|a| (*a).to_owned()).collect();
    assert!(
        shown.contains(&format!(
            "--full-command-sha256 {}",
            hex::encode(ms_rules::argv_hash(&full))
        )),
        "{shown}"
    );
    let reason = h.auth.reasons().last().cloned().unwrap();
    assert!(reason.contains("\"node\" \"--flag-number-0=value\""), "{reason}");
    assert!(reason.contains("command cut"), "{reason}");
}

// protects=L34 review round 2 F2: an approval answered for the session (`s`) is refused for ms dev
// (it would stretch the production window to hours): nothing starts, no value goes out;
// fails_when=a session-scope token starts a dev session; no_claim=the inline review's prompt
// (ms-cli approve inline_review_once_only)
#[test]
fn dev_refuses_a_session_scope_approval() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Production, Tier::Production);
    let root = PathBuf::from(&rec.root);
    let (r, decision) = h.answered(
        APPROVER_PID,
        true,
        Some(ApprovalScope::Session),
        || dev_start_raw(h.as_(terminal()), &["npm", "run", "dev"], &root).0,
    );
    assert!(is_ok(&decision), "{decision:?}");
    assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
    assert!(msg(&r).contains("answer o"), "{r:?}");
    assert_eq!(h.d.dev.len(), 0);
}

// protects=L34 SPEC criterion 7 (design §7.2, AUTH-3, review D-A/D-B): every ms dev run asks one
// Touch ID, bound to the command (the sheet's argv names the project, the root, the swapped keys,
// each variable that gets a value with its key, the production keys, that other websites are
// allowed, and the exact command); production swaps of that run are approved with that token and
// no new prompt, only while the token is live (ms stop revokes it) and within the key's session
// length; a key outside the project is still denied; a denial starts nothing and hands out no
// value; a run with only test keys asks too; fails_when=no approval is asked, one is asked per
// swap, the token covers another command or key, outlives its window or a revocation, or a
// denied run gets values; no_claim=the real LocalAuthentication sheet (manual, PROOF)
#[test]
fn dev_production_needs_one_approval() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Production, Tier::Production);
    h.put("stripe/other", Tier::Production);
    let live = h.d.rules();
    assert_eq!(
        live.keys[&KeyName::new(STRIPE_KEY).unwrap()].tier,
        Tier::Production
    );
    let root = PathBuf::from(&rec.root);

    // Denied: nothing starts.
    let ((r, values), _) = with_person(&h, false, |_| {}, || {
        dev_start_raw(&h, &["npm", "run", "dev"], &root)
    });
    assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
    assert!(values.is_empty());
    assert_eq!(h.d.dev.len(), 0);

    // Approved once.
    let before = h.auth.reasons().len();
    let ((r, values), seen) = with_person(&h, true, |_| {}, || {
        dev_start_raw(&h, &["npm", "run", "dev"], &root)
    });
    let (_, _, env) = started(&r);
    assert_eq!(env, ["VAR_1"]);
    assert_eq!(values.len(), 1);
    assert_eq!(h.auth.reasons().len(), before + 1, "exactly one Touch ID");
    let req = seen.expect("an approval was asked");
    let shown = req.argv_display.join(" ");
    assert_eq!(
        shown,
        format!(
            "ms dev --project shop --command(3 args) npm run dev --root {} --swap {STRIPE_KEY} --env VAR_1={DB_KEY} --production {DB_KEY} {STRIPE_KEY} --other-websites allowed",
            rec.root
        )
    );
    assert_eq!(req.argv_hash, ms_rules::argv_hash(&req.argv_display));

    // Production swaps of this run use that approval: no new prompt.
    let dev = dev_id();
    let approver = h.d.approver();
    let ask = |timeout_ms| {
        let Decision::NeedsApproval { request } = swap_as(&h, &dev, STRIPE_KEY, "api.stripe.com")
        else {
            panic!("production needs approval");
        };
        approver.ask(&request, Duration::from_millis(timeout_ms))
    };
    for _ in 0..3 {
        assert!(matches!(ask(200), ApprovalOutcome::Approved(_)));
    }
    assert_eq!(h.auth.reasons().len(), before + 1, "no prompt per swap");
    assert!(h.receipts_text().contains("\"approved\""));
    // Review R8: a key outside the project is denied, production or not.
    assert!(matches!(
        swap_as(&h, &dev, "stripe/other", "api.stripe.com"),
        Decision::Deny {
            reason: Reason::NoSuchKey
        }
    ));

    // Review D-B: past the key's session length the run's token no longer covers swaps (a
    // person is asked: nobody answers here, so it isn't approved).
    let ttl = live.keys[&KeyName::new(STRIPE_KEY).unwrap()].session_ttl_secs;
    h.d.age_dev_approvals(ttl * 1000 + 1);
    assert!(!matches!(ask(100), ApprovalOutcome::Approved(_)));
    h.d.age_dev_approvals(0);
    assert!(matches!(ask(200), ApprovalOutcome::Approved(_)));
    // ...and once the broker revoked it (what ms stop does), never.
    h.d.approvals.revoke_all().unwrap();
    assert!(!matches!(ask(100), ApprovalOutcome::Approved(_)));

    // Another session's production swap is not covered: it asks a person.
    let Decision::NeedsApproval { request } = h.swap(STRIPE_KEY, "api.stripe.com") else {
        panic!("production needs approval");
    };
    assert!(!matches!(
        approver.ask(&request, Duration::from_millis(100)),
        ApprovalOutcome::Approved(_)
    ));

    // Test keys only: still one approval (review D-A).
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let n = h.auth.reasons().len();
    let (r, _) = dev_start(&h, &["npm", "run", "dev"], Path::new(&rec.root));
    assert!(matches!(r, ResponseBody::DevStarted { .. }), "{r:?}");
    assert_eq!(h.auth.reasons().len(), n + 1);
}

// protects=L34 review R1: a value goes out only when its key's rule is still exactly what the
// person approved; a key raised to production (or otherwise changed) while the sheet was up is
// skipped with a note, and the run's approval does not cover it (it was not listed as production);
// fails_when=a key changed during the approval is released or swapped on the old approval;
// no_claim=changes after the reply (the proxy decides each swap on the rules in force)
#[test]
fn dev_values_follow_the_rules_the_person_saw() {
    let h = fresh();
    let rec = dev_shop(&h, Tier::Test, Tier::Test);
    let root = PathBuf::from(&rec.root);
    let raised = format!(
        "mode = \"run\"\ntier = \"production\"\nroots = [\"{}\"]",
        rec.root
    );
    let ((r, values), seen) = with_person(
        &h,
        true,
        |_| {
            let r = h.propose(DB_KEY, Some(&raised), false);
            assert!(is_ok(&r), "tightening needs no approval: {r:?}");
        },
        || dev_start_raw(h.as_(terminal()), &["npm", "run", "dev"], &root),
    );
    assert!(seen.unwrap().argv_display.contains(&format!("VAR_1={DB_KEY}")));
    assert!(values.is_empty(), "{r:?}");
    match &r {
        ResponseBody::DevStarted { env, notes, .. } => {
            assert!(env.is_empty());
            assert!(
                notes
                    .iter()
                    .any(|n| n.starts_with("VAR_1") && n.contains("changed")),
                "{notes:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        h.d.rules().keys[&KeyName::new(DB_KEY).unwrap()].tier,
        Tier::Production
    );
}

// protects=L34 review S2(b): a record that adds a key whose rule already allows something (made
// by hand, not by this ms init) asks the person, with the key named on the sheet; a denial saves
// no record; once saved, saving the same record again asks nothing; keys that still allow nothing
// join without a prompt; an approved adoption leaves an approved receipt per key; ProjectSave from
// a sandboxed process is refused (round 2 F3); fails_when=a detached process quietly makes an
// existing key part of a project (and so of ms dev's key set and run values); no_claim=ms init's own flow (ms-cli
// init_project tests)
#[test]
fn project_save_asks_to_adopt_a_key_that_allows_something() {
    let h = fresh();
    let legacy = "shop/legacy-token";
    h.put(legacy, Tier::Test);
    let r = h.approved(|| h.propose(legacy, Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]"), false));
    assert!(is_ok(&r), "{r:?}");
    h.put(UNKNOWN_KEY, Tier::Test);
    let rec = project(&h, &[(legacy, None), (UNKNOWN_KEY, None)]);
    let rules = proposal(&h, &rec);
    assert!(rules.keys.is_empty(), "nothing to give a first rule");

    let (r, _) = with_person(&h, false, |_| {}, || save(&h, &rec, &rules));
    assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
    assert!(!h.dir.path().join(PROJECTS_FILE).exists());

    // Round 2 F3: from a sandboxed process, refused before any approval.
    h.d.set_sandbox_probe(|_| true);
    let n = h.auth.reasons().len();
    let r = save(h.as_(terminal()), &rec, &rules);
    assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    assert!(msg(&r).contains("sandboxed"), "{r:?}");
    assert_eq!(h.auth.reasons().len(), n);
    h.d.set_sandbox_probe(|_| false);

    let n = h.auth.reasons().len();
    let (r, seen) = with_person(&h, true, |_| {}, || save(&h, &rec, &rules));
    assert!(is_ok(&r), "{r:?}");
    assert_eq!(h.auth.reasons().len(), n + 1);
    let shown = seen.unwrap().argv_display.join("\n");
    assert!(shown.contains(&format!("{legacy} joins the project")), "{shown}");
    assert!(!shown.contains(&format!("{UNKNOWN_KEY} joins")), "{shown}");

    assert!(
        h.receipts_text().contains("ms init: joins project shop"),
        "the adoption is on the record"
    );
    let n = h.auth.reasons().len();
    assert!(is_ok(&save(&h, &rec, &rules)), "same record again");
    assert_eq!(h.auth.reasons().len(), n, "nothing new to approve");
}
