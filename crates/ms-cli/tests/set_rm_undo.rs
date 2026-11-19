//! `ms set`, `ms rm` and `ms undo` end to end (L33 dash-actions SPEC D-25), against a dev msd
//! (`common::Fx`: memory vault, `--test-touch-id allow`), from the user's own terminal (a
//! detached `script` pty answering the inline review) and from inside a fake agent.

// `--test-touch-id` and `--test-pasteboard-to` exist only in debug builds.
#![cfg(debug_assertions)]

mod common;

use common::Fx;

/// Values that must never be printed, split so secret scanners don't take them for keys.
const STRIPE: &str = concat!("sk_test_", "51UNDOvalueUNDOvalueUNDOvalue00");
const OAI: &str = concat!("sk-", "proj-", "UNDOoaiUNDOoaiUNDOoaiUNDOoai0123");
const SESSION: &str = "e5b8a1c4d7f0e3a6b9c2d5f8a1b4c7d0";
const NEW: &str = concat!("sk_test_", "51NEWvalueNEWvalueNEWvalue0000");

fn env_text() -> String {
    format!(
        "# app\nSTRIPE_SECRET_KEY={STRIPE}\nOPENAI_API_KEY=\"{OAI}\"\nSESSION_SECRET='{SESSION}'\nPORT=3000\n"
    )
}

fn no_values(what: &str, text: &str) {
    for v in [STRIPE, OAI, SESSION, NEW] {
        assert!(!text.contains(v), "{what} holds a value: {text}");
        assert!(
            !text.contains(&v[v.len() - 12..]),
            "{what} holds part of a value"
        );
    }
}

// protects=SPEC D-21, criterion 14: after a real `ms init`, `ms undo shop` (approved on the
// user's terminal, Touch ID stood in by the test flag) writes every value back into .env in
// its original quote style, byte for byte as before the import, prints the restored lines
// (never a value), and removes the project; fails_when=a value comes back wrong, a byte of the
// file differs, or a value is printed or recorded; no_claim=the real Touch ID sheet
#[test]
fn undo_end_to_end() {
    let fx = Fx::new();
    let before = env_text();
    let root = fx.init_shop(&before);
    let imported = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(imported.contains("ms://shop/"), "{imported}");
    no_values(".env after init", &imported);
    let (code, out) = fx.at_terminal(&root, &[], r#""$MS" undo shop"#);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("restored  shop/.env:2  STRIPE_SECRET_KEY"),
        "{out}"
    );
    assert!(out.contains("3 values written back"), "{out}");
    no_values("ms undo output", &out);
    assert_eq!(std::fs::read_to_string(root.join(".env")).unwrap(), before);
    let (code, out) = fx.outside(&root, r#""$MS" projects"#);
    assert!(!out.contains("shop  "), "{code} {out}");
    let r = fx.receipts();
    assert!(r.contains("ms undo"), "{r}");
    no_values("receipts", &r);
    no_values("msd log", &fx.log());
}

// protects=SPEC D-13, D-25, criterion 20: `ms add` on an existing key points at `ms set`;
// `ms set` replaces after the person's approval and never prints the value; `ms rm` refuses
// a key a project file still uses (naming the line) unless --force; `ms undo --key` restores
// one key; all three refuse inside an agent session before asking msd; fails_when=a value is
// replaced or deleted without the review, from an agent, or printed; no_claim=the real sheet
#[test]
fn set_rm_undo_cli() {
    let fx = Fx::new();
    let root = fx.init_shop(&env_text());
    let base = fx.base();
    let (code, out) = fx.outside(
        &base,
        r#"printf 'first-value' | "$MS" add loose/key --stdin --tier test"#,
    );
    assert_eq!(code, 0, "{out}");
    let (code, out) = fx.outside(
        &base,
        r#"printf 'second' | "$MS" add loose/key --stdin --tier test"#,
    );
    assert_ne!(code, 0);
    assert!(out.contains("Replace it with: ms set loose/key"), "{out}");

    let (code, out) = fx.at_terminal(&base, &[NEW, NEW], r#""$MS" set loose/key"#);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("replaced loose/key"), "{out}");
    no_values("ms set output", &out);

    let (code, out) = fx.at_terminal(&base, &[], r#""$MS" rm shop/stripe-secret-key"#);
    assert_eq!(code, 77, "{out}");
    assert!(out.contains("shop .env:2"), "{out}");
    let (code, out) = fx.at_terminal(&root, &[], r#""$MS" undo shop --key shop/openai-api-key"#);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("OPENAI_API_KEY") && out.contains("1 value written back"),
        "{out}"
    );
    let env = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(env.contains(&format!("OPENAI_API_KEY=\"{OAI}\"")));
    assert!(
        env.contains("STRIPE_SECRET_KEY=ms://shop/stripe-secret-key"),
        "{env}"
    );
    let (code, out) = fx.at_terminal(&base, &[], r#""$MS" rm loose/key"#);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("deleted loose/key"), "{out}");

    // Inside an agent: refused before msd is asked (and before a value is read).
    let agent = fx.fake_agent();
    for cmd in [
        r#"printf 'x' | "$MS" set shop/stripe-secret-key --stdin"#.to_owned(),
        r#""$MS" rm shop/stripe-secret-key --force"#.to_owned(),
        r#""$MS" undo shop"#.to_owned(),
    ] {
        let (code, out) = fx.outside(
            &root,
            &format!(
                "'{}' /bin/sh -c '{}'",
                agent.display(),
                cmd.replace('\'', "'\\''")
            ),
        );
        assert_eq!(code, 77, "{cmd}: {out}");
        assert!(out.contains("agent session"), "{cmd}: {out}");
    }
    let env2 = std::fs::read_to_string(root.join(".env")).unwrap();
    assert_eq!(env, env2, "nothing changed from inside the agent");
    let r = fx.receipts();
    assert!(
        r.contains("ms set") && r.contains("ms rm") && r.contains("ms undo"),
        "{r}"
    );
    no_values("receipts", &r);
    no_values("msd log", &fx.log());
}

// protects=REVIEW.md (ms and mors behave identically): the new subcommands answer the same
// under both names; fails_when=mors lacks set, rm or undo or says something else;
// no_claim=-
#[test]
fn mors_is_ms() {
    let fx = Fx::new();
    let base = fx.base();
    let mors = base.join("bin/mors");
    std::os::unix::fs::symlink(common::ms(), &mors).unwrap();
    for sub in ["set", "rm", "undo"] {
        let (_, a) = fx.outside(&base, &format!(r#""$MS" {sub} --help"#));
        let (_, b) = fx.outside(&base, &format!("'{}' {sub} --help", mors.display()));
        assert!(a.contains("Usage: ms "), "{a}");
        assert_eq!(a.replace("Usage: ms ", "Usage: mors "), b, "{sub}");
    }
    let (code, out) = fx.outside(&base, &format!("'{}' rm no/such", mors.display()));
    assert_ne!(code, 0);
    assert!(out.contains("no key named no/such"), "{out}");
}
