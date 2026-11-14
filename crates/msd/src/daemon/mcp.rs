//! `McpCall` (L14): an `ms mcp` tool call, enforced here, not in `ms mcp` (SPEC D3).
//!
//! 1. The caller's session is the kernel peer's (already resolved by `Daemon::handle`); nothing
//!    in the call names a session.
//! 2. The catalog is rebuilt from the live, MAC-verified rules. The call must name a tool in it
//!    and carry the version it was built from, so a tool list can't drift from the rules.
//! 3. The arguments are validated against the tool's JSON Schema and the argv and environment
//!    are built from the tool: the key is the tool's, never an argument.
//! 4. The call then takes L12's run path (`run_buffered`): project roots, the command
//!    allowlist with the project file merged, L11's approver for production keys, receipts
//!    before anything runs, redacted output.
//!
//! Refusals in steps 2–3 are recorded too, so every call leaves a receipt.

use std::path::PathBuf;

use ms_core::{KeyName, Mode, Reason, ReceiptResult, SessionId};
use ms_ipc::{ErrorCode, PeerInfo, ResponseBody, RunEnv};
use ms_mcp::Catalog;
use serde_json::Value;

use super::{Daemon, daemon_key, reply_err, run};

/// Longest tool name kept in a receipt target.
const TOOL_SHOWN: usize = 64;

/// Handles one `McpCall`. Blocking (vault, approvals, receipts).
pub(crate) fn call(
    d: &Daemon,
    peer: &PeerInfo,
    session: &SessionId,
    tool: &str,
    rules_version: u64,
    cwd: PathBuf,
    arguments: &Value,
) -> ResponseBody {
    // The version is compared before the catalog is built, so a stale call costs no catalog
    // build (security review S1). The catalog is built from the same rules the version came from.
    let (catalog, version) = {
        let live = d.read_live();
        let v = live.rules.version;
        (
            (rules_version == v).then(|| Catalog::from_rules(&live.rules)),
            v,
        )
    };
    let shown = shown(tool);
    let refuse_as = |key: &KeyName, why: &str, result: ReceiptResult, reply: ResponseBody| {
        let target = format!("mcp:{shown} ({why})");
        if let Err(e) = d.record(session, key, Mode::Run, &target, version, result, None) {
            tracing::error!(error = %e, "could not record a refused MCP call");
            return reply_err(
                ErrorCode::Internal,
                format!("morsec: the receipt for this call could not be written ({e})"),
            );
        }
        reply
    };
    // Blocked: counts toward LOG-2 (an agent probing for tools or bad arguments).
    let refuse = |key: &KeyName, why: &str, reply: ResponseBody| {
        refuse_as(
            key,
            why,
            ReceiptResult::Blocked(Reason::CommandNotAllowed),
            reply,
        )
    };
    let Some(catalog) = catalog else {
        // The person changed the rules (or they failed their integrity check and load as
        // version 0), not the agent's doing: recorded under msd's key as a failure that does not
        // count toward a LOG-2 session stop (review R2, security review S2).
        return refuse_as(
            &daemon_key(),
            "rules changed",
            ReceiptResult::Failed("the rules changed; restart the MCP server".into()),
            reply_err(
                ErrorCode::Invalid,
                format!(
                    "morsec: the rules changed (tools were built from version {rules_version}, the rules are now version {version}), so this tool may not mean what it did. Restart the morsec MCP server to load the current tools"
                ),
            ),
        );
    };
    let Some(t) = catalog.get(tool) else {
        return refuse(
            &daemon_key(),
            "no such tool",
            reply_err(
                ErrorCode::Invalid,
                format!(
                    "morsec: there is no tool named {shown}. The tools are the run commands your rules allow; list them again (restart the MCP server if the rules changed)"
                ),
            ),
        );
    };
    let c = match t.call(arguments) {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                &t.key,
                "invalid arguments",
                reply_err(ErrorCode::Invalid, format!("morsec: {}: {e}", t.name)),
            );
        }
    };
    let env = c
        .env
        .into_iter()
        .map(|(name, value)| RunEnv { name, value })
        .collect();
    let via = format!("mcp:{}", t.name);
    run::run_buffered(d, peer, c.argv, cwd, env, Some(&via))
}

/// The agent's tool name as recorded: bounded and escaped.
fn shown(tool: &str) -> String {
    let mut s: String = tool
        .chars()
        .take(TOOL_SHOWN)
        .flat_map(char::escape_default)
        .collect();
    if tool.chars().count() > TOOL_SHOWN {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::Tier;
    use ms_ipc::RequestBody;
    use serde_json::json;

    use super::*;
    use crate::daemon::run::tests::{VALUE, answer, peer, rt, test_daemon, test_daemon_with};

    fn mcp(
        rt: &tokio::runtime::Runtime,
        d: &Arc<Daemon>,
        root: &Path,
        tool: &str,
        version: u64,
        arguments: Value,
    ) -> ResponseBody {
        let (d, root, tool) = (d.clone(), root.to_path_buf(), tool.to_owned());
        rt.block_on(async move {
            tokio::task::spawn_blocking(move || {
                d.handle(
                    &peer(),
                    RequestBody::McpCall {
                        tool,
                        rules_version: version,
                        cwd: root,
                        arguments,
                    },
                    None,
                )
            })
            .await
            .unwrap()
        })
    }

    /// Every receipt line written so far.
    fn receipts(dir: &Path) -> Vec<Value> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir.join("receipts")).unwrap() {
            let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
            out.extend(text.lines().filter_map(|l| serde_json::from_str(l).ok()));
        }
        out
    }

    fn stdout(r: &ResponseBody) -> String {
        match r {
            ResponseBody::RunResult { stdout, .. } => {
                String::from_utf8(ms_ipc::b64_decode(stdout).unwrap()).unwrap()
            }
            other => panic!("{other:?}"),
        }
    }

    fn code(r: &ResponseBody) -> Option<ErrorCode> {
        match r {
            ResponseBody::Error { code, .. } => Some(*code),
            _ => None,
        }
    }

    // protects=AUTH-2/D3/D4: a tool call runs the tool's own command with the tool's key (the
    // value only in the rule's env names, redacted in the output) and its receipt names the
    // peer's agent session, the key and the tool; fails_when=the call fails, the value leaks, or
    // the receipt lacks the session/tool; no_claim=a real agent process tree (e2e)
    #[test]
    fn a_call_runs_with_the_tools_key_and_the_peers_session() {
        let rt = rt();
        let (d, dir, root) = test_daemon("commands = [[\"env\"]]\nenv = [\"TOKEN\"]");
        let v = d.rules_version();
        let before = receipts(dir.path()).len();
        let r = mcp(&rt, &d, &root, "svc_test__env", v, Value::Null);
        let out = stdout(&r);
        assert!(out.contains("TOKEN=[redacted ms://svc/test]"), "{out}");
        assert!(!out.contains(VALUE));
        let rs = receipts(dir.path());
        assert_eq!(rs.len(), before + 1, "one receipt");
        let last = rs.last().unwrap().to_string();
        assert!(last.contains("mcp:svc_test__env env [env TOKEN]"), "{last}");
        assert!(
            last.contains("svc/test") && last.contains("allowed"),
            "{last}"
        );
        assert!(last.contains("claude") && last.contains("42"), "{last}");
        assert!(!last.contains(VALUE));
    }

    // protects=AUTH-2/OUT-1: a call can't name another key or session and can't break the
    // schema: ms:// refs, extra key/session/cwd/env properties, wrong types, missing or
    // oversized arguments are refused before anything runs, each with a receipt;
    // fails_when=any runs or goes unrecorded; no_claim=-
    #[test]
    fn schema_violations_and_other_keys_are_refused_and_recorded() {
        let rt = rt();
        let (d, dir, root) = test_daemon("commands = [[\"echo\", \"*\"]]\nenv = [\"TOKEN\"]");
        let v = d.rules_version();
        let ok = mcp(
            &rt,
            &d,
            &root,
            "svc_test__echo",
            v,
            json!({"arg1": "a; rm -rf /"}),
        );
        assert_eq!(stdout(&ok), "a; rm -rf /\n", "literal, no shell");
        let bad = [
            json!({"arg1": "ms://other/key"}),
            json!({"arg1": "$(cat ms://svc/test)"}),
            json!({"arg1": "x", "key": "other/key"}),
            json!({"arg1": "x", "session": "codex:1:1"}),
            json!({"arg1": "x", "cwd": "/"}),
            json!({"arg1": "x", "env": {"TOKEN": "ms://other/key"}}),
            json!({"arg1": 1}),
            json!({}),
            json!({"arg1": "x".repeat(5000)}),
            json!(["x"]),
        ];
        drop((d, dir));
        for a in bad {
            // A fresh daemon each time: repeated refusals stop the session (LOG-2, next test).
            let (d, dir, root) = test_daemon("commands = [[\"echo\", \"*\"]]\nenv = [\"TOKEN\"]");
            let before = receipts(dir.path()).len();
            let r = mcp(&rt, &d, &root, "svc_test__echo", v, a.clone());
            assert_eq!(code(&r), Some(ErrorCode::Invalid), "{a}: {r:?}");
            let rs = receipts(dir.path());
            assert_eq!(rs.len(), before + 1, "{a}: no receipt");
            let last = rs.last().unwrap().to_string();
            assert!(
                last.contains("invalid arguments") && last.contains("svc/test"),
                "{last}"
            );
            assert!(last.contains("blocked"), "{last}");
        }
    }

    // protects=LOG-2: refused tool calls count as blocked attempts, so an agent probing the
    // tools with bad calls gets its session stopped like any other; fails_when=it can keep
    // calling forever; no_claim=the threshold itself (ms-receipts)
    #[test]
    fn repeated_refusals_stop_the_session() {
        let rt = rt();
        let (d, _dir, root) = test_daemon("commands = [[\"echo\", \"*\"]]\nenv = [\"TOKEN\"]");
        let v = d.rules_version();
        let stopped = (0..50).any(|_| {
            let r = mcp(&rt, &d, &root, "svc_test__echo", v, json!({"key": "x"}));
            code(&r) == Some(ErrorCode::Denied)
        });
        assert!(stopped, "the session was never stopped");
        let r = mcp(&rt, &d, &root, "svc_test__echo", v, json!({"arg1": "x"}));
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    }

    // protects=MCP-2 / D2: an unknown tool, and a call built from an older rules version, are
    // refused and recorded; fails_when=either runs or leaves no receipt; no_claim=-
    #[test]
    fn unknown_tools_and_stale_versions_are_refused() {
        let rt = rt();
        let (d, dir, root) = test_daemon("commands = [[\"env\"]]\nenv = [\"TOKEN\"]");
        let v = d.rules_version();
        let r = mcp(&rt, &d, &root, "svc_test__env\u{1b}[2J", v, Value::Null);
        assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
        let last = receipts(dir.path()).last().unwrap().to_string();
        assert!(
            last.contains("no such tool") && last.contains("morsec/daemon"),
            "{last}"
        );
        assert!(!last.contains('\u{1b}'), "{last}");
        let r = mcp(&rt, &d, &root, "svc_test__env", v - 1, Value::Null);
        assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
        let last = receipts(dir.path()).last().unwrap().to_string();
        assert!(
            last.contains("rules changed") && last.contains("morsec/daemon"),
            "{last}"
        );
        assert!(!last.contains("blocked"), "{last}");
        // Not the agent's fault: a stale list never gets the session stopped (review R2).
        for _ in 0..30 {
            let r = mcp(&rt, &d, &root, "svc_test__env", v - 1, Value::Null);
            assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
        }
    }

    // protects=D5/AUTH-3: a production tool call waits for L11's approver; approved it runs
    // (receipt approved, touch-id), denied it does not (receipt denied); fails_when=a production
    // call runs without approval; no_claim=the real Touch ID sheet
    #[test]
    fn production_calls_go_through_the_approver() {
        let rt = rt();
        for approve in [true, false] {
            let (d, dir, root) = test_daemon_with(
                Tier::Production,
                "commands = [[\"env\"]]\nenv = [\"TOKEN\"]",
                FakeAuthenticator::approve(),
            );
            let v = d.rules_version();
            let decider = answer(&d, approve, Some(&["env"]));
            let r = mcp(&rt, &d, &root, "svc_test__env", v, Value::Null);
            decider.join().unwrap();
            let last = receipts(dir.path()).last().unwrap().to_string();
            if approve {
                assert!(stdout(&r).contains("TOKEN=[redacted ms://svc/test]"));
                assert!(
                    last.contains("approved") && last.contains("touch-id"),
                    "{last}"
                );
            } else {
                assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
                assert!(
                    last.contains("denied") && last.contains("mcp:svc_test__env"),
                    "{last}"
                );
            }
        }
    }
}
