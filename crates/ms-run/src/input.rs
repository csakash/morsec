//! Checking a run request before policy sees it (SPEC D3, D4).
//!
//! Everything here is agent-supplied, so it is bounded and validated first: argv is a non-empty
//! array of UTF-8 strings without NUL bytes, `argv[0]` is a bare tool name or an absolute path
//! (never a relative path an agent could rewrite), and the forwarded environment holds only
//! variables whose value carries an `ms://` ref, with safe names.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ms_core::{KeyName, SecretRef};

use crate::error::RunError;

/// Most arguments in one call, `argv[0]` included.
pub const MAX_ARGS: usize = 1024;
/// Most bytes across all arguments.
pub const MAX_ARGV_BYTES: usize = 256 * 1024;
/// Most forwarded environment variables.
pub const MAX_ENV: usize = 64;
/// Longest forwarded variable name.
pub const MAX_ENV_NAME: usize = 128;
/// Longest forwarded variable value.
pub const MAX_ENV_VALUE: usize = 64 * 1024;

/// Variable names a call may never set, whatever their value: the child's search path and
/// home come from msd, and these change how a program, a shell or an interpreter loads code
/// (an agent could point them at files it wrote).
const DENIED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "IFS",
    "ENV",
    "BASH_ENV",
    "CDPATH",
    "PS4",
    "PROMPT_COMMAND",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUBYOPT",
    "RUBYLIB",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "GCONV_PATH",
    "TMPDIR",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "LESSOPEN",
    "LESSCLOSE",
];
/// Suffixes of variables tools run as commands (`PSQL_PAGER`, `SSH_ASKPASS`, `GIT_EDITOR`…).
const DENIED_ENV_SUFFIXES: &[&str] = &["_PAGER", "_EDITOR", "_ASKPASS", "_BROWSER"];
const DENIED_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "PYTHON",
    "PERL",
    "GIT_",
    "BASH_FUNC_",
    "LUA_",
    "MALLOC_",
];

/// A validated run request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInput {
    /// The argv policy and the child see. `argv[0]` is a bare tool name or an absolute path.
    pub argv: Vec<String>,
    /// The working directory as sent (checked against the roots later, see [`crate::cwd`]).
    pub cwd: PathBuf,
    /// Forwarded variables, each holding at least one ref.
    pub env: Vec<(String, String)>,
    /// Keys referenced in argv.
    pub argv_keys: BTreeSet<KeyName>,
    /// Keys referenced in the forwarded environment.
    pub env_keys: BTreeSet<KeyName>,
}

impl RunInput {
    /// Checks a request. `argv[0]` keeps its form: a bare name, or an absolute path.
    pub fn new(
        argv: Vec<String>,
        cwd: PathBuf,
        env: Vec<(String, String)>,
    ) -> Result<Self, RunError> {
        check_argv(&argv)?;
        if !cwd.is_absolute() {
            return Err(RunError::invalid(
                "morsec: the working directory must be an absolute path",
            ));
        }
        check_env(&env)?;
        let argv_keys = argv.iter().flat_map(|a| refs(a)).collect();
        let env_keys = env.iter().flat_map(|(_, v)| refs(v)).collect();
        Ok(Self {
            argv,
            cwd,
            env,
            argv_keys,
            env_keys,
        })
    }

    /// Every key the call references, in argv or the environment.
    pub fn keys(&self) -> BTreeSet<KeyName> {
        self.argv_keys.union(&self.env_keys).cloned().collect()
    }

    /// The tool name (`argv[0]`).
    pub fn program(&self) -> &str {
        &self.argv[0]
    }
}

fn refs(s: &str) -> impl Iterator<Item = KeyName> {
    SecretRef::find_all(s)
        .into_iter()
        .map(|(_, r)| r.name().clone())
}

fn check_argv(argv: &[String]) -> Result<(), RunError> {
    let Some(first) = argv.first() else {
        return Err(RunError::invalid("morsec: the command is empty"));
    };
    if argv.len() > MAX_ARGS {
        return Err(RunError::invalid(format!(
            "morsec: the command has more than {MAX_ARGS} arguments"
        )));
    }
    if argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES {
        return Err(RunError::invalid(format!(
            "morsec: the command's arguments are longer than {MAX_ARGV_BYTES} bytes"
        )));
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Err(RunError::invalid("morsec: an argument contains a NUL byte"));
    }
    check_program(first)
}

/// `argv[0]`: a bare name (`psql`), or an absolute path (`/opt/tools/deploy`). A relative path
/// with a `/` (`./deploy.sh`, `bin/x`) is refused: the agent can rewrite that file.
fn check_program(p: &str) -> Result<(), RunError> {
    if p.is_empty() || p == "." || p == ".." || p.chars().any(char::is_control) {
        return Err(RunError::invalid(format!(
            "morsec: {} is not a program name",
            crate::printable(p)
        )));
    }
    if p.contains('/') && !p.starts_with('/') {
        return Err(RunError::denied(format!(
            "morsec: {} is a relative path, which an agent could rewrite, so morsec won't run it with a key. Allowlist the program by its absolute path (ms rules <key> --add-command) and call it that way",
            crate::printable(p)
        )));
    }
    if p.starts_with('/') && p.split('/').any(|c| c == "." || c == "..") {
        return Err(RunError::invalid(format!(
            "morsec: {} must be a normalised absolute path",
            crate::printable(p)
        )));
    }
    Ok(())
}

/// True when `name` may be forwarded: `[A-Za-z_][A-Za-z0-9_]*`, not on the deny list.
pub fn env_name_allowed(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ENV_NAME
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !DENIED_ENV.contains(&name)
        && !DENIED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
        && !DENIED_ENV_SUFFIXES.iter().any(|x| name.ends_with(x))
}

fn check_env(env: &[(String, String)]) -> Result<(), RunError> {
    if env.len() > MAX_ENV {
        return Err(RunError::invalid(format!(
            "morsec: more than {MAX_ENV} environment variables hold references"
        )));
    }
    let mut seen = BTreeSet::new();
    for (name, value) in env {
        if !env_name_allowed(name) {
            return Err(RunError::denied(format!(
                "morsec: the environment variable {} can't carry a reference (allowed: letters, digits and '_'; never one that changes how programs load code, such as PATH, HOME, BASH_ENV, LD_*, DYLD_*, PYTHON*, PERL*, NODE_OPTIONS, GIT_*)",
                crate::printable(name)
            )));
        }
        if !seen.insert(name.as_str()) {
            return Err(RunError::invalid(format!(
                "morsec: the environment variable {name} is sent twice"
            )));
        }
        if value.len() > MAX_ENV_VALUE || value.contains('\0') {
            return Err(RunError::invalid(format!(
                "morsec: the value of {name} is longer than {MAX_ENV_VALUE} bytes or contains a NUL byte"
            )));
        }
        if SecretRef::find_all(value).is_empty() {
            return Err(RunError::invalid(format!(
                "morsec: {name} holds no ms:// reference; only variables with a reference are sent"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RunErrorKind;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // protects=argv[0] is a bare name or an absolute path; relative paths, empty argv, NUL bytes
    // and oversized argv are refused before policy; fails_when=any of them passes;
    // no_claim=whether the program is allowlisted (policy) or exists (resolve)
    #[test]
    fn argv_shapes() {
        let ok = |a: &[&str]| RunInput::new(s(a), "/r".into(), vec![]);
        assert!(ok(&["psql", "-c", "select 1"]).is_ok());
        assert!(ok(&["/opt/tools/deploy"]).is_ok());
        for bad in [
            vec![],
            vec!["./deploy.sh"],
            vec!["bin/x"],
            vec![""],
            vec!["."],
            vec!["/a/../b"],
            vec!["ps\nql"],
            vec!["psql", "a\0b"],
        ] {
            assert!(ok(&bad).is_err(), "accepted {bad:?}");
        }
        let e = ok(&["./deploy.sh"]).unwrap_err();
        assert_eq!(e.kind, RunErrorKind::Denied);
        let many = vec!["x".to_owned(); MAX_ARGS + 1];
        assert!(RunInput::new(many, "/r".into(), vec![]).is_err());
        let big = vec!["x".to_owned(), "y".repeat(MAX_ARGV_BYTES)];
        assert!(RunInput::new(big, "/r".into(), vec![]).is_err());
        assert!(RunInput::new(s(&["x"]), "rel".into(), vec![]).is_err());
    }

    // protects=only ref-bearing variables with safe names are accepted, so a call can't set PATH,
    // HOME or a loader variable for the child; fails_when=any denied name or a ref-less value
    // passes; no_claim=what the child's environment ends up as (runner tests)
    #[test]
    fn env_rules() {
        let with =
            |n: &str, v: &str| RunInput::new(s(&["x"]), "/r".into(), vec![(n.into(), v.into())]);
        let r = with("DATABASE_URL", "ms://pg/staging").unwrap();
        assert_eq!(r.env_keys.len(), 1);
        assert!(with("TOKEN", "Bearer ms://a/b").is_ok());
        for bad in [
            "PATH",
            "HOME",
            "SHELL",
            "IFS",
            "BASH_ENV",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PERL5OPT",
            "NODE_OPTIONS",
            "RUBYOPT",
            "GIT_SSH_COMMAND",
            "JAVA_TOOL_OPTIONS",
            "VISUAL",
            "EDITOR",
            "PAGER",
            "PSQL_PAGER",
            "SSH_ASKPASS",
            "SUDO_ASKPASS",
            "LESSOPEN",
            "BROWSER",
            "1X",
            "A-B",
            "",
            "A B",
        ] {
            assert!(with(bad, "ms://a").is_err(), "accepted {bad:?}");
        }
        assert!(with("X", "no ref here").is_err());
        assert!(with("X", "ms://a\0").is_err());
        let dup = RunInput::new(
            s(&["x"]),
            "/r".into(),
            vec![("A".into(), "ms://a".into()), ("A".into(), "ms://b".into())],
        );
        assert!(dup.is_err());
        let many: Vec<_> = (0..=MAX_ENV)
            .map(|i| (format!("V{i}"), "ms://a".to_owned()))
            .collect();
        assert!(RunInput::new(s(&["x"]), "/r".into(), many).is_err());
    }

    // protects=keys are found in argv and env separately (the generic adapter refuses argv refs);
    // fails_when=a ref is missed or attributed to the wrong place; no_claim=ref grammar (ms-core)
    #[test]
    fn keys_found() {
        let r = RunInput::new(
            s(&["curl", "-H", "Authorization: Bearer ms://stripe/test"]),
            "/r".into(),
            vec![("DB".into(), "postgres://u@h/d?password=ms://pg/x".into())],
        )
        .unwrap();
        let names = |set: &BTreeSet<KeyName>| {
            set.iter()
                .map(|k| k.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&r.argv_keys), ["stripe/test"]);
        assert_eq!(names(&r.env_keys), ["pg/x"]);
        assert_eq!(r.keys().len(), 2);
    }
}
