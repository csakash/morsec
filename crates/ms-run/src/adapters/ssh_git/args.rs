//! Arguments: which tool a call is, what the caller may pass to it, and the ssh options morsec
//! always puts first (SPEC D5, D6).

use std::path::Path;

use crate::error::RunError;

use super::HostPin;

/// The tools this adapter runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `ssh`.
    Ssh,
    /// `git`.
    Git,
}

/// The tool `argv0` names: only the bare names `ssh` and `git`, resolved from the trusted path
/// (an absolute path could be a file the agent wrote, review R3).
pub fn tool_of(argv0: &str) -> Option<Tool> {
    match argv0 {
        "ssh" => Some(Tool::Ssh),
        "git" => Some(Tool::Git),
        _ => None,
    }
}

/// ssh flags that take an argument (OpenSSH 10 `ssh.c` getopt string).
const SSH_WITH_ARG: &[u8] = b"BbcDEeFIiJLlmOoPpQRSWw";
/// ssh flags without an argument.
const SSH_PLAIN: &[u8] = b"1246AaCfGgKkMNnqsTtVvXxYy";
/// Flags the caller may not pass: agent forwarding, another config file, a jump host, a control
/// socket or master, a PKCS#11 provider.
const SSH_REFUSED: &[u8] = b"AFJSMI";

/// Checks the caller's arguments (after `argv[0]`) for `tool`. For ssh, the destination must be
/// one of `pins` (host and port).
pub fn check(tool: Tool, args: &[String], pins: &[HostPin]) -> Result<(), RunError> {
    match tool {
        Tool::Git => check_git(args),
        Tool::Ssh => check_ssh(args, pins),
    }
}

/// The git subcommands a morsec key can run with (review R1): the ones that talk to a remote and
/// start no program the caller chose. Aliases, `rebase --exec`, `submodule foreach`,
/// `bisect run`, `difftool -x`, `clone -c/--template` and the like are refused with them.
pub const GIT_SUBCOMMANDS: &[&str] = &["push", "fetch", "pull", "ls-remote"];

fn check_git(args: &[String]) -> Result<(), RunError> {
    let Some(sub) = args.first() else {
        return Err(RunError::invalid(
            "morsec: name a git subcommand, e.g. git push",
        ));
    };
    if sub.starts_with('-') {
        return Err(RunError::denied(format!(
            "morsec: git options before the subcommand ({}) are refused with a morsec key: they can change which config, repository or programs git uses. Run from the repository directory instead",
            crate::printable(sub)
        )));
    }
    if !GIT_SUBCOMMANDS.contains(&sub.as_str()) {
        return Err(RunError::denied(format!(
            "morsec: git {} doesn't run with a morsec key; only git {} do",
            crate::printable(sub),
            GIT_SUBCOMMANDS.join(", git ")
        )));
    }
    for a in &args[1..] {
        if a == "--" {
            break;
        }
        if a.starts_with("--recurse-submodules") {
            return Err(RunError::denied(
                "morsec: --recurse-submodules is refused with a morsec key: a submodule's own git config is not checked",
            ));
        }
        if a.starts_with("--signed") || a.starts_with("--gpg-sign") || a.starts_with("-S") {
            return Err(RunError::denied(
                "morsec: signing (--signed, -S) is refused with a morsec key: it runs a signing program",
            ));
        }
    }
    Ok(())
}

fn check_ssh(args: &[String], pins: &[HostPin]) -> Result<(), RunError> {
    let mut port: Option<u16> = None;
    let mut dest: Option<&str> = None;
    let mut i = 0;
    let mut ended = false;
    while i < args.len() {
        let a = args[i].as_str();
        let option = !ended && a.starts_with('-') && a.len() > 1;
        if !option {
            if dest.is_some() {
                break; // the remote command starts here
            }
            if !ended && a == "-" {
                return Err(RunError::invalid("morsec: ssh: '-' is not a destination"));
            }
            dest = Some(a);
            i += 1;
            // ssh reads options again right after the destination (ssh.c `again:`).
            continue;
        }
        if a == "--" {
            ended = true;
            i += 1;
            continue;
        }
        let flags = &a.as_bytes()[1..];
        let mut j = 0;
        while j < flags.len() {
            let f = flags[j];
            if SSH_REFUSED.contains(&f) {
                return Err(RunError::denied(format!(
                    "morsec: ssh -{} is refused with a morsec key (agent forwarding, another config file, jump hosts, control sockets and PKCS#11 are off)",
                    f as char
                )));
            }
            if SSH_WITH_ARG.contains(&f) {
                let value = if j + 1 < flags.len() {
                    std::str::from_utf8(&flags[j + 1..])
                        .unwrap_or("")
                        .to_owned()
                } else {
                    i += 1;
                    args.get(i).cloned().ok_or_else(|| {
                        RunError::invalid(format!("morsec: ssh -{} needs a value", f as char))
                    })?
                };
                if f == b'o' {
                    check_ssh_option(&value)?;
                }
                if f == b'p' {
                    port =
                        Some(value.parse().ok().filter(|p| *p != 0).ok_or_else(|| {
                            RunError::invalid("morsec: ssh -p takes a port number")
                        })?);
                }
                break;
            }
            if !SSH_PLAIN.contains(&f) {
                return Err(RunError::invalid(format!(
                    "morsec: unknown ssh option -{}",
                    (f as char).escape_default()
                )));
            }
            j += 1;
        }
        i += 1;
    }
    let Some(dest) = dest else {
        return Err(RunError::invalid("morsec: ssh needs a destination"));
    };
    let (host, url_port) = destination(dest)?;
    let port = url_port.or(port).unwrap_or(22);
    let host = host.to_ascii_lowercase();
    if pins.iter().any(|p| p.host == host && p.port == port) {
        Ok(())
    } else {
        Err(RunError::denied(format!(
            "morsec: {} is not a pinned SSH host for this key. Pin it from your own terminal: ms rules <key> --add-ssh-host-key \"$(ssh-keyscan -t ed25519{} {})\"",
            crate::printable(&host),
            if port == 22 {
                String::new()
            } else {
                format!(" -p {port}")
            },
            crate::printable(&host),
        )))
    }
}

/// `-o` options a caller may pass to ssh with a morsec key (review R2). The rest could send ssh
/// to another host (`HostName`, `Port`, `HostKeyAlias`), run code inside it (`PKCS11Provider`,
/// `SecurityKeyProvider`, `KnownHostsCommand`, `Match exec`), or are morsec's own.
const SSH_OPTIONS: &[&str] = &[
    "serveraliveinterval",
    "serveralivecountmax",
    "connecttimeout",
    "connectionattempts",
    "loglevel",
    "requesttty",
    "compression",
    "tcpkeepalive",
    "user",
];

fn check_ssh_option(value: &str) -> Result<(), RunError> {
    let key = value
        .trim_start()
        .split(|c: char| c == '=' || c.is_ascii_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if SSH_OPTIONS.contains(&key.as_str()) {
        Ok(())
    } else {
        Err(RunError::denied(format!(
            "morsec: ssh -o {} is refused with a morsec key; allowed: ServerAliveInterval, ServerAliveCountMax, ConnectTimeout, ConnectionAttempts, LogLevel, RequestTTY, Compression, TCPKeepAlive, User",
            crate::printable(&key)
        )))
    }
}

/// `[user@]host` or `ssh://[user@]host[:port]` → host and URL port.
fn destination(d: &str) -> Result<(&str, Option<u16>), RunError> {
    let bad = || {
        RunError::invalid(format!(
            "morsec: ssh: can't read the destination {}",
            crate::printable(d)
        ))
    };
    if let Some(rest) = d.strip_prefix("ssh://") {
        let hostport = rest.split('/').next().unwrap_or("");
        let hostport = hostport.rsplit_once('@').map_or(hostport, |(_, h)| h);
        if let Some(v6) = hostport.strip_prefix('[') {
            let (h, p) = v6.split_once(']').ok_or_else(bad)?;
            let port = match p.strip_prefix(':') {
                Some(p) => Some(p.parse().map_err(|_| bad())?),
                None if p.is_empty() => None,
                None => return Err(bad()),
            };
            return Ok((h, port));
        }
        return match hostport.split_once(':') {
            Some((h, p)) => Ok((h, Some(p.parse().map_err(|_| bad())?))),
            None => Ok((hostport, None)),
        };
    }
    let host = d.rsplit_once('@').map_or(d, |(_, h)| h);
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host, None))
}

/// The options morsec puts before the caller's ssh arguments. ssh keeps the first value of each
/// option, so these win. `agent` is the agent socket; `public` and `known_hosts` are files in the
/// run's private directory.
pub(crate) fn forced_ssh_options(agent: &Path, public: &Path, known_hosts: &Path) -> Vec<String> {
    let mut v = vec!["-F".to_owned(), "/dev/null".to_owned()];
    for o in [
        format!("IdentityAgent={}", agent.display()),
        "IdentitiesOnly=yes".to_owned(),
        format!("IdentityFile={}", public.display()),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "ForwardAgent=no".to_owned(),
        "ProxyCommand=none".to_owned(),
        "ProxyJump=none".to_owned(),
        "ControlMaster=no".to_owned(),
        "ControlPath=none".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "BatchMode=yes".to_owned(),
        "PasswordAuthentication=no".to_owned(),
        "KbdInteractiveAuthentication=no".to_owned(),
    ] {
        v.push("-o".to_owned());
        v.push(o);
    }
    v
}

/// A path ssh and the shell take literally: no spaces, quotes, `%` or `$` expansion, `~`.
pub(crate) fn plain_path(p: &Path) -> bool {
    p.to_str().is_some_and(|s| {
        s.starts_with('/')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
    })
}

/// Single-quotes `s` for `sh`.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Vec<HostPin> {
        vec![
            HostPin {
                host: "github.com".into(),
                port: 22,
                key: [0; 32],
            },
            HostPin {
                host: "127.0.0.1".into(),
                port: 4422,
                key: [0; 32],
            },
        ]
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    // protects=SPEC D5: a direct ssh call reaches only a pinned host and port, with no
    // forwarding, other config, jump host, control socket or PKCS#11 flag; fails_when=any of
    // these is accepted or a pinned destination is refused; no_claim=the host-key check itself
    // (agent tests and the sshd integration test)
    #[test]
    fn ssh_destinations_and_flags() {
        let p = pins();
        for ok in [
            &["-T", "git@github.com"][..],
            &["github.com", "echo", "-A"],
            &["-p", "4422", "me@127.0.0.1", "ls"],
            &["-oConnectTimeout=5", "-o", "User git", "github.com"],
            &["-p4422", "127.0.0.1"],
            &["ssh://me@127.0.0.1:4422"],
            &["-v", "-o", "ServerAliveInterval=5", "GitHub.com"],
            &["github.com", "-v", "--", "ls"],
        ] {
            check(Tool::Ssh, &v(ok), &p).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for bad in [
            &["evil.com"][..],
            &["-p", "2222", "github.com"],
            &["127.0.0.1"],
            &["-A", "github.com"],
            &["-tA", "github.com"],
            &["github.com", "-A"],
            &["-F", "/tmp/cfg", "github.com"],
            &["-J", "jump", "github.com"],
            &["-S", "/tmp/s", "github.com"],
            &["-I", "/lib.so", "github.com"],
            &["-M", "github.com"],
            &["-Z", "github.com"],
            &["-o", "HostName=evil.example", "github.com"],
            &["-oPort=2222", "github.com"],
            &["-o", "HostKeyAlias github.com", "evil.example"],
            &["-o", "PKCS11Provider=/tmp/x.dylib", "github.com"],
            &["-o", "SecurityKeyProvider=/tmp/x.dylib", "github.com"],
            &["-o", "KnownHostsCommand=/tmp/x", "github.com"],
            &["-o", "IdentityAgent=/tmp/s", "github.com"],
            &["-o", "Match exec /tmp/x", "github.com"],
            &["-p"],
            &[],
            &["ssh://github.com:x"],
        ] {
            assert!(check(Tool::Ssh, &v(bad), &p).is_err(), "{bad:?}");
        }
    }

    // protects=SPEC D6: git with a morsec key takes no global options (-c, -C, --git-dir,
    // --exec-path, --config-env could change its config or programs); fails_when=one passes;
    // no_claim=-
    #[test]
    fn git_takes_no_global_options() {
        assert!(check(Tool::Git, &v(&["push", "origin", "main"]), &[]).is_ok());
        for bad in [
            &["-c", "core.sshCommand=x", "push"][..],
            &["-C", "/x", "push"],
            &["--git-dir=/x", "push"],
            &["--exec-path=/x", "push"],
            &["--config-env=a=b", "push"],
            &["credential", "fill"],
            &["credential-store", "get"],
            &["x"],
            &["rebase", "--exec", "sh", "main"],
            &["submodule", "foreach", "sh"],
            &["bisect", "run", "sh"],
            &["clone", "-c", "a=b", "https://x/y"],
            &["push", "--signed", "origin"],
            &["pull", "-S"],
            &["push", "--recurse-submodules=on-demand"],
            &[],
        ] {
            assert!(check(Tool::Git, &v(bad), &[]).is_err(), "{bad:?}");
        }
        assert_eq!(tool_of("git"), Some(Tool::Git));
        assert_eq!(tool_of("/usr/bin/ssh"), None);
        assert_eq!(tool_of("sshx"), None);
        assert_eq!(tool_of("./git"), None);
    }

    // protects=paths given to ssh and sh are taken literally; fails_when=a path with an
    // expansion character or a quote passes, or quoting breaks out; no_claim=-
    #[test]
    fn literal_paths_and_quoting() {
        assert!(plain_path(Path::new(
            "/var/folders/ab/T/ms-ssh-01/agent.sock"
        )));
        for bad in ["/a b", "/a%d", "/a$HOME", "~/x", "/a'b", "rel"] {
            assert!(!plain_path(Path::new(bad)), "{bad}");
        }
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        let opts = forced_ssh_options(Path::new("/s"), Path::new("/p"), Path::new("/k"));
        assert_eq!(&opts[..2], ["-F", "/dev/null"]);
        assert!(opts.contains(&"ForwardAgent=no".to_owned()));
    }
}
