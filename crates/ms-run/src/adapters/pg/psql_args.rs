//! psql's command line, checked (SPEC D2).
//!
//! The connection comes only from the key: its ref is the whole connection argument (the
//! positional dbname or the value of `-d` / `--dbname`), and every option that would change the
//! host, port or user is refused. Options are parsed the way `getopt_long` does (short clusters,
//! `-xVALUE`, `--long=VALUE`, unique prefixes of long names, `--` ends options) and, to be safe
//! with either argument order, an option after a positional is still read as an option.
//! Unknown options are refused.

use ms_core::{KeyName, SecretRef};

/// psql 17's short options that take a value.
const SHORT_WITH_VALUE: &str = "cdfFhLopPRTUv";
/// psql 17's short options without a value.
const SHORT_FLAGS: &str = "aAbeEHlnqsStwWxXz01V?";
/// psql 17's long options: (name, takes a value, short equivalent or 0).
const LONG: &[(&str, bool, char)] = &[
    ("command", true, 'c'),
    ("dbname", true, 'd'),
    ("file", true, 'f'),
    ("field-separator", true, 'F'),
    ("host", true, 'h'),
    ("log-file", true, 'L'),
    ("output", true, 'o'),
    ("port", true, 'p'),
    ("pset", true, 'P'),
    ("record-separator", true, 'R'),
    ("table-attr", true, 'T'),
    ("username", true, 'U'),
    ("set", true, 'v'),
    ("variable", true, 'v'),
    ("echo-all", false, 'a'),
    ("no-align", false, 'A'),
    ("echo-errors", false, 'b'),
    ("echo-queries", false, 'e'),
    ("echo-hidden", false, 'E'),
    ("html", false, 'H'),
    ("list", false, 'l'),
    ("no-readline", false, 'n'),
    ("single-transaction", false, '1'),
    ("quiet", false, 'q'),
    ("single-step", false, 's'),
    ("single-line", false, 'S'),
    ("tuples-only", false, 't'),
    ("no-password", false, 'w'),
    ("password", false, 'W'),
    ("expanded", false, 'x'),
    ("no-psqlrc", false, 'X'),
    ("field-separator-zero", false, 'z'),
    ("record-separator-zero", false, '0'),
    ("csv", false, '\0'),
    ("version", false, 'V'),
    ("help", false, '?'),
];

/// Where the ref sits in argv, so the adapter can put the rewritten URL there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnArg {
    /// Index in argv (0 is the program).
    pub index: usize,
    /// Text before the ref in that argument (`""`, `"-d"` or `"--dbname="`).
    pub prefix: String,
}

/// A checked psql command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsqlArgs {
    /// The key the connection comes from.
    pub key: KeyName,
    /// Where its ref is.
    pub conn: ConnArg,
    /// The `-c` commands, in order.
    pub commands: Vec<String>,
    /// How many `-f` options there are.
    pub files: usize,
}

fn refuse<T>(m: impl Into<String>) -> Result<T, String> {
    Err(m.into())
}

/// The key when `s` is exactly one ref and nothing else.
fn whole_ref(s: &str) -> Option<KeyName> {
    let found = SecretRef::find_all(s);
    match found.as_slice() {
        [(range, r)] if range.start == 0 && range.end == s.len() => Some(r.name().clone()),
        _ => None,
    }
}

/// Handles one option's value: the connection, a refused option, or a command.
fn take(
    opt: char,
    long: &str,
    value: &str,
    index: usize,
    prefix: String,
    out: &mut Partial,
) -> Result<(), String> {
    match opt {
        'h' | 'p' | 'U' => refuse(format!(
            "psql's {long} is refused: the connection (host, port, user) comes only from the key's stored URL"
        )),
        'd' => {
            let Some(k) = whole_ref(value) else {
                return refuse(
                    "psql's dbname must be the key's ref itself (psql -d ms://<key> …); the database is the one in the key's stored URL",
                );
            };
            out.set_conn(k, ConnArg { index, prefix })
        }
        'o' | 'L' if value.trim_start().starts_with('|') => refuse(format!(
            "psql's {long} with a pipe would start a shell command, which morsec doesn't allow; write to a file, or let morsec return the output"
        )),
        'c' => {
            out.commands.push(value.to_owned());
            Ok(())
        }
        'f' => {
            out.files += 1;
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Default)]
struct Partial {
    conn: Option<(KeyName, ConnArg)>,
    commands: Vec<String>,
    files: usize,
}

impl Partial {
    fn set_conn(&mut self, k: KeyName, c: ConnArg) -> Result<(), String> {
        if self.conn.is_some() {
            return refuse("psql was given the connection twice; give the key's ref once");
        }
        self.conn = Some((k, c));
        Ok(())
    }
}

fn long_option(name: &str) -> Result<(&'static str, bool, char), String> {
    if let Some(&(n, v, c)) = LONG.iter().find(|(n, _, _)| *n == name) {
        return Ok((n, v, c));
    }
    let matches: Vec<_> = LONG
        .iter()
        .filter(|(n, _, _)| n.starts_with(name))
        .collect();
    // `--set` and `--variable` both mean -v; any other overlap is ambiguous.
    match matches.as_slice() {
        [(n, v, c)] => Ok((n, *v, *c)),
        [] => refuse(format!(
            "psql option --{} isn't one morsec knows, so it is refused",
            crate::printable(name)
        )),
        _ => refuse(format!(
            "psql option --{} is ambiguous",
            crate::printable(name)
        )),
    }
}

/// Checks `argv` (`argv[0]` is the program).
pub fn parse(argv: &[String]) -> Result<PsqlArgs, String> {
    let mut out = Partial::default();
    let mut positional: Vec<(usize, &str)> = Vec::new();
    let mut only_positional = false;
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if only_positional || a == "-" || !a.starts_with('-') {
            positional.push((i, a));
            i += 1;
            continue;
        }
        if a == "--" {
            only_positional = true;
            i += 1;
            continue;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (body, None),
            };
            let (full, takes, short) = long_option(name)?;
            let long = format!("--{full}");
            if takes {
                let (value, idx, prefix) = match inline {
                    Some(v) => (v, i, format!("--{name}=")),
                    None => {
                        i += 1;
                        let Some(v) = argv.get(i) else {
                            return refuse(format!("psql's {long} needs a value"));
                        };
                        (v.as_str(), i, String::new())
                    }
                };
                take(short, &long, value, idx, prefix, &mut out)?;
            } else if full == "help" {
                // `--help[=topic]`: harmless.
            } else if inline.is_some() {
                return refuse(format!("psql's {long} takes no value"));
            }
            i += 1;
            continue;
        }
        // A cluster of short options: `-At`, `-Atc SQL`, `-cSQL`.
        let chars: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            if SHORT_WITH_VALUE.contains(c) {
                let rest: String = chars[j + 1..].iter().collect();
                let long = format!("-{c}");
                if rest.is_empty() {
                    i += 1;
                    let Some(v) = argv.get(i) else {
                        return refuse(format!("psql's {long} needs a value"));
                    };
                    take(c, &long, v, i, String::new(), &mut out)?;
                } else {
                    let prefix: String = a[..a.len() - rest.len()].to_owned();
                    take(c, &long, &rest, i, prefix, &mut out)?;
                }
                break;
            }
            if !SHORT_FLAGS.contains(c) {
                return refuse(format!(
                    "psql option -{} isn't one morsec knows, so it is refused",
                    crate::printable(&c.to_string())
                ));
            }
            j += 1;
        }
        i += 1;
    }
    for (idx, p) in positional {
        match whole_ref(p) {
            Some(k) => out.set_conn(
                k,
                ConnArg {
                    index: idx,
                    prefix: String::new(),
                },
            )?,
            None => {
                return refuse(
                    "psql takes the key's ref as its only connection argument (psql ms://<key> -c …); other positional arguments (database, user) are refused",
                );
            }
        }
    }
    let Some((key, conn)) = out.conn else {
        return refuse("psql needs the key's ref as its connection argument: psql ms://<key> …");
    };
    // A ref anywhere else would reach psql as literal text; say so instead.
    for (n, a) in argv.iter().enumerate() {
        if n != conn.index && !SecretRef::find_all(a).is_empty() {
            return refuse(
                "a reference in another psql argument isn't substituted; the key goes only in the connection argument",
            );
        }
    }
    Ok(PsqlArgs {
        key,
        conn,
        commands: out.commands,
        files: out.files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // protects=SPEC D2: the connection comes only from the key's ref; every way getopt_long
    // accepts a host/port/user/dbname (short, cluster, attached, long, prefix, after a
    // positional) is refused, and so are unknown options and pipes; fails_when=an agent can
    // point psql somewhere else or start a shell from the command line; no_claim=psql's
    // meta-commands inside -c (passfile is gone by then, residual in ARI42)
    #[test]
    fn connection_only_from_the_key() {
        let p = parse(&a(&["psql", "ms://pg/prod", "-Atc", "select 1"])).unwrap();
        assert_eq!(p.key.as_str(), "pg/prod");
        assert_eq!(
            p.conn,
            ConnArg {
                index: 1,
                prefix: String::new()
            }
        );
        assert_eq!(p.commands, ["select 1"]);
        let p = parse(&a(&["psql", "-X", "--dbname=ms://pg/prod", "-f", "x.sql"])).unwrap();
        assert_eq!(p.conn.prefix, "--dbname=");
        assert_eq!(p.files, 1);
        let p = parse(&a(&["psql", "-dms://pg/prod", "-c", "a", "--command=b"])).unwrap();
        assert_eq!(p.conn.prefix, "-d");
        assert_eq!(p.commands, ["a", "b"]);
        let p = parse(&a(&["psql", "--dbn", "ms://pg/prod", "--var", "X=1"])).unwrap();
        assert_eq!(p.conn.index, 2);

        for bad in [
            &["psql", "ms://pg/prod", "-h", "evil"][..],
            &["psql", "-hevil", "ms://pg/prod"],
            &["psql", "-qh", "evil", "ms://pg/prod"],
            &["psql", "--host=evil", "ms://pg/prod"],
            &["psql", "--ho", "evil", "ms://pg/prod"],
            &["psql", "ms://pg/prod", "-p", "1"],
            &["psql", "ms://pg/prod", "-U", "postgres"],
            &["psql", "ms://pg/prod", "--user=postgres"],
            &["psql", "ms://pg/prod", "otheruser"],
            &["psql", "-d", "postgres://h/db", "ms://pg/prod"],
            &["psql", "ms://pg/prod", "ms://pg/prod"],
            &["psql", "ms://pg/prod", "--", "-h"],
            &["psql", "ms://pg/prod", "-o", "|curl x"],
            &["psql", "ms://pg/prod", "--log-file= |sh"],
            &["psql", "ms://pg/prod", "-c", "select 'ms://pg/prod'"],
            &["psql", "ms://pg/prod", "-K"],
            &["psql", "ms://pg/prod", "--frobnicate"],
            &["psql", "ms://pg/prod", "--csv=x"],
            &["psql", "ms://pg/prod", "-c"],
            &["psql", "-c", "select 1"],
            &["psql", "postgres://u:ms://pg/prod@h/db"],
            &["psql", "x ms://pg/prod"],
        ] {
            assert!(parse(&a(bad)).is_err(), "{bad:?}");
        }
    }
}
