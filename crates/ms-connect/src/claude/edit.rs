//! Recorded, reversible edits to a JSON document (SPEC D7).
//!
//! Every change the connector makes is recorded with the value before and the value written, so
//! `disconnect` can undo exactly its own changes even after the user edited the file: a change is
//! undone only while the current value is still the one morsec wrote.

use super::json::Value;

/// One recorded change. Paths go through object keys only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The object member at `path` was set to `after`; it was `before` (None: absent).
    Set {
        /// Object keys from the root.
        path: Vec<String>,
        /// Previous value.
        before: Option<Value>,
        /// Value written.
        after: Value,
    },
    /// `value` was appended to the array at `path`.
    Add {
        /// Path of the array.
        path: Vec<String>,
        /// Element appended.
        value: Value,
    },
    /// The object member at `path` was set to `after`; it held a value of the user's that is
    /// not kept in any form (not even a hash, which a weak value could be guessed from), so undo
    /// removes the member (security review S1, S5).
    SetRedacted {
        /// Object keys from the root.
        path: Vec<String>,
        /// Value written.
        after: Value,
    },
    /// A command (hook or stdio MCP server) was wrapped as `ms run -- …` in place. Only what is
    /// needed to unwrap it is kept, never the command itself (security review S1).
    Wrap {
        /// For a server: the server object. For hooks: `["hooks", <event>]`, whose groups'
        /// `hooks` lists hold the wrapped hook.
        path: Vec<String>,
        /// SHA-256 of the wrapped object's shape: every member but `command` and `args`, plus
        /// the length of `args`. The command itself is never hashed, so an inline secret in it
        /// can't be guessed from the record (security review S5).
        sha256: String,
        /// It was shell form (`command` string, no `args`): unwrap from `/bin/sh -c`.
        shell: bool,
        /// It had an `args` member before.
        had_args: bool,
        /// For hooks: the (group, hook) index of the wrapped hook under `path`. Undo unwraps
        /// that hook only, so two hooks of the same shape can't be swapped (review F1).
        at: Option<(usize, usize)>,
    },
}

/// The shape hash of a wrapped command object (see [`Change::Wrap`]).
pub fn wrap_shape_sha256(v: &Value) -> String {
    let mut shape = v.clone();
    shape.remove("command");
    // A server's `env` values can hold secrets: hash only its names (review F3).
    if let Some(Value::Object(m)) = shape.get_mut("env") {
        for (_, x) in m.iter_mut() {
            *x = Value::Null;
        }
    }
    let n = v.get("args").and_then(Value::as_array).map_or(0, Vec::len);
    shape.set("args", Value::int(i64::try_from(n).unwrap_or(i64::MAX)));
    super::skel::sha256(&super::json::print(&shape, ""))
}

/// Unwraps `ms run -- …` in `o` per a [`Change::Wrap`]. False when `o` isn't such a wrap.
fn unwrap_command(o: &mut Value, shell: bool, had_args: bool) -> bool {
    let Some(argv) = o.get("args").and_then(Value::as_array).cloned() else {
        return false;
    };
    let strs: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
    let Some(a) = strs else { return false };
    if a.len() < 3 || a[0] != "run" || a[1] != "--" {
        return false;
    }
    if shell {
        if a.len() != 5 || a[2] != "/bin/sh" || a[3] != "-c" {
            return false;
        }
        o.set("command", Value::str(a[4]));
        o.remove("args");
    } else {
        o.set("command", Value::str(a[2]));
        if had_args {
            o.set("args", Value::Array(argv[3..].to_vec()));
        } else {
            o.remove("args");
        }
    }
    true
}

/// The changes made to one document, plus the containers created for them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edits {
    /// In the order made.
    pub changes: Vec<Change>,
    /// Objects or arrays that did not exist before, in creation order.
    pub created: Vec<Vec<String>>,
}

impl Edits {
    /// True when nothing was changed.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.created.is_empty()
    }
}

fn dotted(path: &[String]) -> String {
    path.join(".")
}

/// Makes sure an object exists at `path`, creating (and recording) missing ones.
pub fn ensure_object<'a>(
    root: &'a mut Value,
    path: &[String],
    edits: &mut Edits,
) -> Result<&'a mut Value, String> {
    let mut cur = root;
    for (i, k) in path.iter().enumerate() {
        if !matches!(cur, Value::Object(_)) {
            return Err(format!(
                "settings key \"{}\" is {}, but an object was expected there",
                dotted(&path[..i]),
                cur.kind()
            ));
        }
        if cur.get(k).is_none() {
            cur.set(k, Value::object());
            edits.created.push(path[..=i].to_vec());
        }
        cur = cur.get_mut(k).ok_or("unreachable")?;
    }
    if !matches!(cur, Value::Object(_)) {
        return Err(format!(
            "settings key \"{}\" is {}, but an object was expected there",
            dotted(path),
            cur.kind()
        ));
    }
    Ok(cur)
}

/// Sets `path` to `value`, recording the change (nothing is recorded when it already had it).
pub fn set(
    root: &mut Value,
    path: &[String],
    value: Value,
    edits: &mut Edits,
) -> Result<(), String> {
    let (key, parent) = path.split_last().ok_or("empty path")?;
    let obj = ensure_object(root, parent, edits)?;
    if obj.get(key) == Some(&value) {
        return Ok(());
    }
    let before = obj.set(key, value.clone());
    edits.changes.push(Change::Set {
        path: path.to_vec(),
        before,
        after: value,
    });
    Ok(())
}

/// Adds `value` to the array at `path` unless an equal element is there, creating the array if
/// needed.
pub fn add_unique(
    root: &mut Value,
    path: &[String],
    value: Value,
    edits: &mut Edits,
) -> Result<(), String> {
    let (key, parent) = path.split_last().ok_or("empty path")?;
    let obj = ensure_object(root, parent, edits)?;
    if obj.get(key).is_none() {
        obj.set(key, Value::Array(Vec::new()));
        edits.created.push(path.to_vec());
    }
    let Some(Value::Array(a)) = obj.get_mut(key) else {
        return Err(format!(
            "settings key \"{}\" is {}, but a list was expected there",
            dotted(path),
            obj.get(key).map_or("missing", Value::kind)
        ));
    };
    if a.contains(&value) {
        return Ok(());
    }
    a.push(value.clone());
    edits.changes.push(Change::Add {
        path: path.to_vec(),
        value,
    });
    Ok(())
}

/// `o` is a wrap with the shape `sha256` records, in the form a record with `shell` unwraps
/// (shell: `ms run -- /bin/sh -c CMD`).
fn wrap_fits(o: &Value, sha256: &str, shell: bool) -> bool {
    let Some(a) = o.get("args").and_then(Value::as_array) else {
        return false;
    };
    wrap_shape_sha256(o) == sha256
        && a.first() == Some(&Value::str("run"))
        && (!shell || (a.len() == 5 && a[2] == Value::str("/bin/sh") && a[3] == Value::str("-c")))
}

fn wrap_note(path: &[String]) -> String {
    format!(
        "a command morsec wrapped in {} was edited or moved after ms connect, so morsec can't tell it apart; it is left as it is now (still run through `ms run --`). Edit it back by hand if you need to",
        dotted(path)
    )
}

/// A hook wrap record: (sha256, shell, had_args, position).
type WrapRec<'a> = (&'a str, bool, bool, Option<(usize, usize)>);

/// Undoes the hook wraps of each event together (review F1, G1, G3). First every record whose
/// hook is still at the recorded place; then the rest by shape, against the hooks still wrapped.
/// Records with the same shape and form are interchangeable (the command comes back from the
/// hook's own argv), so a hook is refused only when it also fits a still-open record of another
/// form: picking there could turn a shell-form hook into exec form or back.
fn undo_hook_wraps(root: &mut Value, changes: &[Change], notes: &mut Vec<String>) {
    let mut events: Vec<&Vec<String>> = Vec::new();
    for c in changes {
        if let Change::Wrap { path, .. } = c
            && matches!(root.at(path), Some(Value::Array(_)))
            && !events.contains(&path)
        {
            events.push(path);
        }
    }
    for event in events {
        // Newest first.
        let recs: Vec<WrapRec<'_>> = changes
            .iter()
            .rev()
            .filter_map(|c| match c {
                Change::Wrap {
                    path,
                    sha256,
                    shell,
                    had_args,
                    at,
                } if path == event => Some((sha256.as_str(), *shell, *had_args, *at)),
                _ => None,
            })
            .collect();
        let Some(Value::Array(groups)) = root.at_mut(event) else {
            continue;
        };
        let mut hooks: Vec<(usize, usize, &mut Value)> = Vec::new();
        for (gi, g) in groups.iter_mut().enumerate() {
            if let Some(Value::Array(hs)) = g.get_mut("hooks") {
                for (hi, h) in hs.iter_mut().enumerate() {
                    hooks.push((gi, hi, h));
                }
            }
        }
        let mut used = vec![false; hooks.len()];
        let mut open: Vec<usize> = Vec::new();
        for (r, (sha, shell, had_args, at)) in recs.iter().enumerate() {
            let i = at.and_then(|p| hooks.iter().position(|(g, h, _)| (*g, *h) == p));
            match i {
                Some(i) if !used[i] && wrap_fits(hooks[i].2, sha, *shell) => {
                    used[i] = unwrap_command(hooks[i].2, *shell, *had_args);
                    if !used[i] {
                        open.push(r);
                    }
                }
                _ => open.push(r),
            }
        }
        let mut done = vec![false; recs.len()];
        for &r in &open {
            let (sha, shell, had_args, _) = recs[r];
            let rival = |i: usize, done: &[bool]| {
                open.iter().any(|&q| {
                    let (qs, qsh, qha, _) = recs[q];
                    !done[q] && (qsh, qha) != (shell, had_args) && wrap_fits(hooks[i].2, qs, qsh)
                })
            };
            let cands: Vec<usize> = (0..hooks.len())
                .filter(|&i| !used[i] && wrap_fits(hooks[i].2, sha, shell))
                .collect();
            let pick = cands.first().copied();
            if let Some(i) = pick
                && !cands.iter().any(|&j| rival(j, &done))
                && unwrap_command(hooks[i].2, shell, had_args)
            {
                used[i] = true;
                done[r] = true;
            } else {
                notes.push(wrap_note(event));
            }
        }
    }
}

/// Undoes `edits` on `root`, newest first. A change whose current value is no longer the one
/// written is left alone, with a note. Created containers are removed only when empty.
pub fn undo(root: &mut Value, edits: &Edits) -> Vec<String> {
    let mut notes = Vec::new();
    undo_hook_wraps(root, &edits.changes, &mut notes);
    for c in edits.changes.iter().rev() {
        match c {
            Change::Set {
                path,
                before,
                after,
            } => {
                let Some((key, parent)) = path.split_last() else {
                    continue;
                };
                if root.at(path) != Some(after) {
                    notes.push(format!(
                        "{} was changed after ms connect; left as it is now",
                        dotted(path)
                    ));
                    continue;
                }
                if let Some(obj) = root.at_mut(parent) {
                    match before {
                        Some(b) => {
                            obj.set(key, b.clone());
                        }
                        None => {
                            obj.remove(key);
                        }
                    }
                }
            }
            Change::Add { path, value } => {
                if let Some(Value::Array(a)) = root.at_mut(path)
                    && let Some(i) = a.iter().position(|e| e == value)
                {
                    a.remove(i);
                    continue;
                }
                notes.push(format!(
                    "an entry morsec added to {} is gone or changed; nothing to remove there",
                    dotted(path)
                ));
            }
            Change::SetRedacted { path, after, .. } => {
                let Some((key, parent)) = path.split_last() else {
                    continue;
                };
                if root.at(path) != Some(after) {
                    notes.push(format!(
                        "{} was changed after ms connect; left as it is now",
                        dotted(path)
                    ));
                    continue;
                }
                if let Some(obj) = root.at_mut(parent) {
                    obj.remove(key);
                }
                notes.push(format!(
                    "{} held a value of yours before ms connect; morsec never keeps values, so it was removed, not put back. Set it again if you still need it",
                    dotted(path)
                ));
            }
            Change::Wrap {
                path,
                sha256,
                shell,
                had_args,
                ..
            } => {
                // Hook wraps (a list under `path`) were undone together above.
                if matches!(root.at(path), Some(Value::Array(_))) {
                    continue;
                }
                let done = match root.at_mut(path) {
                    Some(o) if wrap_fits(o, sha256, *shell) => unwrap_command(o, *shell, *had_args),
                    _ => false,
                };
                if !done {
                    notes.push(wrap_note(path));
                }
            }
        }
    }
    for p in edits.created.iter().rev() {
        let Some((key, parent)) = p.split_last() else {
            continue;
        };
        if root.at(p).is_some_and(Value::is_empty_container)
            && let Some(obj) = root.at_mut(parent)
        {
            obj.remove(key);
        }
    }
    notes
}

/// `path` as a list of owned keys.
pub fn path(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| (*k).to_owned()).collect()
}

// ---- state (de)serialisation ------------------------------------------------------------------

fn path_value(p: &[String]) -> Value {
    Value::Array(p.iter().map(|k| Value::str(k.clone())).collect())
}

fn value_path(v: Option<&Value>) -> Result<Vec<String>, String> {
    v.and_then(Value::as_array)
        .ok_or("state: path is not a list")?
        .iter()
        .map(|k| {
            k.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "state: path element is not a string".to_owned())
        })
        .collect()
}

/// Edits as a JSON value for the state file.
pub fn edits_to_value(e: &Edits) -> Value {
    let changes = e
        .changes
        .iter()
        .map(|c| {
            let mut o = Value::object();
            match c {
                Change::Set {
                    path,
                    before,
                    after,
                } => {
                    o.set("op", Value::str("set"));
                    o.set("path", path_value(path));
                    if let Some(b) = before {
                        o.set("before", b.clone());
                    }
                    o.set("after", after.clone());
                }
                Change::Add { path, value } => {
                    o.set("op", Value::str("add"));
                    o.set("path", path_value(path));
                    o.set("value", value.clone());
                }
                Change::SetRedacted { path, after } => {
                    o.set("op", Value::str("set_redacted"));
                    o.set("path", path_value(path));
                    o.set("after", after.clone());
                }
                Change::Wrap {
                    path,
                    sha256,
                    shell,
                    had_args,
                    at,
                } => {
                    o.set("op", Value::str("wrap"));
                    o.set("path", path_value(path));
                    o.set("sha256", Value::str(sha256.clone()));
                    o.set("shell", Value::Bool(*shell));
                    o.set("had_args", Value::Bool(*had_args));
                    if let Some((g, h)) = at {
                        let int = |n: usize| Value::int(i64::try_from(n).unwrap_or(i64::MAX));
                        o.set("group", int(*g));
                        o.set("hook", int(*h));
                    }
                }
            }
            o
        })
        .collect();
    let mut o = Value::object();
    o.set("changes", Value::Array(changes));
    o.set(
        "created",
        Value::Array(e.created.iter().map(|p| path_value(p)).collect()),
    );
    o
}

/// A non-negative integer index from the state file.
fn index(v: &Value) -> Result<usize, String> {
    match v {
        Value::Number(n) => n.parse().map_err(|_| "state: bad wrap position".into()),
        _ => Err("state: bad wrap position".into()),
    }
}

/// Edits from the state file.
pub fn edits_from_value(v: &Value) -> Result<Edits, String> {
    let mut e = Edits::default();
    for c in v
        .get("changes")
        .and_then(Value::as_array)
        .ok_or("state: changes missing")?
    {
        let path = value_path(c.get("path"))?;
        let need = |k: &str| {
            c.get(k)
                .cloned()
                .ok_or_else(|| format!("state: change is missing {k}"))
        };
        let need_str = |k: &str| {
            c.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("state: change is missing {k}"))
        };
        e.changes.push(match c.get("op").and_then(Value::as_str) {
            Some("set") => Change::Set {
                path,
                before: c.get("before").cloned(),
                after: need("after")?,
            },
            Some("add") => Change::Add {
                path,
                value: need("value")?,
            },
            Some("set_redacted") => Change::SetRedacted {
                path,
                after: need("after")?,
            },
            Some("wrap") => Change::Wrap {
                path,
                sha256: need_str("sha256")?,
                shell: c.get("shell") == Some(&Value::Bool(true)),
                had_args: c.get("had_args") == Some(&Value::Bool(true)),
                at: match (c.get("group"), c.get("hook")) {
                    (None, None) => None,
                    (Some(g), Some(h)) => Some((index(g)?, index(h)?)),
                    _ => return Err("state: wrap position is incomplete".into()),
                },
            },
            _ => return Err("state: unknown change".into()),
        });
    }
    for p in v
        .get("created")
        .and_then(Value::as_array)
        .ok_or("state: created missing")?
    {
        e.created.push(value_path(Some(p))?);
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::super::json::parse;
    use super::*;

    // protects=undo removes exactly what set/add_unique recorded, prunes containers it
    // created, and leaves a value the user changed since; fails_when=a user edit is reverted or
    // an empty created container stays
    #[test]
    fn undo_is_exact_and_respects_user_edits() {
        let orig = parse(r#"{"a": 1, "sandbox": {"enabled": false}, "l": ["x"]}"#).unwrap();
        let mut v = orig.clone();
        let mut e = Edits::default();
        set(
            &mut v,
            &path(&["sandbox", "enabled"]),
            Value::Bool(true),
            &mut e,
        )
        .unwrap();
        set(&mut v, &path(&["env", "X"]), Value::str("1"), &mut e).unwrap();
        add_unique(&mut v, &path(&["l"]), Value::str("y"), &mut e).unwrap();
        add_unique(&mut v, &path(&["l"]), Value::str("x"), &mut e).unwrap();
        add_unique(&mut v, &path(&["new", "list"]), Value::str("z"), &mut e).unwrap();
        assert_eq!(e.changes.len(), 4);
        let round = edits_from_value(&edits_to_value(&e)).unwrap();
        assert_eq!(round, e);

        let mut w = v.clone();
        assert!(undo(&mut w, &e).is_empty());
        assert_eq!(w, orig);

        // The user changes sandbox.enabled after connect: it stays; the rest is undone.
        let mut u = v.clone();
        u.at_mut(&path(&["sandbox"]))
            .unwrap()
            .set("enabled", Value::str("mine"));
        let notes = undo(&mut u, &e);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(
            u.at(&path(&["sandbox", "enabled"])),
            Some(&Value::str("mine"))
        );
        assert!(u.get("env").is_none() && u.get("new").is_none());
    }

    // protects=review F3: the wrap shape hash covers a server's env names but not their
    // values, so the state can't be used to test a guess at a secret; fails_when=a value changes
    // the hash or a name doesn't
    #[test]
    fn shape_hash_ignores_env_values() {
        let a =
            parse(r#"{"command":"x","args":["run","--","s"],"env":{"TOKEN":"ghp_A"}}"#).unwrap();
        let b =
            parse(r#"{"command":"y","args":["run","--","t"],"env":{"TOKEN":"ghp_B"}}"#).unwrap();
        let c =
            parse(r#"{"command":"x","args":["run","--","s"],"env":{"OTHER":"ghp_A"}}"#).unwrap();
        assert_eq!(wrap_shape_sha256(&a), wrap_shape_sha256(&b));
        assert_ne!(wrap_shape_sha256(&a), wrap_shape_sha256(&c));
    }

    #[test]
    fn type_conflicts_are_errors() {
        let mut v = parse(r#"{"sandbox": true, "l": {}}"#).unwrap();
        let mut e = Edits::default();
        assert!(
            set(
                &mut v,
                &path(&["sandbox", "enabled"]),
                Value::Bool(true),
                &mut e
            )
            .is_err()
        );
        assert!(add_unique(&mut v, &path(&["l"]), Value::Null, &mut e).is_err());
    }
}
