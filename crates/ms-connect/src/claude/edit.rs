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
    /// not kept (only its hash), so undo removes the member (security review S1).
    SetRedacted {
        /// Object keys from the root.
        path: Vec<String>,
        /// SHA-256 of the previous value, printed compactly.
        before_sha256: String,
        /// Value written.
        after: Value,
    },
    /// A command (hook or stdio MCP server) was wrapped as `ms run -- …` in place. Only what is
    /// needed to unwrap it is kept, never the command itself (security review S1).
    Wrap {
        /// For a server: the server object. For hooks: `["hooks", <event>]`, whose groups'
        /// `hooks` lists hold the wrapped hook.
        path: Vec<String>,
        /// SHA-256 of the wrapped object, printed compactly.
        sha256: String,
        /// It was shell form (`command` string, no `args`): unwrap from `/bin/sh -c`.
        shell: bool,
        /// It had an `args` member before.
        had_args: bool,
    },
}

/// SHA-256 of a value printed compactly, hex.
pub fn value_sha256(v: &Value) -> String {
    super::skel::sha256(&super::json::print(v, ""))
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

/// Undoes `edits` on `root`, newest first. A change whose current value is no longer the one
/// written is left alone, with a note. Created containers are removed only when empty.
pub fn undo(root: &mut Value, edits: &Edits) -> Vec<String> {
    let mut notes = Vec::new();
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
            } => {
                let hit = |o: &Value| value_sha256(o) == *sha256;
                let done = match root.at_mut(path) {
                    Some(Value::Array(groups)) => groups
                        .iter_mut()
                        .filter_map(|g| match g.get_mut("hooks") {
                            Some(Value::Array(hs)) => Some(hs),
                            _ => None,
                        })
                        .flat_map(|hs| hs.iter_mut())
                        .find(|h| hit(h))
                        .is_some_and(|h| unwrap_command(h, *shell, *had_args)),
                    Some(o @ Value::Object(_)) if hit(o) => unwrap_command(o, *shell, *had_args),
                    _ => false,
                };
                if !done {
                    notes.push(format!(
                        "a command morsec wrapped in {} was edited after ms connect; left as it is now",
                        dotted(path)
                    ));
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
                Change::SetRedacted {
                    path,
                    before_sha256,
                    after,
                } => {
                    o.set("op", Value::str("set_redacted"));
                    o.set("path", path_value(path));
                    o.set("before_sha256", Value::str(before_sha256.clone()));
                    o.set("after", after.clone());
                }
                Change::Wrap {
                    path,
                    sha256,
                    shell,
                    had_args,
                } => {
                    o.set("op", Value::str("wrap"));
                    o.set("path", path_value(path));
                    o.set("sha256", Value::str(sha256.clone()));
                    o.set("shell", Value::Bool(*shell));
                    o.set("had_args", Value::Bool(*had_args));
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
                before_sha256: need_str("before_sha256")?,
                after: need("after")?,
            },
            Some("wrap") => Change::Wrap {
                path,
                sha256: need_str("sha256")?,
                shell: c.get("shell") == Some(&Value::Bool(true)),
                had_args: c.get("had_args") == Some(&Value::Bool(true)),
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
