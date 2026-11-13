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
    /// An element of the array at `path` equal to `before` was replaced by `after`.
    Replace {
        /// Path of the array.
        path: Vec<String>,
        /// Element before.
        before: Value,
        /// Element after.
        after: Value,
    },
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
            Change::Replace {
                path,
                before,
                after,
            } => {
                if let Some(Value::Array(a)) = root.at_mut(path)
                    && let Some(e) = a.iter_mut().find(|e| *e == after)
                {
                    *e = before.clone();
                    continue;
                }
                notes.push(format!(
                    "an entry morsec changed in {} was edited after ms connect; left as it is now",
                    dotted(path)
                ));
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
                Change::Replace {
                    path,
                    before,
                    after,
                } => {
                    o.set("op", Value::str("replace"));
                    o.set("path", path_value(path));
                    o.set("before", before.clone());
                    o.set("after", after.clone());
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
            Some("replace") => Change::Replace {
                path,
                before: need("before")?,
                after: need("after")?,
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

    // protects=undo removes exactly what set/add_unique/Replace recorded, prunes containers it
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
