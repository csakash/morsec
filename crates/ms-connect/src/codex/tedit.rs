//! Recorded, reversible edits to a TOML document (SPEC D3, D4).
//!
//! Every change morsec makes to `config.toml` is a [`Record`] keyed by its full key path, never
//! by position in an array or by the shape of a value (the L08 review F1 bug). A plan always
//! starts from the document with the previous connect undone and records afresh, so a re-run
//! can't add a second record for the same path (the L08 review F2 bug): [`Edits::push`] keeps
//! one record per path.
//!
//! Edits go through `toml_edit`, which keeps comments, ordering and layout of everything it
//! doesn't touch. Inserted keys and tables carry default decoration, so removing them gives back
//! the exact bytes; the connector checks that with a dry undo before writing anything.

use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

/// A value compared by content, not by layout: `"a"` and `'a'` are equal, as are an inline table
/// and a `[table]` with the same keys.
#[derive(Debug, Clone, PartialEq)]
pub enum Canon {
    /// A string.
    Str(String),
    /// An integer.
    Int(i64),
    /// A float, by its text.
    Float(String),
    /// A boolean.
    Bool(bool),
    /// A date-time, by its text.
    Datetime(String),
    /// An array.
    Array(Vec<Canon>),
    /// A table, keys sorted.
    Table(Vec<(String, Canon)>),
}

/// The content of a value.
pub fn canon_value(v: &Value) -> Canon {
    match v {
        Value::String(s) => Canon::Str(s.value().clone()),
        Value::Integer(i) => Canon::Int(*i.value()),
        Value::Float(f) => Canon::Float(f.value().to_string()),
        Value::Boolean(b) => Canon::Bool(*b.value()),
        Value::Datetime(d) => Canon::Datetime(d.value().to_string()),
        Value::Array(a) => Canon::Array(a.iter().map(canon_value).collect()),
        Value::InlineTable(t) => {
            let mut kv: Vec<(String, Canon)> = t
                .iter()
                .map(|(k, v)| (k.to_owned(), canon_value(v)))
                .collect();
            kv.sort_by(|a, b| a.0.cmp(&b.0));
            Canon::Table(kv)
        }
    }
}

/// The content of an item; `None` for an empty slot.
pub fn canon_item(i: &Item) -> Option<Canon> {
    match i {
        Item::None => None,
        Item::Value(v) => Some(canon_value(v)),
        Item::Table(t) => {
            let mut kv: Vec<(String, Canon)> = t
                .iter()
                .filter_map(|(k, v)| canon_item(v).map(|c| (k.to_owned(), c)))
                .collect();
            kv.sort_by(|a, b| a.0.cmp(&b.0));
            Some(Canon::Table(kv))
        }
        Item::ArrayOfTables(a) => Some(Canon::Array(
            a.iter()
                .filter_map(|t| canon_item(&Item::Table(t.clone())))
                .collect(),
        )),
    }
}

/// A value's text without its surrounding whitespace and comments.
pub fn value_text(v: &Value) -> String {
    let mut v = v.clone();
    v.decor_mut().clear();
    v.to_string()
}

/// Parses one TOML value from its text.
pub fn parse_value(text: &str) -> Result<Value, String> {
    let doc: DocumentMut = format!("v = {text}\n")
        .parse()
        .map_err(|e| format!("bad recorded value: {e}"))?;
    doc.get("v")
        .and_then(Item::as_value)
        .cloned()
        .map(|mut v| {
            v.decor_mut().clear();
            v
        })
        .ok_or_else(|| "bad recorded value".to_owned())
}

/// How a record was made, which decides how it is undone.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// The key did not exist; undo removes it.
    Added,
    /// The key held a value of the user's that the state may keep (never a secret: SPEC D9);
    /// undo puts this text back in place.
    Replaced {
        /// The old value's text.
        before: String,
    },
    /// The key held a value of the user's that morsec does not keep (it may be a secret,
    /// security review S1 of L08); undo removes the key. `before` lives only in memory, for the
    /// dry undo of the plan that made it, and is never written to the state file.
    Redacted {
        /// The old value's text, this process only.
        before: Option<String>,
    },
}

/// One change: what morsec wrote at `path`.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Key path from the document root.
    pub path: Vec<String>,
    /// The text of the value morsec wrote.
    pub after: String,
    /// How it was made.
    pub kind: Kind,
}

/// All changes to one document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Edits {
    /// Changed keys, in the order they were made.
    pub records: Vec<Record>,
    /// Tables morsec created to hold its keys, outermost first; undo removes them when empty.
    pub created: Vec<Vec<String>>,
    /// The text before had no final newline; `toml_edit` ends an appended line with one, which
    /// [`undo_text`] takes off again.
    pub no_final_newline: bool,
}

impl Edits {
    /// Notes the text the edits start from (its final newline, see [`Edits::no_final_newline`]).
    pub fn starting_from(text: &str) -> Self {
        Self {
            no_final_newline: !text.is_empty() && !text.ends_with('\n'),
            ..Self::default()
        }
    }

    /// True when nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.created.is_empty()
    }

    /// The record for `path`.
    pub fn get(&self, path: &[String]) -> Option<&Record> {
        self.records.iter().find(|r| r.path == path)
    }

    /// Adds a record, replacing any record for the same path (one record per path).
    pub fn push(&mut self, r: Record) {
        if let Some(old) = self.records.iter_mut().find(|x| x.path == r.path) {
            *old = r;
        } else {
            self.records.push(r);
        }
    }
}

/// `["a", "b"]` as an owned path.
pub fn path(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| (*s).to_owned()).collect()
}

/// Dotted display of a path, quoting keys that need it.
pub fn show_path(p: &[String]) -> String {
    p.iter()
        .map(|k| {
            if !k.is_empty()
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                k.clone()
            } else {
                toml_edit::Key::new(k.as_str()).display_repr().into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The item at `p`.
pub fn get<'a>(doc: &'a DocumentMut, p: &[String]) -> Option<&'a Item> {
    let mut cur = doc.as_item();
    for k in p {
        cur = cur.as_table_like()?.get(k)?;
    }
    (!cur.is_none()).then_some(cur)
}

fn get_mut<'a>(doc: &'a mut DocumentMut, p: &[String]) -> Option<&'a mut Item> {
    let mut cur = doc.as_item_mut();
    for k in p {
        cur = cur.as_table_like_mut()?.get_mut(k)?;
    }
    (!cur.is_none()).then_some(cur)
}

/// The table-like item at `p`, creating missing tables (recorded in `e.created`). A
/// [`Table`] parent gets an implicit table (no header of its own); an inline parent gets an
/// inline table.
fn ensure_table<'a>(
    doc: &'a mut DocumentMut,
    p: &[String],
    e: &mut Edits,
) -> Result<&'a mut Item, String> {
    for n in 1..=p.len() {
        let (parent, key) = (&p[..n - 1], &p[n - 1]);
        let par = if parent.is_empty() {
            doc.as_item_mut()
        } else {
            get_mut(doc, parent).ok_or("internal: missing parent")?
        };
        let inline = par.is_inline_table();
        let t = par
            .as_table_like_mut()
            .ok_or_else(|| format!("{} is not a table", show_path(parent)))?;
        match t.get(key) {
            Some(i) if !i.is_none() => {
                if i.as_table_like().is_none() {
                    return Err(format!(
                        "{} is set to a {}, but morsec needs it to be a table",
                        show_path(&p[..n]),
                        i.type_name()
                    ));
                }
            }
            _ => {
                let item = if inline {
                    Item::Value(Value::InlineTable(InlineTable::new()))
                } else {
                    let mut nt = Table::new();
                    nt.set_implicit(true);
                    Item::Table(nt)
                };
                t.insert(key, item);
                e.created.push(p[..n].to_vec());
            }
        }
    }
    if p.is_empty() {
        Ok(doc.as_item_mut())
    } else {
        get_mut(doc, p).ok_or_else(|| "internal: missing table".to_owned())
    }
}

/// Converts `item` to a value for an inline parent.
fn to_value(item: Item) -> Option<Value> {
    match item {
        Item::Value(v) => Some(v),
        Item::Table(t) => Some(Value::InlineTable(t.into_inline_table())),
        _ => None,
    }
}

/// What [`set`] does when the key already holds a different value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    /// Refuse: `set` returns `Ok(Some(old text))` and changes nothing.
    Refuse,
    /// Replace and keep the old value's text in the state ([`Kind::Replaced`]).
    Keep,
    /// Replace without keeping the old value ([`Kind::Redacted`]).
    Drop,
}

/// Sets `p` to `item`, recording the change. A key that already holds an equal value is left
/// alone and not recorded (it is the user's, and stays after disconnect). Returns the old value's
/// text when `on` is [`OnConflict::Refuse`] and the key holds something else.
pub fn set(
    doc: &mut DocumentMut,
    p: &[String],
    item: Item,
    e: &mut Edits,
    on: OnConflict,
) -> Result<Option<String>, String> {
    let (key, parent) = p.split_last().ok_or("empty path")?;
    let after_canon = canon_item(&item);
    let after_text = match &item {
        Item::Value(v) => value_text(v),
        Item::Table(t) => value_text(&Value::InlineTable(t.clone().into_inline_table())),
        _ => return Err("internal: unsupported item".into()),
    };
    if let Some(cur) = get(doc, p) {
        if canon_item(cur) == after_canon {
            return Ok(None);
        }
        let before = match cur {
            Item::Value(v) => Some(value_text(v)),
            Item::Table(t) => Some(value_text(&Value::InlineTable(
                t.clone().into_inline_table(),
            ))),
            _ => None,
        };
        let kind = match on {
            OnConflict::Refuse => return Ok(Some(before.unwrap_or_default())),
            OnConflict::Keep => Kind::Replaced {
                before: before
                    .ok_or_else(|| format!("{} can't be replaced reversibly", show_path(p)))?,
            },
            OnConflict::Drop => Kind::Redacted { before },
        };
        // In place, keeping the key's position and the value's comments.
        let slot = get_mut(doc, p).ok_or("internal: missing key")?;
        match (slot, item) {
            (Item::Value(old), Item::Value(mut new)) => {
                *new.decor_mut() = old.decor().clone();
                *old = new;
            }
            (slot, new) => *slot = new,
        }
        e.push(Record {
            path: p.to_vec(),
            after: after_text,
            kind,
        });
        return Ok(None);
    }
    let par = ensure_table(doc, parent, e)?;
    let inline = par.is_inline_table();
    let t = par.as_table_like_mut().ok_or("internal: not a table")?;
    let item = if inline {
        Item::Value(to_value(item).ok_or("internal: not a value")?)
    } else {
        item
    };
    t.insert(key, item);
    e.push(Record {
        path: p.to_vec(),
        after: after_text,
        kind: Kind::Added,
    });
    Ok(None)
}

/// Undoes `e` on `doc`: each record whose key still holds what morsec wrote is removed or put
/// back; a key the user changed since is left alone, with a note. Tables morsec created are
/// removed when empty. `dry` uses the in-memory old value of a [`Kind::Redacted`] record (for
/// the reversibility check of a plan); a real undo removes such a key.
pub fn undo(doc: &mut DocumentMut, e: &Edits, dry: bool) -> Vec<String> {
    let mut notes = Vec::new();
    for r in e.records.iter().rev() {
        let Ok(after) = parse_value(&r.after) else {
            notes.push(format!(
                "{}: damaged record, left as is",
                show_path(&r.path)
            ));
            continue;
        };
        let ours = get(doc, &r.path).and_then(canon_item) == Some(canon_value(&after));
        if !ours {
            if get(doc, &r.path).is_some() {
                notes.push(format!(
                    "{} was changed after ms connect, so morsec left it as it is",
                    show_path(&r.path)
                ));
            }
            continue;
        }
        let restore = match &r.kind {
            // A record carried from an earlier connect: its key was already in the text the
            // plan started from, so a dry undo leaves it.
            Kind::Redacted { before: None } if dry => continue,
            Kind::Added => None,
            Kind::Replaced { before } => Some(before.clone()),
            Kind::Redacted { before } if dry => before.clone(),
            Kind::Redacted { .. } => {
                notes.push(format!(
                    "{} held a value of yours before ms connect; morsec didn't keep it, so the entry is removed",
                    show_path(&r.path)
                ));
                None
            }
        };
        match restore.map(|b| parse_value(&b)) {
            Some(Ok(v)) => {
                if let Some(slot) = get_mut(doc, &r.path) {
                    match slot {
                        Item::Value(old) => {
                            let mut v = v;
                            *v.decor_mut() = old.decor().clone();
                            *old = v;
                        }
                        other => {
                            // A whole table morsec replaced: put the old one back as a table.
                            *other = match v {
                                Value::InlineTable(t) => Item::Table(t.into_table()),
                                v => Item::Value(v),
                            };
                        }
                    }
                }
            }
            Some(Err(m)) => notes.push(format!("{}: {m}", show_path(&r.path))),
            None => remove(doc, &r.path),
        }
    }
    for c in e.created.iter().rev() {
        if get(doc, c)
            .and_then(Item::as_table_like)
            .is_some_and(|t| t.is_empty())
        {
            remove(doc, c);
        }
    }
    notes
}

/// Parses `text`, undoes `e` (see [`undo`]) and renders the result.
pub fn undo_text(text: &str, e: &Edits, dry: bool) -> Result<(String, Vec<String>), String> {
    let mut d: DocumentMut = text.parse().map_err(|err| format!("{err}"))?;
    let notes = undo(&mut d, e, dry);
    let mut out = d.to_string();
    if e.no_final_newline && out.ends_with('\n') {
        out.pop();
        if out.ends_with('\r') {
            out.pop();
        }
    }
    Ok((out, notes))
}

fn remove(doc: &mut DocumentMut, p: &[String]) {
    let Some((key, parent)) = p.split_last() else {
        return;
    };
    let par = if parent.is_empty() {
        Some(doc.as_item_mut())
    } else {
        get_mut(doc, parent)
    };
    if let Some(t) = par.and_then(Item::as_table_like_mut) {
        t.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(t: &str) -> DocumentMut {
        t.parse().unwrap()
    }

    fn s(v: &str) -> Item {
        Item::Value(Value::from(v))
    }

    // protects=SPEC D4: set then undo gives back the exact bytes for tables in every TOML
    // shape (header tables, dotted keys, inline tables, no trailing newline, comments);
    // fails_when=any byte differs after undo
    #[test]
    fn set_then_undo_is_byte_exact() {
        for t in [
            "",
            "# just a comment\n",
            "model = \"o3\"",
            "model = \"o3\"\n\n[shell_environment_policy]\ninherit = \"core\" # keep\n",
            "shell_environment_policy.set.FOO = 'bar'\n",
            "[shell_environment_policy]\nset = { FOO = \"bar\" }\n",
            "[mcp_servers.gh]\ncommand = \"npx\"\nargs = [\"-y\", \"gh\"]\n\n[mcp_servers.gh.env]\nX = \"1\"\n",
            "[profiles.a]\nmodel = \"x\"   # c\n\n\n[[skills]]\nname = \"a\"\n\t\n[[skills]]\nname = \"b\"",
        ] {
            let mut d = doc(t);
            let mut e = Edits::starting_from(t);
            for (p, v) in [
                (
                    path(&["shell_environment_policy", "set", "MORSEC_CONNECTED"]),
                    "codex",
                ),
                (path(&["mcp_servers", "gh", "env", "TOKEN"]), "ms://gh/x"),
                (path(&["a", "b", "c"]), "z"),
            ] {
                set(&mut d, &p, s(v), &mut e, OnConflict::Refuse).unwrap();
            }
            let written = d.to_string();
            assert_ne!(written, t);
            let (back, notes) = undo_text(&written, &e, false).unwrap();
            assert!(notes.is_empty());
            assert_eq!(back, t, "from {written:?}");
        }
    }

    // protects=one record per path: setting the same key twice keeps one record (L08 F2);
    // an equal value already there is not recorded, so disconnect keeps it
    #[test]
    fn one_record_per_path_and_equal_values_untouched() {
        let mut d = doc("[x]\na = \"same\"\n");
        let mut e = Edits::default();
        set(
            &mut d,
            &path(&["x", "a"]),
            s("same"),
            &mut e,
            OnConflict::Refuse,
        )
        .unwrap();
        assert!(e.records.is_empty());
        set(
            &mut d,
            &path(&["x", "b"]),
            s("1"),
            &mut e,
            OnConflict::Refuse,
        )
        .unwrap();
        set(&mut d, &path(&["x", "b"]), s("2"), &mut e, OnConflict::Drop).unwrap();
        assert_eq!(e.records.len(), 1);
    }

    // protects=a conflicting value is refused unless allowed; Keep puts it back in place with
    // its comment, Drop removes it (never stored); a key the user changed since is left alone
    #[test]
    fn conflicts_and_user_changes() {
        let t = "[x]\na = 'old' # c\nz = 1\n";
        let mut d = doc(t);
        let mut e = Edits::default();
        assert_eq!(
            set(
                &mut d,
                &path(&["x", "a"]),
                s("new"),
                &mut e,
                OnConflict::Refuse
            )
            .unwrap(),
            Some("'old'".into())
        );
        assert_eq!(d.to_string(), t);
        set(
            &mut d,
            &path(&["x", "a"]),
            s("new"),
            &mut e,
            OnConflict::Keep,
        )
        .unwrap();
        assert_eq!(d.to_string(), "[x]\na = \"new\" # c\nz = 1\n");
        let mut back = doc(&d.to_string());
        undo(&mut back, &e, false);
        assert_eq!(back.to_string(), t);

        let mut d = doc(t);
        let mut e = Edits::default();
        set(
            &mut d,
            &path(&["x", "a"]),
            s("new"),
            &mut e,
            OnConflict::Drop,
        )
        .unwrap();
        let mut dry = doc(&d.to_string());
        undo(&mut dry, &e, true);
        assert_eq!(dry.to_string(), t);
        let mut real = doc(&d.to_string());
        assert_eq!(undo(&mut real, &e, false).len(), 1);
        assert_eq!(real.to_string(), "[x]\nz = 1\n");

        let mut d = doc("");
        let mut e = Edits::default();
        set(
            &mut d,
            &path(&["x", "a"]),
            s("ours"),
            &mut e,
            OnConflict::Refuse,
        )
        .unwrap();
        let edited = d.to_string().replace("ours", "theirs");
        let mut back = doc(&edited);
        assert_eq!(undo(&mut back, &e, false).len(), 1);
        assert_eq!(back.to_string(), edited);
    }

    #[test]
    fn non_table_parent_is_an_error() {
        let mut d = doc("shell_environment_policy = \"x\"\n");
        let mut e = Edits::default();
        let r = set(
            &mut d,
            &path(&["shell_environment_policy", "set", "A"]),
            s("b"),
            &mut e,
            OnConflict::Refuse,
        );
        assert!(r.unwrap_err().contains("needs it to be a table"));
    }

    #[test]
    fn canon_ignores_layout() {
        let a = doc("[t]\nx = 'a'\ny = [1, 2]\n");
        let b = doc("t = { y = [ 1,2 ], x = \"a\" }\n");
        assert_eq!(
            canon_item(a.get("t").unwrap()),
            canon_item(b.get("t").unwrap())
        );
    }
}

/// A changed `config.toml` line for display: table headers and keys as they are, and a value
/// only when every string in it is one `safe` says morsec wrote. Anything else becomes `"…"`, so
/// a user's own value (a token in an MCP server's env) never reaches the terminal or an agent's
/// transcript. Lines that are not a whole `key = value` (a continuation of a multi-line value,
/// a comment) are shown as `…`.
pub fn redact_line(line: &str, safe: &dyn Fn(&str) -> bool) -> String {
    let t = line.trim();
    if t.is_empty() {
        return line.to_owned();
    }
    if t.starts_with('[') {
        // A header holds only keys; check it parses as one.
        let ok = format!("{t}\n").parse::<DocumentMut>().is_ok();
        return if ok {
            line.to_owned()
        } else {
            "…".to_owned()
        };
    }
    let Ok(d) = format!("{t}\n").parse::<DocumentMut>() else {
        return "…".to_owned();
    };
    let indent = &line[..line.len() - line.trim_start().len()];
    let mut out = Vec::new();
    for (k, item) in d.iter() {
        let mut keys = vec![k.to_owned()];
        let mut cur = item;
        // A dotted key parses as nested tables with one entry each.
        while let Some(tl) = cur.as_table().filter(|t| t.is_dotted() || t.is_implicit()) {
            let Some((k2, i2)) = tl.iter().next() else {
                break;
            };
            keys.push(k2.to_owned());
            cur = i2;
        }
        let shown = cur
            .as_value()
            .map(|v| all_strings_safe(&canon_value(v), safe).then(|| value_text(v)))
            .unwrap_or(None);
        out.push(format!(
            "{} = {}",
            show_path(&keys),
            shown.unwrap_or_else(|| "\"…\"".to_owned())
        ));
    }
    if out.len() != 1 {
        return "…".to_owned();
    }
    format!("{indent}{}", out.remove(0))
}

fn all_strings_safe(c: &Canon, safe: &dyn Fn(&str) -> bool) -> bool {
    match c {
        Canon::Str(s) => safe(s),
        Canon::Array(a) => a.iter().all(|x| all_strings_safe(x, safe)),
        Canon::Table(kv) => kv.iter().all(|(_, x)| all_strings_safe(x, safe)),
        _ => true,
    }
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    // protects=the plan preview never prints a user's own value from config.toml (a token in
    // an MCP server's env, a bearer token); fails_when=a value morsec didn't write is printed
    #[test]
    fn preview_hides_user_values() {
        let safe = |s: &str| s == "codex" || s.starts_with("ms://");
        assert_eq!(
            redact_line("MORSEC_CONNECTED = \"codex\"", &safe),
            "MORSEC_CONNECTED = \"codex\""
        );
        assert_eq!(
            redact_line("  GH = 'ghp_SECRET' # c", &safe),
            "  GH = \"…\""
        );
        assert_eq!(
            redact_line("[mcp_servers.gh.env]", &safe),
            "[mcp_servers.gh.env]"
        );
        assert_eq!(
            redact_line("env = { TOKEN = \"ghp_SECRET\", X = \"ms://a/b\" }", &safe),
            "env = \"…\""
        );
        assert_eq!(
            redact_line("mcp_servers.gh.env.T = \"ms://gh/t\"", &safe),
            "mcp_servers.gh.env.T = \"ms://gh/t\""
        );
        assert_eq!(redact_line("port = 4101", &safe), "port = 4101");
        assert_eq!(redact_line("  \"ghp_SECRET\",", &safe), "…");
        assert_eq!(redact_line("x = \"\"\"ghp_SECRET", &safe), "…");
        assert_eq!(redact_line("# token ghp_SECRET", &safe), "…");
    }
}
