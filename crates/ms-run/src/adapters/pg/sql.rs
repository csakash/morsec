//! The statement check for effect previews (SPEC D5).
//!
//! A preview counts the rows a statement would change without running it: `SELECT count(*) FROM
//! <table> WHERE <its WHERE clause>` in a read-only transaction. Only statements this strict
//! check fully understands are previewed: one `UPDATE` or `DELETE`, written with a small
//! alphabet, reading no other relation. Anything else is "unknown". The check is a lexer for a subset of SQL that refuses
//! every construct where Postgres' lexer could read the text differently (comments, dollar
//! quotes, prefixed strings, backslashes, psql variables, non-ASCII outside quotes), so the
//! function and operator names it collects are all the ones Postgres will see.

/// Why a statement is not previewed.
pub type Why = &'static str;

/// One token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Unquoted identifier or keyword, lowercased.
    Word(String),
    /// `"Quoted"` identifier, as written (with its quotes).
    Quoted(String),
    /// `'string'` or a number.
    Literal,
    /// Operator characters.
    Op(String),
    /// `(`, `)`, `,`, `.`, `[`, `]`, `;`.
    Punct(char),
    /// `::`.
    Cast,
}

/// A statement that can be previewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simple {
    /// The target table as written (`orders`, `public."Order"`), for `to_regclass`.
    pub table: String,
    /// `UPDATE ONLY` / `DELETE FROM ONLY`.
    pub only: bool,
    /// The text of the `WHERE` clause, when there is one (else every row matches).
    pub filter: Option<String>,
    /// Function names called in the filter (lowercased unless quoted, quotes removed).
    pub functions: Vec<String>,
    /// Operators used in the filter.
    pub operators: Vec<String>,
    /// Type names cast to in the filter (`::t`, `t 'literal'`); each must be a `pg_catalog`
    /// type for a preview.
    pub casts: Vec<String>,
}

const OP_CHARS: &str = "+-*/<>=~!@#%^&|";

/// Keywords a literal may follow without being a typed literal (`type 'text'`).
const LITERAL_KEYWORDS: &[&str] = &[
    "zone",
    "precision",
    "varying",
    "case",
    "and",
    "or",
    "not",
    "is",
    "like",
    "ilike",
    "similar",
    "to",
    "escape",
    "between",
    "when",
    "then",
    "else",
    "in",
    "where",
    "set",
    "distinct",
    "from",
    "symmetric",
    "collate",
];

/// Words that are followed by `(` without being function calls.
const NOT_FUNCTIONS: &[&str] = &[
    "and", "or", "not", "in", "exists", "any", "all", "some", "where", "set", "values", "select",
    "from", "using", "on", "as", "is", "between", "like", "ilike", "similar", "when", "then",
    "else", "case", "row", "array", "only", "join", "lateral", "by", "having", "limit", "offset",
];

/// Words that make a statement not "simple".
const REFUSED_WORDS: &[(&str, Why)] = &[
    ("returning", "the statement already has RETURNING"),
    ("current", "WHERE CURRENT OF needs a cursor"),
    ("with", "the statement has a WITH clause"),
    ("into", "the statement isn't a simple UPDATE or DELETE"),
    // Another relation (a view, a subquery) could call functions the check can't see.
    (
        "select",
        "the statement reads another relation (a subquery)",
    ),
    ("table", "the statement reads another relation (TABLE)"),
    ("using", "the statement reads another relation (USING)"),
    ("join", "the statement reads another relation (JOIN)"),
];

/// Tokens and the byte offset where each starts.
fn lex(sql: &str) -> Result<(Vec<Tok>, Vec<usize>), Why> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut starts = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if starts.len() < out.len() {
            starts.push(starts.last().copied().unwrap_or(0));
        }
        let tok_start = i;
        let before = out.len();
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'\'' => {
                if i > 0
                    && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_' || b[i - 1] == b'&')
                {
                    // E'…', U&'…', B'…', X'…', N'…' and the like.
                    return Err("the statement has a prefixed string literal");
                }
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err("the statement has an unterminated string"),
                        Some(b'\'') if b.get(i + 1) == Some(&b'\'') => i += 2,
                        Some(b'\'') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => return Err("the statement has a backslash"),
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Literal);
            }
            b'"' => {
                let start = i;
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err("the statement has an unterminated quoted name"),
                        Some(b'"') if b.get(i + 1) == Some(&b'"') => i += 2,
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => return Err("the statement has a backslash"),
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Quoted(sql[start..i].to_owned()));
            }
            b'0'..=b'9' => {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_')
                {
                    i += 1;
                }
                out.push(Tok::Literal);
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                if b.get(i) == Some(&b'$') {
                    return Err("the statement has a $ in a name");
                }
                out.push(Tok::Word(sql[start..i].to_ascii_lowercase()));
            }
            b'(' | b')' | b',' | b'.' | b'[' | b']' | b';' => {
                out.push(Tok::Punct(c as char));
                i += 1;
            }
            b':' => {
                if b.get(i + 1) == Some(&b':') {
                    out.push(Tok::Cast);
                    i += 2;
                } else {
                    return Err("the statement has a ':' (a psql variable or array slice)");
                }
            }
            _ if OP_CHARS.as_bytes().contains(&c) => {
                let start = i;
                while i < b.len() && OP_CHARS.as_bytes().contains(&b[i]) {
                    i += 1;
                }
                let op = &sql[start..i];
                if op.contains("--") || op.contains("/*") {
                    return Err("the statement has a comment");
                }
                out.push(Tok::Op(op.to_owned()));
            }
            b'$' => return Err("the statement has a $ (a parameter or dollar quote)"),
            b'\\' => return Err("the statement has a backslash"),
            _ => return Err("the statement has a character the preview doesn't handle"),
        }
        if out.len() > before {
            starts.push(tok_start);
        }
    }
    Ok((out, starts))
}

/// `name`, `schema.name` or `db.schema.name` starting at `i`: its text and the next index.
fn qualified(toks: &[Tok], mut i: usize, sql_parts: &mut String) -> Option<usize> {
    loop {
        match toks.get(i)? {
            Tok::Word(w) => sql_parts.push_str(w),
            Tok::Quoted(q) => sql_parts.push_str(q),
            _ => return None,
        }
        i += 1;
        if toks.get(i) == Some(&Tok::Punct('.')) {
            sql_parts.push('.');
            i += 1;
        } else {
            return Some(i);
        }
    }
}

/// Checks `sql` and returns what the preview needs, or why it can't be previewed.
pub fn simple(sql: &str) -> Result<Simple, Why> {
    if sql.len() > 64 * 1024 {
        return Err("the statement is too long to preview");
    }
    let (mut toks, starts) = lex(sql)?;
    if toks.last() == Some(&Tok::Punct(';')) {
        toks.pop();
    }
    if toks.contains(&Tok::Punct(';')) {
        return Err("the command has more than one statement");
    }
    for (w, why) in REFUSED_WORDS {
        if toks.contains(&Tok::Word((*w).to_owned())) {
            return Err(why);
        }
    }
    let mut table = String::new();
    let mut i = match toks.first() {
        Some(Tok::Word(w)) if w == "update" => 1,
        Some(Tok::Word(w)) if w == "delete" => {
            if toks.get(1) != Some(&Tok::Word("from".into())) {
                return Err("the statement isn't a simple UPDATE or DELETE");
            }
            2
        }
        _ => return Err("only a single UPDATE or DELETE is previewed"),
    };
    let only = toks.get(i) == Some(&Tok::Word("only".into()));
    if only {
        i += 1;
    }
    let Some(after_table) = qualified(&toks, i, &mut table) else {
        return Err("the statement's table isn't a plain name");
    };
    // `DELETE FROM t` is the only FROM; any other reads another relation.
    let from_at = usize::from(matches!(toks.first(), Some(Tok::Word(w)) if w == "delete"));
    for (n, t) in toks.iter().enumerate() {
        if *t == Tok::Word("from".into()) && n != from_at {
            return Err("the statement reads another relation (FROM)");
        }
    }
    // A dotted name after the table is a qualified column or attribute notation (`t.f`, which
    // calls f(t)); the check can't tell, so it doesn't preview.
    if toks[after_table..].contains(&Tok::Punct('.')) {
        return Err("the statement uses a dotted name (a qualified column or attribute notation)");
    }
    // The WHERE clause at paren depth 0: the only part the preview evaluates.
    let mut depth = 0i32;
    let mut where_at = None;
    for (n, t) in toks.iter().enumerate().skip(after_table) {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth -= 1,
            Tok::Word(w) if w == "where" && depth == 0 => {
                where_at = Some(n);
                break;
            }
            _ => {}
        }
    }
    let (filter, ftoks) = match where_at {
        Some(n) => {
            let Some(&from) = starts.get(n + 1) else {
                return Err("the statement's WHERE clause is empty");
            };
            let end = if toks.len() < starts.len() {
                starts[toks.len()]
            } else {
                sql.len()
            };
            (Some(sql[from..end].trim().to_owned()), &toks[n + 1..])
        }
        None => (None, &toks[toks.len()..]),
    };
    let mut casts = Vec::new();
    for w in ftoks.windows(2) {
        // `type 'literal'` is a cast too (`date '2024-01-01'`, `mydomain '1'`).
        if let (Tok::Word(t), Tok::Literal) = (&w[0], &w[1])
            && !LITERAL_KEYWORDS.contains(&t.as_str())
        {
            casts.push(t.clone());
        }
        if let (Tok::Quoted(q), Tok::Literal) = (&w[0], &w[1]) {
            casts.push(q.clone());
        }
        if w[0] == Tok::Cast {
            match &w[1] {
                Tok::Word(t) => casts.push(t.clone()),
                Tok::Quoted(q) => casts.push(q.clone()),
                _ => return Err("the statement has a cast the preview doesn't handle"),
            }
        }
    }
    casts.sort();
    casts.dedup();
    if casts.iter().any(|c| c.contains(',')) {
        return Err("a type name has a comma");
    }
    let mut functions = Vec::new();
    let mut operators = Vec::new();
    for (n, t) in ftoks.iter().enumerate() {
        match t {
            Tok::Op(o) => operators.push(o.clone()),
            Tok::Word(w) | Tok::Quoted(w) if ftoks.get(n + 1) == Some(&Tok::Punct('(')) => {
                if let Tok::Word(w) = t
                    && NOT_FUNCTIONS.contains(&w.as_str())
                {
                    continue;
                }
                let name = match t {
                    Tok::Quoted(q) => q[1..q.len() - 1].replace("\"\"", "\""),
                    _ => w.clone(),
                };
                if name.contains(',') {
                    return Err("a function name has a comma");
                }
                functions.push(name);
            }
            _ => {}
        }
    }
    // Keyword forms that call operators implicitly.
    for t in ftoks {
        if let Tok::Word(w) = t {
            let implied: &[&str] = match w.as_str() {
                "in" | "case" | "nullif" | "distinct" => &["="],
                "between" => &[">=", "<="],
                "like" => &["~~", "!~~"],
                "ilike" => &["~~*", "!~~*"],
                "similar" => &["~", "!~"],
                "greatest" | "least" => &["<", ">"],
                _ => &[],
            };
            operators.extend(implied.iter().map(|s| (*s).to_owned()));
        }
    }
    functions.sort();
    functions.dedup();
    operators.sort();
    operators.dedup();
    Ok(Simple {
        table,
        only,
        filter,
        functions,
        operators,
        casts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D5: only a single plain UPDATE/DELETE is previewed and its functions and
    // operators are all collected; fails_when=a second statement, a comment, a dollar quote, a
    // prefixed string or a psql variable gets through, or a function call is missed;
    // no_claim=the server-side volatility check (live tests)
    #[test]
    fn only_simple_dml() {
        let s = simple("UPDATE orders SET status = 'paid' WHERE id IN (1, 2, 3);").unwrap();
        assert_eq!(s.table, "orders");
        assert_eq!(s.filter.as_deref(), Some("id IN (1, 2, 3)"));
        assert!(s.functions.is_empty() && !s.only);
        // IN compares with `=`, so `=` is checked even though it isn't written.
        assert_eq!(s.operators, ["="]);
        let s = simple("delete from t where a between 1 and 2 or b ilike 'x'").unwrap();
        assert_eq!(s.operators, ["!~~*", "<=", ">=", "~~*"]);
        let s = simple("delete from only public.\"Order\" where lower(note) like 'x%' and n >= 2")
            .unwrap();
        assert_eq!(s.table, "public.\"Order\"");
        assert!(s.only);
        assert_eq!(s.functions, ["lower"]);
        assert_eq!(s.operators, ["!~~", ">=", "~~"]);
        // The SET list isn't evaluated, so its functions and operators don't matter.
        let s = simple("update t set a = random() + nextval('s'), b = default").unwrap();
        assert!(s.filter.is_none() && s.functions.is_empty() && s.operators.is_empty());
        let s = simple("update t set a = 1 where created at time zone 'UTC' < now() ;").unwrap();
        assert_eq!(
            s.filter.as_deref(),
            Some("created at time zone 'UTC' < now()")
        );
        assert!(s.casts.is_empty());
        assert_eq!(s.functions, ["now"]);
        let s = simple("update t set c = 'it''s; fine' where a = \"My Fn\"(b)::int").unwrap();
        assert_eq!(s.functions, ["My Fn"]);
        assert_eq!(s.casts, ["int"]);
        let s = simple(
            "update t set a = 1 where a = mydom '1' or b = date '2024-01-01' or c like 'x%'",
        )
        .unwrap();
        assert_eq!(s.casts, ["date", "mydom"]);

        for bad in [
            "update t set a = 1; commit",
            "update t set a = 1; delete from t",
            "update t set a = 1 -- x",
            "update t set a = 1 /* x */",
            "update t set a = $$x$$",
            "update t set a = E'\\x'",
            "update t set a = e'x'",
            "update t set a = 'x\\'",
            "update t set a = :v",
            "update t set a = 1 returning *",
            "with x as (select 1) update t set a = 1",
            "insert into t values (1)",
            "select 1",
            "delete t",
            "update t set a = 1 where",
            "update t set a = é",
            "update t set a = U&'d!0061t' uescape '!'",
            "update t set a = 1 where current of c",
            "update t set a = 'unterminated",
            "update t set a = 1 where id in (select id from v)",
            "update t set a = 1 where id in (table v)",
            "update t set a = 1 from u where u.id = t.id",
            "delete from t using u where u.id = t.id",
            "update t set a = 1 where t.f is null",
            "update t set a = 1 where t.id = 1",
        ] {
            assert!(simple(bad).is_err(), "{bad}");
        }
    }
}
