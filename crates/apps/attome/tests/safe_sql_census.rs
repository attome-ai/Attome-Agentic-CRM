//! Z2-T11: the safe-SQL census. Every `format!(` in `crates/**/src` whose
//! first string literal starts with an SQL statement (`SELECT`, `INSERT`,
//! `UPDATE`, `DELETE`, `WITH`, `CREATE`, `ALTER`, `DROP`) is a hit. A hit is
//! safe when every placeholder's argument is a `quote_ident(...)` call, an
//! upper-case constant or a number literal; any other argument is a
//! violation, printed as `path:line` with its arguments.
//!
//! Today's violations are baselined per file in `safe_sql_census.json`
//! (`{path: count}`). The count may only fall: a new string-built statement
//! anywhere fails, and so does a baseline entry above its file's real count
//! (lower it). Values are always bound (`$1`); what reaches `format!` should
//! be an identifier from validated metadata or a fragment built from
//! constants — move such a fragment into a `quote_ident` call or a constant,
//! or bind the value, rather than raising the baseline.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a failed read should panic with its message"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const KEYWORDS: [&str; 8] = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the workspace root")
        .to_path_buf()
}

fn baseline_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("safe_sql_census.json")
}

/// Every `.rs` file under a `src` directory of `crates/`.
fn sources(dir: &Path, in_src: bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name == "target" || name == "node_modules" || name.starts_with('.') {
                continue;
            }
            sources(&path, in_src || name == "src", out);
        } else if in_src && name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// A Rust string literal starting at `s[i]`: its content (escapes kept as
/// written, line continuations removed) and the index after it.
fn string_at(s: &[u8], i: usize) -> Option<(String, usize)> {
    if s.get(i) == Some(&b'r') {
        let mut j = i + 1;
        let mut hashes = 0;
        while s.get(j) == Some(&b'#') {
            hashes += 1;
            j += 1;
        }
        if s.get(j) != Some(&b'"') {
            return None;
        }
        let start = j + 1;
        let mut k = start;
        while k < s.len() {
            if s[k] == b'"'
                && s[k + 1..]
                    .iter()
                    .take(hashes)
                    .filter(|&&b| b == b'#')
                    .count()
                    == hashes
            {
                let content = String::from_utf8_lossy(&s[start..k]).into_owned();
                return Some((content, k + 1 + hashes));
            }
            k += 1;
        }
        return None;
    }
    if s.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    let mut out = Vec::new();
    while j < s.len() {
        match s[j] {
            b'\\' if s.get(j + 1) == Some(&b'\n') => {
                j += 2;
                while j < s.len() && matches!(s[j], b' ' | b'\t' | b'\r' | b'\n') {
                    j += 1;
                }
            }
            b'\\' if s.get(j + 1) == Some(&b'\r') && s.get(j + 2) == Some(&b'\n') => {
                j += 3;
                while j < s.len() && matches!(s[j], b' ' | b'\t' | b'\r' | b'\n') {
                    j += 1;
                }
            }
            b'\\' => {
                out.extend_from_slice(&s[j..(j + 2).min(s.len())]);
                j += 2;
            }
            b'"' => return Some((String::from_utf8_lossy(&out).into_owned(), j + 1)),
            b => {
                out.push(b);
                j += 1;
            }
        }
    }
    None
}

/// The comma-separated arguments after the format string, up to the
/// closing parenthesis.
fn split_args(s: &[u8], mut j: usize) -> Vec<String> {
    let mut depth = 0usize;
    let mut args = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    while j < s.len() {
        let c = s[j];
        let after_ident = current
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if (c == b'"' || (c == b'r' && matches!(s.get(j + 1), Some(b'"' | b'#')) && !after_ident))
            && let Some((_, end)) = string_at(s, j)
        {
            current.extend_from_slice(&s[j..end]);
            j = end;
            continue;
        }
        if c == b'\'' {
            let char_len = if s.get(j + 1) == Some(&b'\\') {
                s.get(j + 3..)
                    .and_then(|rest| rest.iter().position(|&b| b == b'\''))
                    .map(|p| p + 4)
            } else if s.get(j + 2) == Some(&b'\'') {
                Some(3)
            } else {
                None
            };
            if let Some(len) = char_len {
                current.extend_from_slice(&s[j..j + len]);
                j += len;
                continue;
            }
        }
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    args.push(String::from_utf8_lossy(&current).trim().to_owned());
                    return args.into_iter().filter(|a| !a.is_empty()).collect();
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                args.push(String::from_utf8_lossy(&current).trim().to_owned());
                current.clear();
                j += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        j += 1;
    }
    args.into_iter().filter(|a| !a.is_empty()).collect()
}

/// The placeholder names of a format string, in order (`""` for `{}`).
fn placeholders(format: &str) -> Vec<String> {
    let bytes = format.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{{") || bytes[i..].starts_with(b"}}") {
            i += 2;
            continue;
        }
        if bytes[i] == b'{'
            && let Some(close) = bytes[i + 1..].iter().position(|&b| b == b'}')
        {
            let inner = &format[i + 1..i + 1 + close];
            if !inner.contains('{') {
                let name = inner.split(':').next().unwrap_or("").trim();
                names.push(name.to_owned());
                i += close + 2;
                continue;
            }
        }
        i += 1;
    }
    names
}

fn is_ident(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_const(text: &str) -> bool {
    let mut segments: Vec<&str> = text.split("::").collect();
    let last = segments.pop().unwrap_or("");
    segments.iter().all(|s| is_ident(s))
        && last.starts_with(|c: char| c.is_ascii_uppercase())
        && last
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// A placeholder argument the census accepts.
fn safe_argument(expr: &str) -> bool {
    let expr = expr.trim().trim_start_matches('&').trim();
    if expr.bytes().all(|b| b.is_ascii_digit()) && !expr.is_empty() {
        return true;
    }
    if let Some(open) = expr.find('(')
        && expr.ends_with(')')
    {
        let path = &expr[..open];
        let segments: Vec<&str> = path.split("::").collect();
        return segments.last() == Some(&"quote_ident") && segments.iter().all(|s| is_ident(s));
    }
    is_const(expr)
}

/// Whether a format string starts with an SQL statement, after any leading
/// `/* */` or `--` comments.
fn starts_with_statement(format: &str) -> bool {
    let mut body = format.trim_start();
    loop {
        if let Some(rest) = body.strip_prefix("/*")
            && let Some(end) = rest.find("*/")
        {
            body = rest[end + 2..].trim_start();
            continue;
        }
        if let Some(rest) = body.strip_prefix("--")
            && let Some(end) = rest.find('\n')
        {
            body = rest[end + 1..].trim_start();
            continue;
        }
        break;
    }
    KEYWORDS.iter().any(|kw| {
        body.strip_prefix(kw)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_whitespace() || c == '\\')
    })
}

/// Every violation in one source file: `(line, arguments, statement start)`.
fn violations_in(text: &str) -> Vec<(usize, Vec<String>, String)> {
    let s = text.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("format!(") {
        let start = from + at;
        from = start + "format!(".len();
        let preceded_by_ident = start > 0 && {
            let b = s[start - 1];
            b.is_ascii_alphanumeric() || b == b'_'
        };
        if preceded_by_ident {
            continue;
        }
        let mut i = from;
        while i < s.len() && s[i].is_ascii_whitespace() {
            i += 1;
        }
        let Some((format, end)) = string_at(s, i) else {
            continue;
        };
        if !starts_with_statement(&format) {
            continue;
        }
        let mut named = BTreeMap::new();
        let mut positional = Vec::new();
        for arg in split_args(s, end) {
            match arg.split_once('=') {
                Some((name, value)) if is_ident(name.trim()) && !value.starts_with('=') => {
                    named.insert(name.trim().to_owned(), value.trim().to_owned());
                }
                _ => positional.push(arg),
            }
        }
        let mut next = 0;
        let mut bad = Vec::new();
        for name in placeholders(&format) {
            let expr = if name.is_empty() {
                next += 1;
                positional.get(next - 1).cloned().unwrap_or_default()
            } else if let Ok(index) = name.parse::<usize>() {
                positional.get(index).cloned().unwrap_or_default()
            } else if let Some(value) = named.get(&name) {
                value.clone()
            } else {
                name.clone()
            };
            if !safe_argument(&expr) {
                bad.push(expr);
            }
        }
        if !bad.is_empty() {
            let line = text[..start].matches('\n').count() + 1;
            let head: String = format.trim().chars().take(70).collect();
            found.push((line, bad, head));
        }
    }
    found
}

fn census() -> BTreeMap<String, Vec<(usize, Vec<String>, String)>> {
    let root = workspace_root();
    let mut files = Vec::new();
    sources(&root.join("crates"), false, &mut files);
    let mut result = BTreeMap::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a source file");
        let found = violations_in(&text);
        if !found.is_empty() {
            let rel = path
                .strip_prefix(&root)
                .expect("under the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            result.insert(rel, found);
        }
    }
    result
}

fn baseline() -> BTreeMap<String, usize> {
    let text = std::fs::read_to_string(baseline_path()).expect("safe_sql_census.json");
    serde_json::from_str(&text).expect("safe_sql_census.json is a {path: count} map")
}

#[test]
fn safe_sql_census() {
    let found = census();
    let allowed = baseline();
    let mut problems = Vec::new();
    for (path, list) in &found {
        let limit = allowed.get(path).copied().unwrap_or(0);
        if list.len() > limit {
            problems.push(format!(
                "{path}: {} string-built statements, baseline {limit}:",
                list.len()
            ));
            for (line, bad, head) in list {
                problems.push(format!("  {path}:{line} {head:?} interpolates {bad:?}"));
            }
        }
    }
    for (path, &limit) in &allowed {
        let count = found.get(path).map_or(0, Vec::len);
        if count < limit {
            problems.push(format!(
                "{path}: baseline {limit} but only {count} remain; lower it in safe_sql_census.json"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn census_rules_flag_what_they_describe() {
    let flagged = |src: &str| violations_in(src).len();
    assert_eq!(
        flagged(r#"let q = format!("SELECT * FROM t WHERE x = {}", value);"#),
        1
    );
    assert_eq!(flagged(r#"let q = format!("SELECT {cols} FROM t");"#), 1);
    assert_eq!(
        flagged(r#"let q = format!("SELECT a FROM {} WHERE id = $1", quote_ident(table));"#),
        0
    );
    assert_eq!(
        flagged(r#"let q = format!("SELECT {COLUMNS} FROM t LIMIT {}", 10);"#),
        0
    );
    assert_eq!(
        flagged(r#"let q = format!("DELETE FROM {t}", t = attome_core::quote_ident(name));"#),
        0
    );
    assert_eq!(
        flagged(r#"let m = format!("create {}: {e}", dir.display());"#),
        0
    );
    assert_eq!(flagged(r#"let m = format!("Selected {} rows", n);"#), 0);
}
