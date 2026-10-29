//! AB8-T3: add first, remove later. A migration above [`BASELINE`] may only
//! add structure; dropping or renaming a column or table, changing a
//! column's type or making a column NOT NULL without a default belongs in the
//! held-back contract set (`crates/apps/attome/contract/`, applied by
//! `upgrade contract`), so a rollback to the previous release still finds
//! every column it reads.

use std::path::Path;

/// The highest migration ordinal when the rule was introduced. Every
/// migration above it is checked.
const BASELINE: u32 = 88;

/// Committed migrations above the baseline that remove structure, each
/// reviewed and recorded in `crates/apps/attome/contract/README.md`. A
/// committed migration never changes (boot checks its checksum), so it
/// cannot move to the contract set; a new one never belongs here.
const REVIEWED: &[(&str, &str)] = &[
    (
        "0173_marketing_deliverability_reshape.sql",
        "drops only tables still in 0084's early shape, which no release's code reads or writes",
    ),
    (
        "0320_change_event_daily_partitions.sql",
        "swaps entity_change_event for its day-partitioned copy: every row is copied (the late ones under the lock) before the old table is dropped and the copy renamed",
    ),
];

/// One destructive statement: its 1-based line and what it does.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    line: usize,
    what: &'static str,
}

/// Removes `--` comments, keeping line breaks so line numbers stay right.
fn strip_comments(sql: &str) -> String {
    sql.lines()
        .map(|line| match line.find("--") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The destructive statements in `sql`.
fn detect(sql: &str) -> Vec<Finding> {
    let clean = strip_comments(sql);
    let mut findings = Vec::new();
    let mut offset = 0usize;
    for statement in clean.split(';') {
        // The line the statement's first word is on.
        let leading = &statement[..statement.len() - statement.trim_start().len()];
        let line = clean[..offset].matches('\n').count() + leading.matches('\n').count() + 1;
        let upper = statement.to_ascii_uppercase();
        let words: Vec<&str> = upper.split_whitespace().collect();
        let has = |pair: [&str; 2]| words.windows(2).any(|w| w == pair.as_slice());
        let mut flag = |what| findings.push(Finding { line, what });
        if has(["DROP", "COLUMN"]) {
            flag("drops a column");
        }
        if has(["DROP", "TABLE"]) {
            flag("drops a table");
        }
        if has(["RENAME", "COLUMN"]) {
            flag("renames a column");
        } else if has(["RENAME", "TO"]) {
            flag("renames a table or column");
        }
        if has(["ALTER", "COLUMN"]) && words.contains(&"TYPE") {
            flag("changes a column's type");
        }
        if upper.contains("SET NOT NULL") && !words.contains(&"DEFAULT") {
            flag("makes a column NOT NULL without a default");
        }
        offset += statement.len() + 1;
    }
    findings
}

fn ordinal(name: &str) -> Option<u32> {
    name.split('_').next()?.parse().ok()
}

#[test]
fn new_migrations_are_expand_only() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut problems = Vec::new();
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read migrations") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.ends_with(".sql")
            || ordinal(&name).is_none_or(|n| n <= BASELINE)
            || REVIEWED.iter().any(|(file, _)| *file == name)
        {
            continue;
        }
        checked += 1;
        let sql = std::fs::read_to_string(&path).expect("read migration");
        for f in detect(&sql) {
            problems.push(format!("{name}:{}: {}", f.line, f.what));
        }
    }
    assert!(
        problems.is_empty(),
        "migrations above {BASELINE:04} must only add structure; move these to a contract \
         migration (crates/apps/attome/contract/README.md):\n{}",
        problems.join("\n")
    );
    eprintln!("migration_expand_only: {checked} migrations above the baseline checked");
}

#[test]
fn detector_flags_drop_column() {
    let sql = "-- a harmless comment: DROP TABLE x\n\
               ALTER TABLE a ADD COLUMN IF NOT EXISTS b text;\n\
               ALTER TABLE a DROP COLUMN c;\n";
    assert_eq!(
        detect(sql),
        vec![Finding {
            line: 3,
            what: "drops a column"
        }]
    );
}

#[test]
fn detector_flags_type_rename_and_not_null() {
    let flagged = |sql: &str| detect(sql).into_iter().map(|f| f.what).collect::<Vec<_>>();
    assert_eq!(
        flagged("ALTER TABLE a ALTER COLUMN b TYPE bigint;"),
        vec!["changes a column's type"]
    );
    assert_eq!(
        flagged("ALTER TABLE a RENAME TO b;"),
        vec!["renames a table or column"]
    );
    assert_eq!(
        flagged("ALTER TABLE a ALTER COLUMN b SET NOT NULL;"),
        vec!["makes a column NOT NULL without a default"]
    );
    assert!(flagged("ALTER TABLE a ADD COLUMN b integer NOT NULL DEFAULT 0;").is_empty());
    assert!(flagged("CREATE TABLE IF NOT EXISTS t (id uuid PRIMARY KEY);").is_empty());
}
