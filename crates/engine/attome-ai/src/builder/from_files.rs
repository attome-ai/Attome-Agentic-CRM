//! AD5-T1: a model from several uploaded sheets, and their import.
//!
//! Each sheet (a CSV's text with a name) becomes one drafted entity through
//! [`table_from_csv`] (column types from the cells: Hijri and Gregorian
//! dates, numbers, emails, phones, yes/no, Arabic text). On top of that:
//!
//! - **currency**: a column whose filled cells are amounts with one currency
//!   marker (`SAR`, `ر.س`, `$`, `€`, ...) is a `currency` attribute, and the
//!   currency is named;
//! - **keys**: a sheet's key is a column filled and distinct in every row,
//!   preferring a header that says id, code or number;
//! - **lookups**: a column whose values are, for at least [`LOOKUP_SHARE`]
//!   of its filled cells, another sheet's key values is a lookup to that
//!   sheet's entity (`<target>_ref`, many-to-one);
//! - **the import**: per sheet, the `POST /api/v1/{entity}/imports` options
//!   that load the file once the model is built (each column to its
//!   attribute, lookups matched on the target's key, upsert on the sheet's
//!   own key), ordered so a sheet's targets load first.
//!
//! Pure: nothing here calls a model or writes. The action
//! (`model.from_files`) labels the result and plans the build-tool calls.

use std::collections::HashSet;

use serde::Serialize;
use serde_json::{Value, json};

use crate::actions::draft_model::{DraftTable, MAX_INFER_ROWS, table_from_csv};
use crate::builder::infer::{is_number, parse_csv};
use crate::builder::review::DraftRelationship;

/// The share of a column's filled cells that must be another sheet's keys.
pub const LOOKUP_SHARE: f64 = 0.9;

/// Currency markers and the code each names; longer markers first.
const CURRENCIES: &[(&str, &str)] = &[
    ("SAR", "SAR"),
    ("ر.س", "SAR"),
    ("﷼", "SAR"),
    ("EGP", "EGP"),
    ("ج.م", "EGP"),
    ("AED", "AED"),
    ("د.إ", "AED"),
    ("KWD", "KWD"),
    ("د.ك", "KWD"),
    ("QAR", "QAR"),
    ("ر.ق", "QAR"),
    ("USD", "USD"),
    ("EUR", "EUR"),
    ("GBP", "GBP"),
    ("$", "USD"),
    ("€", "EUR"),
    ("£", "GBP"),
];

/// One uploaded sheet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Sheet {
    /// The file or sheet name; the entity is named from it.
    pub name: String,
    pub csv: String,
}

/// A lookup found between two sheets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SheetLookup {
    /// The entity and attribute holding the lookup.
    pub entity: String,
    pub attribute: String,
    /// The column it came from.
    pub column: String,
    /// The entity it points to, and that entity's key attribute.
    pub target: String,
    pub target_key: String,
    /// The share of filled cells found among the target's keys.
    pub share: f64,
}

/// What the files make.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FilesDraft {
    pub tables: Vec<DraftTable>,
    /// Per entity, the key attribute (if a column is one).
    pub keys: Vec<(String, Option<String>)>,
    /// Per entity and attribute, the currency a currency column holds.
    pub currencies: Vec<(String, String, String)>,
    pub lookups: Vec<SheetLookup>,
    /// Per sheet, in load order, the import that loads it once built.
    pub imports: Vec<Value>,
}

/// The currency `cell` is an amount in, if it is one. Pure.
pub fn currency_of(cell: &str) -> Option<&'static str> {
    let t = cell.trim();
    CURRENCIES.iter().find_map(|(marker, code)| {
        let rest = t.strip_prefix(marker).or_else(|| t.strip_suffix(marker))?;
        is_number(rest.trim()).then_some(*code)
    })
}

/// The one currency at least nine in ten of `cells` (filled) are in. Pure.
pub fn column_currency(cells: &[&str]) -> Option<&'static str> {
    let first = cells.iter().find_map(|c| currency_of(c))?;
    let agree = cells
        .iter()
        .filter(|c| currency_of(c) == Some(first))
        .count();
    (agree * 10 >= cells.len() * 9).then_some(first)
}

fn key_like(header: &str) -> bool {
    let h = header.trim().to_lowercase();
    ["id", "code", "number", "no", "ref", "رقم", "كود", "رمز"]
        .iter()
        .any(|k| {
            h == *k
                || h.ends_with(&format!(" {k}"))
                || h.ends_with(&format!("_{k}"))
                || h.starts_with(&format!("{k} "))
        })
}

/// The key column of a sheet: filled and distinct in every row (two rows at
/// least), a key-like header first. Pure.
pub fn key_column(headers: &[String], rows: &[Vec<String>]) -> Option<usize> {
    if rows.len() < 2 {
        return None;
    }
    let unique = |i: usize| {
        let mut seen = HashSet::new();
        rows.iter().all(|r| {
            r.get(i)
                .map(|c| c.trim())
                .is_some_and(|c| !c.is_empty() && seen.insert(c.to_owned()))
        })
    };
    let candidates: Vec<usize> = (0..headers.len()).filter(|i| unique(*i)).collect();
    candidates
        .iter()
        .copied()
        .find(|i| key_like(&headers[*i]))
        .or_else(|| candidates.first().copied())
}

struct Parsed {
    entity: String,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    key: Option<usize>,
}

fn column_cells<'a>(rows: &'a [Vec<String>], i: usize) -> Vec<&'a str> {
    rows.iter()
        .filter_map(|r| r.get(i).map(|c| c.trim()))
        .filter(|c| !c.is_empty())
        .collect()
}

/// Drafts the sheets' entities, lookups and imports. Pure.
pub fn from_files(sheets: &[Sheet]) -> FilesDraft {
    let mut tables: Vec<DraftTable> = Vec::new();
    let mut parsed: Vec<Parsed> = Vec::new();
    let mut names = HashSet::new();
    for sheet in sheets {
        let mut table = table_from_csv(&sheet.name, &sheet.csv);
        while !names.insert(table.name.clone()) {
            table.name.push_str("_2");
        }
        let (headers, rows) = parse_csv(&sheet.csv);
        let rows: Vec<Vec<String>> = rows.into_iter().take(MAX_INFER_ROWS).collect();
        let key = key_column(&headers, &rows);
        parsed.push(Parsed {
            entity: table.name.clone(),
            headers,
            rows,
            key,
        });
        tables.push(table);
    }

    let mut currencies = Vec::new();
    for (table, p) in tables.iter_mut().zip(&parsed) {
        for (i, attribute) in table.attributes.iter_mut().enumerate() {
            if let Some(code) = column_currency(&column_cells(&p.rows, i)) {
                attribute.field_type = "currency".to_owned();
                currencies.push((table.name.clone(), attribute.name.clone(), code.to_owned()));
            }
        }
    }

    // Lookups: a column whose values are another sheet's keys.
    let mut lookups = Vec::new();
    for (a, pa) in parsed.iter().enumerate() {
        for i in 0..pa.headers.len() {
            if Some(i) == pa.key {
                continue;
            }
            let cells = column_cells(&pa.rows, i);
            if cells.is_empty() {
                continue;
            }
            let mut best: Option<(usize, f64)> = None;
            for (b, pb) in parsed.iter().enumerate() {
                let Some(k) = pb.key else { continue };
                if a == b {
                    continue;
                }
                let keys: HashSet<&str> = column_cells(&pb.rows, k).into_iter().collect();
                let found = cells.iter().filter(|c| keys.contains(*c)).count();
                let share = found as f64 / cells.len() as f64;
                if share >= LOOKUP_SHARE && best.is_none_or(|(_, s)| share > s) {
                    best = Some((b, share));
                }
            }
            if let Some((b, share)) = best {
                let target = &tables[b];
                let target_key = target.attributes[parsed[b].key.unwrap_or(0)].name.clone();
                lookups.push(SheetLookup {
                    entity: tables[a].name.clone(),
                    attribute: format!("{}_ref", target.name),
                    column: pa.headers[i].trim().to_owned(),
                    target: target.name.clone(),
                    target_key,
                    share,
                });
            }
        }
    }
    for l in &lookups {
        let Some(table) = tables.iter_mut().find(|t| t.name == l.entity) else {
            continue;
        };
        if let Some(attribute) = table.attributes.iter_mut().find(|a| a.label_en == l.column) {
            attribute.name.clone_from(&l.attribute);
            attribute.field_type = "lookup".to_owned();
        }
        table.relationships.push(DraftRelationship {
            target: l.target.clone(),
            kind: "many_to_one".to_owned(),
            attribute: Some(l.attribute.clone()),
        });
    }

    let keys: Vec<(String, Option<String>)> = tables
        .iter()
        .zip(&parsed)
        .map(|(t, p)| (t.name.clone(), p.key.map(|k| t.attributes[k].name.clone())))
        .collect();
    let imports = import_offers(&tables, &parsed, &keys, &lookups);
    FilesDraft {
        tables,
        keys,
        currencies,
        lookups,
        imports,
    }
}

/// The imports in load order: an entity after the entities it looks up.
fn import_offers(
    tables: &[DraftTable],
    parsed: &[Parsed],
    keys: &[(String, Option<String>)],
    lookups: &[SheetLookup],
) -> Vec<Value> {
    let mut order: Vec<usize> = Vec::new();
    while order.len() < tables.len() {
        let before = order.len();
        for (i, t) in tables.iter().enumerate() {
            if order.contains(&i) {
                continue;
            }
            let waits = lookups.iter().any(|l| {
                l.entity == t.name
                    && l.target != t.name
                    && !order.iter().any(|o| tables[*o].name == l.target)
            });
            if !waits {
                order.push(i);
            }
        }
        if order.len() == before {
            // A cycle: the rest in sheet order.
            order.extend(
                (0..tables.len())
                    .filter(|i| !order.contains(i))
                    .collect::<Vec<_>>(),
            );
        }
    }
    order
        .into_iter()
        .map(|i| {
            let t = &tables[i];
            let columns: Vec<Value> = parsed[i]
                .headers
                .iter()
                .zip(&t.attributes)
                .map(|(h, a)| json!({ "source": h.trim(), "target": a.name }))
                .collect();
            let mut lookup_map = serde_json::Map::new();
            for l in lookups.iter().filter(|l| l.entity == t.name) {
                lookup_map.insert(
                    l.attribute.clone(),
                    json!({ "by": "code", "field": l.target_key }),
                );
            }
            let key = keys[i].1.clone();
            json!({
                "entity": t.name,
                "file": t.label_en,
                "method": "POST",
                "route": format!("/api/v1/{}/imports", t.name),
                "options": {
                    "mapping": { "columns": columns, "lookups": lookup_map },
                    "match_mode": if key.is_some() { "upsert" } else { "create" },
                    "match_columns": key.into_iter().collect::<Vec<_>>(),
                    "dry_run": true,
                },
                "after": lookups.iter().filter(|l| l.entity == t.name && l.target != t.name)
                    .map(|l| l.target.clone()).collect::<Vec<_>>(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sheets() -> Vec<Sheet> {
        vec![
            Sheet {
                name: "Visits".into(),
                csv: "Visit No,Patient Code,Fee,Visit Date\n\
                      V1,P1,150 SAR,1446/03/15\n\
                      V2,P2,ر.س 200,1446/03/16\n\
                      V3,P1,90 SAR,1446/03/17\n"
                    .into(),
            },
            Sheet {
                name: "Patients".into(),
                csv: "Code,Name,Phone\nP1,Sara,+966500000001\nP2,Omar,+966500000002\n".into(),
            },
        ]
    }

    #[test]
    fn builder_from_files_reads_currency_keys_and_lookups() {
        assert_eq!(currency_of("150 SAR"), Some("SAR"));
        assert_eq!(currency_of("ر.س 1,200.50"), Some("SAR"));
        assert_eq!(currency_of("$12"), Some("USD"));
        assert_eq!(currency_of("SAR"), None);
        assert_eq!(currency_of("150"), None);

        let draft = from_files(&sheets());
        let visits = &draft.tables[0];
        assert_eq!(visits.name, "visits");
        let fee = visits.attributes.iter().find(|a| a.name == "fee").unwrap();
        assert_eq!(fee.field_type, "currency");
        assert_eq!(
            draft.currencies,
            vec![("visits".to_owned(), "fee".to_owned(), "SAR".to_owned())]
        );
        assert_eq!(
            draft.keys,
            vec![
                ("visits".to_owned(), Some("visit_no".to_owned())),
                ("patients".to_owned(), Some("code".to_owned())),
            ]
        );
        assert_eq!(draft.lookups.len(), 1);
        let lookup = &draft.lookups[0];
        assert_eq!(
            (
                lookup.entity.as_str(),
                lookup.attribute.as_str(),
                lookup.target_key.as_str()
            ),
            ("visits", "patients_ref", "code")
        );
        let patient = visits
            .attributes
            .iter()
            .find(|a| a.name == "patients_ref")
            .unwrap();
        assert_eq!(patient.field_type, "lookup");
        assert_eq!(visits.relationships[0].target, "patients");
    }

    #[test]
    fn builder_from_files_offers_the_import_targets_first() {
        let draft = from_files(&sheets());
        let order: Vec<&str> = draft
            .imports
            .iter()
            .map(|i| i["entity"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["patients", "visits"]);
        let visits = &draft.imports[1];
        assert_eq!(visits["route"], "/api/v1/visits/imports");
        assert_eq!(visits["options"]["match_columns"], json!(["visit_no"]));
        assert_eq!(
            visits["options"]["mapping"]["lookups"]["patients_ref"],
            json!({ "by": "code", "field": "code" })
        );
        assert_eq!(
            visits["options"]["mapping"]["columns"][1],
            json!({ "source": "Patient Code", "target": "patients_ref" })
        );
        assert_eq!(visits["after"], json!(["patients"]));
    }

    #[test]
    fn builder_from_files_needs_most_cells_to_match_a_key() {
        let mut s = sheets();
        s[0].csv = "Visit No,Patient Code\nV1,P1\nV2,X9\nV3,X8\n".into();
        assert!(from_files(&s).lookups.is_empty());
        assert!(key_column(&["A".into()], &[vec!["1".into()]]).is_none());
    }
}
