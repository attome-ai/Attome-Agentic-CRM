//! Draft edit commands (roadmap Y1-T8): the one way a document changes, for
//! the canvas, agents and the API alike. Agents never write a document
//! directly; they send the same commands as people.
//!
//! Paths are JSON Pointers (RFC 6901). `Add` inserts into an array (an index,
//! or `-` for the end) or sets an object member; `Set` replaces a value that
//! exists or adds an object member; `Remove` deletes; `Move` removes then adds,
//! with the destination read after the removal, as RFC 6902 does.
//!
//! [`apply_commands`] refuses a stale edit: the caller names the content hash
//! it edited, and a draft that changed since is a version conflict.

use attome_db::Tx;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::KindRegistry;
use crate::kind::{Issue, Kind};
use crate::store::{self, DraftSaved, ObjectSpec};

/// One edit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Command {
    Add { path: String, value: Value },
    Remove { path: String },
    Move { from: String, to: String },
    Set { path: String, value: Value },
}

fn unescape(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

/// The parent of `path` and the last segment.
fn split(path: &str) -> Result<(Vec<String>, String), Issue> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(Issue::new(
            path,
            "bad_path",
            "a path is a JSON Pointer such as /a/0/b",
        ));
    }
    let mut segments: Vec<String> = path[1..].split('/').map(unescape).collect();
    let last = segments.pop().unwrap_or_default();
    Ok((segments, last))
}

fn walk<'a>(doc: &'a mut Value, segments: &[String], path: &str) -> Result<&'a mut Value, Issue> {
    let mut current = doc;
    for segment in segments {
        current = match current {
            Value::Object(map) => map.get_mut(segment),
            Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get_mut(i)),
            _ => None,
        }
        .ok_or_else(|| Issue::new(path, "no_such_path", format!("{path} does not exist")))?;
    }
    Ok(current)
}

fn index(items: &[Value], segment: &str, path: &str, allow_end: bool) -> Result<usize, Issue> {
    if allow_end && segment == "-" {
        return Ok(items.len());
    }
    let index: usize = segment.parse().map_err(|_| {
        Issue::new(
            path,
            "bad_index",
            format!("{segment} is not an array index"),
        )
    })?;
    let limit = if allow_end {
        items.len()
    } else {
        items.len().saturating_sub(1)
    };
    if index > limit || (!allow_end && items.is_empty()) {
        return Err(Issue::new(
            path,
            "index_out_of_range",
            format!("{path} is past the end"),
        ));
    }
    Ok(index)
}

fn add(doc: &mut Value, path: &str, value: Value) -> Result<(), Issue> {
    let (parent, last) = split(path)?;
    match walk(doc, &parent, path)? {
        Value::Object(map) => {
            map.insert(last, value);
            Ok(())
        }
        Value::Array(items) => {
            let at = index(items, &last, path, true)?;
            items.insert(at, value);
            Ok(())
        }
        _ => Err(Issue::new(
            path,
            "not_a_container",
            "only objects and arrays hold values",
        )),
    }
}

fn remove(doc: &mut Value, path: &str) -> Result<Value, Issue> {
    let (parent, last) = split(path)?;
    match walk(doc, &parent, path)? {
        Value::Object(map) => map
            .remove(&last)
            .ok_or_else(|| Issue::new(path, "no_such_path", format!("{path} does not exist"))),
        Value::Array(items) => {
            let at = index(items, &last, path, false)?;
            Ok(items.remove(at))
        }
        _ => Err(Issue::new(
            path,
            "not_a_container",
            "only objects and arrays hold values",
        )),
    }
}

fn set(doc: &mut Value, path: &str, value: Value) -> Result<(), Issue> {
    let (parent, last) = split(path)?;
    match walk(doc, &parent, path)? {
        Value::Object(map) => {
            map.insert(last, value);
            Ok(())
        }
        Value::Array(items) => {
            let at = index(items, &last, path, false)?;
            items[at] = value;
            Ok(())
        }
        _ => Err(Issue::new(
            path,
            "not_a_container",
            "only objects and arrays hold values",
        )),
    }
}

/// Applies one command to `doc`, with no I/O. On error `doc` may be left
/// partly changed; [`apply_all`] works on a copy.
pub fn apply(doc: &mut Value, command: &Command) -> Result<(), Issue> {
    match command {
        Command::Add { path, value } => add(doc, path, value.clone()),
        Command::Remove { path } => remove(doc, path).map(|_| ()),
        Command::Set { path, value } => set(doc, path, value.clone()),
        Command::Move { from, to } => {
            if to.starts_with(&format!("{from}/")) {
                return Err(Issue::new(
                    to.as_str(),
                    "move_into_itself",
                    "a value cannot move inside itself",
                ));
            }
            let value = remove(doc, from)?;
            add(doc, to, value)
        }
    }
}

/// Applies every command to a copy of `doc`; all or nothing.
pub fn apply_all(doc: &Value, commands: &[Command]) -> Result<Value, Issue> {
    let mut copy = doc.clone();
    for command in commands {
        apply(&mut copy, command)?;
    }
    Ok(copy)
}

fn issues_error(issues: &[Issue]) -> AppError {
    crate::validate::publish_error(issues)
}

/// Loads the object's current document (its draft, else its newest version),
/// refuses when its content hash is not `base_hash`, applies `commands`,
/// checks the shape and saves the draft. Runs in the caller's transaction.
pub async fn apply_commands(
    tx: &mut Tx<'_>,
    registry: &KindRegistry,
    kind: &dyn Kind,
    object: &ObjectSpec,
    base_hash: &str,
    commands: &[Command],
    actor: Option<Uuid>,
) -> Result<DraftSaved, AppError> {
    let current: Option<(Value, String)> = sqlx::query_as(
        "SELECT doc, content_hash FROM metadata_object_version \
         WHERE object_id = $1 ORDER BY (state = 'draft') DESC, version_no DESC LIMIT 1",
    )
    .bind(object.id.0)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (doc, hash) = current.ok_or(AppError::NotFound)?;
    if hash != base_hash {
        return Err(AppError::VersionConflict);
    }
    let edited = apply_all(&doc, commands).map_err(|issue| issues_error(&[issue]))?;
    let issues = crate::validate::validate_edit(kind, &edited);
    if !issues.is_empty() {
        return Err(issues_error(&issues));
    }
    store::save_draft(tx, registry, kind, object, &edited, actor).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(doc: Value, commands: &[Command]) -> Result<Value, Issue> {
        apply_all(&doc, commands)
    }

    #[test]
    fn set_nested_property() {
        let out = run(
            json!({ "a": { "b": 1 } }),
            &[
                Command::Set {
                    path: "/a/b".into(),
                    value: json!(2),
                },
                Command::Set {
                    path: "/a/c".into(),
                    value: json!("x"),
                },
            ],
        )
        .unwrap();
        assert_eq!(out, json!({ "a": { "b": 2, "c": "x" } }));
        assert_eq!(
            run(
                json!({}),
                &[Command::Set {
                    path: "/missing/x".into(),
                    value: json!(1)
                }]
            )
            .unwrap_err()
            .code,
            "no_such_path"
        );
    }

    #[test]
    fn add_and_remove_array_item() {
        let out = run(
            json!({ "items": ["a", "c"] }),
            &[
                Command::Add {
                    path: "/items/1".into(),
                    value: json!("b"),
                },
                Command::Add {
                    path: "/items/-".into(),
                    value: json!("d"),
                },
                Command::Remove {
                    path: "/items/0".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(out, json!({ "items": ["b", "c", "d"] }));
    }

    #[test]
    fn move_between_arrays() {
        let out = run(
            json!({ "left": [1, 2], "right": [3] }),
            &[Command::Move {
                from: "/left/0".into(),
                to: "/right/-".into(),
            }],
        )
        .unwrap();
        assert_eq!(out, json!({ "left": [2], "right": [3, 1] }));
        assert_eq!(
            run(
                json!({ "a": { "b": {} } }),
                &[Command::Move {
                    from: "/a".into(),
                    to: "/a/b/c".into()
                }]
            )
            .unwrap_err()
            .code,
            "move_into_itself"
        );
    }

    #[test]
    fn out_of_range_index_is_issue() {
        let doc = json!({ "items": [1] });
        assert_eq!(
            run(
                doc.clone(),
                &[Command::Add {
                    path: "/items/5".into(),
                    value: json!(0)
                }]
            )
            .unwrap_err()
            .code,
            "index_out_of_range"
        );
        assert_eq!(
            run(
                doc.clone(),
                &[Command::Remove {
                    path: "/items/1".into()
                }]
            )
            .unwrap_err()
            .code,
            "index_out_of_range"
        );
        assert_eq!(
            run(
                json!({ "items": [] }),
                &[Command::Set {
                    path: "/items/0".into(),
                    value: json!(0)
                }]
            )
            .unwrap_err()
            .code,
            "index_out_of_range"
        );
        // All or nothing: a failing command leaves the input untouched.
        let original = json!({ "items": [1] });
        let _ = run(
            original.clone(),
            &[
                Command::Remove {
                    path: "/items/0".into(),
                },
                Command::Remove {
                    path: "/items/0".into(),
                },
            ],
        );
        assert_eq!(original, json!({ "items": [1] }));
    }

    #[test]
    fn commands_round_trip_as_json() {
        let command: Command =
            serde_json::from_value(json!({ "op": "move", "from": "/a", "to": "/b" })).unwrap();
        assert_eq!(
            command,
            Command::Move {
                from: "/a".into(),
                to: "/b".into()
            }
        );
    }
}
