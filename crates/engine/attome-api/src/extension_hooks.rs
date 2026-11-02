//! Y10-T2: published extensions run at the record write pipeline's hook
//! stages. A manifest's `hooks` name the entity and stage; [`ExtensionHooks`]
//! (one per stage, registered at boot) calls each matching extension's
//! `on_record` export through the JSON calling convention
//! (`attome_extension::Runtime::call_json_measured`).
//!
//! What a hook sees and may do is held to its grants: the values it is given
//! are only the attributes it may read, and a change to an attribute it may
//! not write refuses the save. An extension that fails (fuel, time, memory,
//! a trap, an answer that is not one of the three below) refuses the save
//! too: a validation the extension owns is never skipped silently. Every call
//! is logged as a run (Y10-T6).
//!
//! The answer is JSON: `"continue"`, `{"change": {attribute: value}}` (a
//! `before` stage only) or `{"reject": "message"}`.
//!
//! Cache: no file-store read may happen inside a write's transaction, so the
//! published extensions and their compiled modules are kept in a process
//! snapshot ([`refresh`]), loaded at boot before anything serves and every
//! [`REFRESH_EVERY`] after by [`start`]. Source of truth: the `extension`
//! table and the file store; key: the module's SHA-256; no invalidation
//! beyond the refresh, so a newly published version runs within
//! [`REFRESH_EVERY`]. Switching off is immediate: each call re-reads the
//! version's status from the database first. A module the
//! refresh could not load refuses its entity's writes with a 503 until it
//! loads; a refresh that fails keeps the snapshot before it.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use attome_core::EngineState;
use attome_core::record_hooks::{HookEvent, HookFuture, HookOutcome, HookStage, RecordHook};
use attome_extension::{Grants, HookPoint, Limits, Runtime};
use attome_storage::object_store::{ObjectStoreExt, path::Path as ObjectPath};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// How often [`start`]'s task reloads the published extensions.
pub const REFRESH_EVERY: Duration = Duration::from_secs(5);

/// The export a hook calls.
pub const HOOK_EXPORT: &str = "on_record";

/// One published extension's hook on one entity and stage.
#[derive(Clone)]
struct Target {
    name: String,
    version: i32,
    entity: String,
    point: HookPoint,
    order: i32,
    grants: Arc<Grants>,
    /// `None` when the refresh could not load or compile the module.
    module: Option<attome_extension::Module>,
}

#[derive(Default)]
struct Snapshot {
    targets: Vec<Target>,
}

impl Snapshot {
    fn watches(&self, entity: &str, point: HookPoint) -> bool {
        self.targets
            .iter()
            .any(|t| t.entity == entity && t.point == point)
    }
}

/// The process's snapshot. Empty until the first [`refresh`].
static SNAPSHOT: LazyLock<RwLock<Arc<Snapshot>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Snapshot::default())));

fn current() -> Arc<Snapshot> {
    SNAPSHOT.read().map_or_else(
        |poisoned| Arc::clone(&poisoned.into_inner()),
        |s| Arc::clone(&s),
    )
}

fn point_of(stage: HookStage) -> HookPoint {
    match stage {
        HookStage::BeforeValidation => HookPoint::BeforeValidation,
        HookStage::BeforeSave => HookPoint::BeforeSave,
        HookStage::AfterSave => HookPoint::AfterSave,
        HookStage::AfterCommit => HookPoint::AfterCommit,
    }
}

#[derive(sqlx::FromRow)]
struct PublishedRow {
    name: String,
    version: i32,
    module_key: String,
    module_sha256: String,
    manifest: Value,
}

/// Reloads the published extensions that declare hooks, reusing the
/// modules already compiled (by SHA-256) and loading the rest from the file
/// store. Answers how many hooks the snapshot holds.
pub async fn refresh(state: &EngineState) -> Result<usize, AppError> {
    let rows: Vec<PublishedRow> = sqlx::query_as(
        "SELECT name, version, module_key, module_sha256, manifest FROM extension \
          WHERE status = 'published' AND jsonb_array_length(COALESCE(manifest->'hooks', '[]'::jsonb)) > 0",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let before = current();
    let mut compiled: HashMap<String, attome_extension::Module> = HashMap::new();
    for target in &before.targets {
        if let Some(module) = &target.module {
            compiled.insert(
                format!("{}#{}", target.name, target.version),
                module.clone(),
            );
        }
    }
    let mut targets = Vec::new();
    for row in rows {
        let grants: Grants = match serde_json::from_value(row.manifest) {
            Ok(grants) => grants,
            Err(error) => {
                tracing::warn!(extension = %row.name, %error, "a published manifest does not parse; its hooks are skipped");
                continue;
            }
        };
        let key = format!("{}#{}", row.name, row.version);
        let module = match compiled.get(&key) {
            Some(module) => Some(module.clone()),
            None => load(state, &row.module_key, &row.module_sha256)
                .await
                .inspect_err(|error| {
                    tracing::error!(extension = %row.name, version = row.version, %error, "a published extension could not be loaded; its entity's writes are refused until it loads");
                })
                .ok(),
        };
        let grants = Arc::new(grants);
        for hook in &grants.hooks {
            targets.push(Target {
                name: row.name.clone(),
                version: row.version,
                entity: hook.entity.clone(),
                point: hook.stage,
                order: hook.order,
                grants: grants.clone(),
                module: module.clone(),
            });
        }
    }
    targets.sort_by_key(|t| t.order);
    let count = targets.len();
    let next = Arc::new(Snapshot { targets });
    match SNAPSHOT.write() {
        Ok(mut slot) => *slot = next,
        Err(poisoned) => *poisoned.into_inner() = next,
    }
    Ok(count)
}

/// Reads a module from the file store, checks its digest and compiles it
/// off the async workers.
async fn load(
    state: &EngineState,
    key: &str,
    sha256: &str,
) -> Result<attome_extension::Module, AppError> {
    use sha2::{Digest, Sha256};
    let path = ObjectPath::parse(key).map_err(AppError::internal)?;
    let bytes = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .map_err(AppError::internal)?
        .bytes()
        .await
        .map_err(AppError::internal)?;
    if hex::encode(Sha256::digest(&bytes)) != sha256 {
        return Err(AppError::internal(format!(
            "the stored module {key} does not match its digest"
        )));
    }
    tokio::task::spawn_blocking(move || Runtime::shared().and_then(|rt| rt.compile(&bytes)))
        .await
        .map_err(AppError::internal)?
        .map_err(AppError::internal)
}

/// Loads the snapshot once (awaited, so the first request sees it) and
/// keeps it fresh every [`REFRESH_EVERY`] for the life of the process.
pub async fn start(state: EngineState) {
    if let Err(error) = refresh(&state).await {
        tracing::error!(%error, "extension hooks could not be loaded at boot; retrying");
    }
    // Process-lifetime supervision: the loop only rebuilds a snapshot.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(error) = refresh(&state).await {
                tracing::warn!(%error, "extension hooks refresh failed; keeping the last snapshot");
            }
        }
    });
}

/// What an extension answered.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    Continue,
    Change(Map<String, Value>),
    Reject(String),
}

/// The values a grant lets the extension see: every attribute, or the
/// granted ones and the id. Pure.
fn visible(grants: &Grants, entity: &str, values: &Map<String, Value>) -> Map<String, Value> {
    match grants.entities.get(entity) {
        Some(grant) if !grant.attributes.is_empty() => values
            .iter()
            .filter(|(k, _)| k.as_str() == "id" || grant.attributes.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        Some(_) => values.clone(),
        None => Map::new(),
    }
}

/// The record write hook for one stage, running every published extension
/// declared on it.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionHooks {
    stage: HookStage,
}

impl ExtensionHooks {
    /// One per stage, for the `EngineSystem` builder.
    pub fn all() -> [ExtensionHooks; 4] {
        [
            HookStage::BeforeValidation,
            HookStage::BeforeSave,
            HookStage::AfterSave,
            HookStage::AfterCommit,
        ]
        .map(|stage| ExtensionHooks { stage })
    }
}

impl RecordHook for ExtensionHooks {
    fn name(&self) -> &str {
        "extensions"
    }

    fn entity(&self) -> &str {
        "*"
    }

    fn watches(&self, entity: &str) -> bool {
        current().watches(entity, point_of(self.stage))
    }

    fn stage(&self) -> HookStage {
        self.stage
    }

    /// After the platform's own hooks.
    fn order(&self) -> i32 {
        1_000
    }

    fn run<'a>(&'a self, state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move {
            let point = point_of(self.stage);
            let snapshot = current();
            let limits = Limits::from(&state.base.config.extensions);
            let mut changes = Map::new();
            for target in snapshot
                .targets
                .iter()
                .filter(|t| t.entity == event.entity && t.point == point)
            {
                // Switched off or superseded since the snapshot: skip.
                let live = crate::extension_admin::published(&state.base.db, &target.name)
                    .await?
                    .is_some_and(|v| v.version == target.version);
                if !live {
                    continue;
                }
                let Some(module) = target.module.clone() else {
                    return Err(AppError::CapabilityUnavailable(
                        "an extension on this entity could not be loaded",
                    ));
                };
                let mut values = event.values.clone();
                values.extend(changes.clone());
                let input = json!({
                    "stage": point,
                    "entity": event.entity,
                    "record_id": event.record_id,
                    "is_create": event.is_create,
                    "values": visible(&target.grants, event.entity, &values),
                    "previous": event.previous.map(|p| visible(&target.grants, event.entity, p)),
                    "actor": event.actor,
                });
                let input = serde_json::to_vec(&input).map_err(AppError::internal)?;
                let (result, cost) = tokio::task::spawn_blocking(move || match Runtime::shared() {
                    Ok(rt) => rt.call_json_measured(&module, HOOK_EXPORT, &input, &limits),
                    Err(e) => (Err(e), attome_extension::CallCost::default()),
                })
                .await
                .map_err(AppError::internal)?;
                let answer = result.map_err(|e| e.to_string()).and_then(|out| {
                    serde_json::from_slice::<Answer>(&out)
                        .map_err(|e| format!("the answer is not continue, change or reject: {e}"))
                });
                let error = answer.as_ref().err().cloned();
                if let Err(log_error) = crate::extension_admin::record_run(
                    &state.base.db,
                    &target.name,
                    target.version,
                    cost,
                    error.as_deref(),
                    &[],
                    &[],
                    false,
                )
                .await
                {
                    tracing::warn!(extension = %target.name, error = %log_error, "an extension run was not logged");
                }
                match answer {
                    Err(error) => {
                        return Err(AppError::Validation(format!(
                            "the extension {} failed: {error}",
                            target.name
                        )));
                    }
                    Ok(Answer::Continue) => {}
                    Ok(Answer::Change(set)) => {
                        let keys: Vec<&str> = set.keys().map(String::as_str).collect();
                        target
                            .grants
                            .may_write(event.entity, &keys)
                            .map_err(|denied| {
                                AppError::Validation(format!(
                                    "the extension {}: {denied}",
                                    target.name
                                ))
                            })?;
                        changes.extend(set);
                    }
                    Ok(Answer::Reject(message)) => return Ok(HookOutcome::Reject(message)),
                }
            }
            Ok(if changes.is_empty() {
                HookOutcome::Continue
            } else {
                HookOutcome::Change(changes)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_and_visible_values() {
        assert!(matches!(
            serde_json::from_str::<Answer>(r#""continue""#),
            Ok(Answer::Continue)
        ));
        assert!(matches!(
            serde_json::from_str::<Answer>(r#"{"reject":"no"}"#),
            Ok(Answer::Reject(m)) if m == "no"
        ));
        assert!(serde_json::from_str::<Answer>(r#"{"other":1}"#).is_err());

        let grants: Grants = serde_json::from_value(json!({
            "entities": { "account": { "read": true, "attributes": ["name"] } }
        }))
        .unwrap();
        let values: Map<String, Value> =
            serde_json::from_value(json!({ "id": "x", "name": "n", "secret_note": "s" })).unwrap();
        let seen = visible(&grants, "account", &values);
        assert_eq!(seen.len(), 2);
        assert!(!seen.contains_key("secret_note"));
        assert!(visible(&grants, "deal", &values).is_empty());
    }
}
