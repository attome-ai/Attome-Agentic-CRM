//! MCP entity admission — plan item M3.4 (`mcp-excellence-10-10.md` §4,
//! invariant MI-3), MASTER-PLAN P0 row 0.5.
//!
//! **Default-deny.** An external agent on the MCP surface reaches an entity
//! through the `record.*` tools only when an administrator has admitted that
//! entity, for that verb, in the deployment-scope runtime setting
//! [`ADMISSION_SETTING_KEY`] (`{"<entity>": ["read", "create", "update",
//! "delete"]}`, default `{}`; owner decision 2026-09-28 — a setting rather
//! than an entity metadata flag). Nothing is admitted until listed.
//!
//! **Some entities are never admitted.** [`EXCLUDED_ENTITIES`] and
//! [`EXCLUDED_PREFIXES`] name the security, identity, audit and licence
//! entities; they are refused even when the setting lists them, whatever the
//! caller holds. That list is code, reviewed like code, and cannot be widened
//! at runtime.
//!
//! **Admission only narrows.** It runs *before* the principal's own privilege
//! check, and that check, record-level security, field grants and the gate
//! all still apply afterwards. Admission never grants anything.
//!
//! **Dark refusals.** A refused call is `AppError::NotFound` — the same answer
//! as an entity that does not exist, an unlicensed tool, or a switched-off
//! surface (D-010) — so probing tells an external agent nothing about what the
//! deployment holds. The reason is logged for the operator instead.
//!
//! **Scope.** Only [`ActionContext::is_mcp_agent`] invocations are governed:
//! the in-product surfaces (chat, webchat, internal agents) run inside the
//! platform's own conversation and are unchanged. The check is called from
//! the action layer (`execute::dispatch` before the gate, so no confirmation
//! or four-eyes request is ever raised for an unadmitted entity; the approved
//! path at execution time; and `run_executor`, the shared tail) — never from
//! the MCP transport, which stays an adapter (D-485, ai-engineering §7).
//!
//! **Read tools without an `entity` argument.** `query.execute`,
//! `search.records` and `graph.traverse` reach entities too; their executors
//! apply [`ReadAdmission`] themselves (see [`GOVERNED_READ_ACTIONS`]), since
//! only they know which entities an answer touches.

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;

use crate::context::ActionContext;
use crate::descriptor::ActionId;

/// The deployment-scope runtime setting (`attome-core::setting_catalog`)
/// holding the admission map.
pub const ADMISSION_SETTING_KEY: &str = "ai.mcp_entity_admission";

/// The verbs an admission entry may grant. A closed set: a string in the
/// setting that is not one of these admits nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Read,
    Create,
    Update,
    Delete,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Read => "read",
            Verb::Create => "create",
            Verb::Update => "update",
            Verb::Delete => "delete",
        }
    }
}

/// Every action admission governs, with the verb it needs. `record.restore`
/// needs `update`, matching the privilege the HTTP restore route (and the
/// executor) requires.
///
/// `admission_covers_every_record_tool` fails when a `record.*` action is
/// registered without an entry here, so a new record tool cannot ship
/// ungoverned.
pub(crate) const GOVERNED_ACTIONS: &[(&str, Verb)] = &[
    ("record.get", Verb::Read),
    // AA7-T10: what changed in one entity since a cursor.
    ("record.changes", Verb::Read),
    ("record.summarize", Verb::Read),
    ("record.classify", Verb::Read),
    ("record.update_field", Verb::Update),
    ("record.create", Verb::Create),
    ("record.update", Verb::Update),
    ("record.delete", Verb::Delete),
    ("record.restore", Verb::Update),
    ("record.deleted", Verb::Read),
    ("record.assign", Verb::Update),
    ("record.schema", Verb::Read),
    ("record.validate", Verb::Read),
    ("record.ai_field", Verb::Read),
    ("record.transitions", Verb::Read),
    ("record.transition", Verb::Update),
    ("record.bulk.preview", Verb::Read),
    ("record.bulk.status", Verb::Read),
    ("record.bulk.update", Verb::Update),
    ("record.bulk.delete", Verb::Delete),
    // A15-T8: duplicates act on one entity's records.
    ("duplicates.check", Verb::Read),
    ("duplicates.list", Verb::Read),
    ("duplicates.merge", Verb::Delete),
    ("duplicates.propose_rules", Verb::Read),
];

/// Security, identity, audit and licence entities, by exact logical name,
/// with the reason logged on refusal. Never admitted over MCP.
pub const EXCLUDED_ENTITIES: &[(&str, &str)] = &[
    ("user_account", "identity"),
    ("role", "security administration"),
    ("privilege", "security administration"),
    ("team", "security administration"),
    ("organization", "security administration"),
    ("api_key", "credential"),
    ("authentication_type", "identity"),
    ("license", "licence"),
    ("ai_agent", "agent principal"),
    ("ai_agent_policy", "agent governance"),
    ("ai_capability_pack", "agent governance"),
    ("ai_provider", "credential"),
    ("ai_model", "model approval"),
    ("integration_system", "service principal"),
    ("webportal_user", "identity"),
];

/// Logical-name prefixes excluded as a family: the audit trail and its
/// configuration, S2S machine principals, and the security join tables.
pub const EXCLUDED_PREFIXES: &[(&str, &str)] = &[
    ("audit_", "audit"),
    ("s2s_", "machine identity"),
    ("user_account_", "security administration"),
    ("role_", "security administration"),
    ("privilege_", "security administration"),
    ("team_", "security administration"),
];

/// What admission decided for one (entity, verb).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    /// Refused by code, whatever the setting says.
    Excluded {
        reason: &'static str,
    },
    /// Not listed in the setting for this verb (the default).
    NotAdmitted,
}

/// The verb an action needs, when admission governs it at all.
pub(crate) fn governed_verb(action: &str) -> Option<Verb> {
    GOVERNED_ACTIONS
        .iter()
        .find(|(id, _)| *id == action)
        .map(|(_, verb)| *verb)
}

/// The code-owned exclusion for `entity`, if any.
pub fn excluded_reason(entity: &str) -> Option<&'static str> {
    EXCLUDED_ENTITIES
        .iter()
        .find(|(name, _)| *name == entity)
        .map(|(_, reason)| *reason)
        .or_else(|| {
            EXCLUDED_PREFIXES
                .iter()
                .find(|(prefix, _)| entity.starts_with(prefix))
                .map(|(_, reason)| *reason)
        })
}

/// Pure decision over the resolved setting value. Exclusion wins over the
/// setting; anything the setting does not list, lists with a non-array
/// value, or lists without this verb is not admitted.
pub fn classify(setting: &Value, entity: &str, verb: Verb) -> Admission {
    if let Some(reason) = excluded_reason(entity) {
        return Admission::Excluded { reason };
    }
    let listed = setting
        .get(entity)
        .and_then(Value::as_array)
        .is_some_and(|verbs| verbs.iter().any(|v| v.as_str() == Some(verb.as_str())));
    if listed {
        Admission::Admitted
    } else {
        Admission::NotAdmitted
    }
}

/// How many entities the setting effectively admits for at least one verb
/// (excluded entities and unrecognised verbs do not count).
pub fn admitted_entity_count(setting: &Value) -> usize {
    let Some(map) = setting.as_object() else {
        return 0;
    };
    map.keys()
        .filter(|entity| {
            [Verb::Read, Verb::Create, Verb::Update, Verb::Delete]
                .into_iter()
                .any(|verb| classify(setting, entity, verb) == Admission::Admitted)
        })
        .count()
}

/// The current effective admission map, from the settings snapshot.
fn current_setting(state: &EngineState) -> Result<Value, AppError> {
    let descriptor = attome_core::setting_registry()
        .get(ADMISSION_SETTING_KEY)
        .ok_or_else(|| AppError::internal("MCP entity admission setting is not registered"))?;
    let (value, _source) = state.settings.load().resolve(descriptor, None, None);
    Ok(value)
}

/// Logs a warning when no entity is admitted, so an operator learns why every
/// MCP `record.*` call is refused. Returns whether anything is admitted.
///
/// Called on every MCP `initialize`; also safe to call at boot once the
/// settings snapshot is loaded.
pub fn warn_if_nothing_admitted(state: &EngineState) -> bool {
    let admitted = match current_setting(state) {
        Ok(setting) => admitted_entity_count(&setting),
        Err(error) => {
            tracing::error!(%error, "could not read the MCP entity admission setting");
            0
        }
    };
    if admitted == 0 {
        tracing::warn!(
            setting = ADMISSION_SETTING_KEY,
            "MCP entity admission is empty: every MCP record.* tool call is refused \
             (default-deny, plan item M3.4). To admit an entity, an administrator calls \
             PUT /api/v1/admin/settings/ai.mcp_entity_admission with \
             {{\"scope\": \"deployment\", \"value\": {{\"account\": [\"read\", \"update\"]}}}}"
        );
    }
    admitted > 0
}

/// Refuses, darkly, an MCP agent's governed call on an entity that is not
/// admitted for the verb. `Ok(())` for every other caller and every
/// ungoverned action.
pub(crate) fn check(
    state: &EngineState,
    ctx: &ActionContext,
    action: ActionId,
    args: &Value,
) -> Result<(), AppError> {
    if !ctx.is_mcp_agent() {
        return Ok(());
    }
    let Some(verb) = governed_verb(action.as_str()) else {
        return Ok(());
    };
    // A governed call without an entity name reaches nothing; refuse it the
    // same dark way rather than let an executor decide what it meant.
    let Some(entity) = args.get("entity").and_then(Value::as_str) else {
        return Err(AppError::NotFound);
    };
    let setting = current_setting(state)?;
    match classify(&setting, entity, verb) {
        Admission::Admitted => Ok(()),
        Admission::Excluded { reason } => {
            tracing::info!(
                action = action.as_str(),
                entity,
                verb = verb.as_str(),
                reason,
                agent_session_id = ?ctx.agent_session_id,
                "MCP record tool refused: entity is excluded from MCP by code"
            );
            Err(AppError::NotFound)
        }
        Admission::NotAdmitted => {
            tracing::info!(
                action = action.as_str(),
                entity,
                verb = verb.as_str(),
                agent_session_id = ?ctx.agent_session_id,
                setting = ADMISSION_SETTING_KEY,
                "MCP record tool refused: entity is not admitted for this verb"
            );
            Err(AppError::NotFound)
        }
    }
}

// ── The read tools that reach entities without naming one up front ─────────

/// The three read actions that reach entity rows over MCP without the
/// `entity` argument [`check`] keys on (D-769's open item). Each executor
/// asks [`ReadAdmission::for_caller`] and applies it itself, because only the
/// executor knows which entities its answer touches:
///
/// - `query.execute` refuses (dark `NotFound`) unless every entity the stored
///   query touches is admitted for `read` ([`query_touched_entities`]), and
///   strips each row's `__lookups` display entry into an entity not admitted
///   ([`ReadAdmission::redact_query_lookups`]; `record.get` and the
///   `record.*` writes do the same to a record's `lookups`);
/// - `search.records` drops hits of entities not admitted, re-pages over what
///   remains, and answers an explicit `type:`/`entity:` filter naming an
///   unadmitted entity with an empty page;
/// - `graph.traverse` refuses an unadmitted start entity and drops every node
///   (and edge) the walk reached only through an unadmitted one
///   ([`filter_traversal`]).
///
/// `admission_covers_every_read_tool` pins each executor to the call; this
/// inventory is what it checks against the registry.
#[cfg(test)]
pub(crate) const GOVERNED_READ_ACTIONS: &[&str] = &[
    crate::actions::read::QUERY_EXECUTE,
    crate::actions::search_records::SEARCH_RECORDS,
    crate::actions::graph::GRAPH_TRAVERSE,
    crate::actions::commission::EXPLAIN_LINE,
    crate::actions::search_ask::SEARCH_PARSE_FILTER,
    crate::actions::search_ask::SEARCH_ANSWER_RECORDS,
    crate::builder::explain::BUILDER_EXPLAIN,
    crate::actions::help::HELP_ANSWER,
];

/// Read-side admission for one MCP invocation: a snapshot of the setting,
/// taken once, so every entity in one answer is judged against the same map.
pub(crate) struct ReadAdmission {
    setting: Value,
}

impl ReadAdmission {
    /// `Some` only for an MCP agent; every other caller is not governed and
    /// gets `None` without the settings snapshot being read.
    pub(crate) fn for_caller(
        state: &EngineState,
        ctx: &ActionContext,
    ) -> Result<Option<Self>, AppError> {
        if !ctx.is_mcp_agent() {
            return Ok(None);
        }
        Ok(Some(Self {
            setting: current_setting(state)?,
        }))
    }

    /// A snapshot over an explicit setting value (unit tests).
    #[cfg(test)]
    pub(crate) fn from_setting(setting: Value) -> Self {
        Self { setting }
    }

    /// Whether `entity` is admitted for `read`. Excluded entities never are.
    pub(crate) fn admits(&self, entity: &str) -> bool {
        classify(&self.setting, entity, Verb::Read) == Admission::Admitted
    }

    /// `Ok(())` when every entity in `touched` is admitted for `read`, and a
    /// dark `NotFound` naming nothing otherwise. An empty `touched` is
    /// refused too: a query whose entities cannot be named is not admitted.
    pub(crate) fn require_all(
        &self,
        action: &str,
        ctx: &ActionContext,
        touched: &[String],
    ) -> Result<(), AppError> {
        if touched.is_empty() {
            tracing::info!(
                action,
                agent_session_id = ?ctx.agent_session_id,
                "MCP read tool refused: the entities it touches cannot be named"
            );
            return Err(AppError::NotFound);
        }
        for entity in touched {
            if !self.admits(entity) {
                tracing::info!(
                    action,
                    entity = entity.as_str(),
                    excluded = excluded_reason(entity),
                    agent_session_id = ?ctx.agent_session_id,
                    setting = ADMISSION_SETTING_KEY,
                    "MCP read tool refused: it touches an entity not admitted for read"
                );
                return Err(AppError::NotFound);
            }
        }
        Ok(())
    }

    /// Keeps only the lookup display entries (`{exists, is_active, name}`,
    /// keyed by lookup field) whose target entity is admitted for `read`.
    /// A display entry is a read of the *target* record, so it needs the
    /// target's admission, not the row's. An entry is dropped whole (its
    /// `exists`/`is_active` say something about the target too), and so is
    /// one this snapshot cannot attribute: an unknown row entity, a field
    /// that is not a lookup of it, or a target missing from the registry.
    /// The raw foreign-key id in the row's own data is untouched — it is a
    /// column of the admitted record.
    fn retain_admitted_lookups(
        &self,
        state: &EngineState,
        row_entity_id: Option<uuid::Uuid>,
        lookups: &mut serde_json::Map<String, Value>,
    ) {
        let registry = state.entities.load();
        let meta = row_entity_id.and_then(|id| registry.get_by_id(id));
        lookups.retain(|field, _| {
            meta.and_then(|m| m.attrs.iter().find(|a| &a.logicalname == field))
                .and_then(|attr| attr.lookup_entity_ref)
                .and_then(|target| registry.get_by_id(target))
                .is_some_and(|target| self.admits(&target.logicalname))
        });
    }

    /// D-769: strips, from a serialised `query_exec::ExecResponse`, every
    /// row's `__lookups` entry into an entity not admitted for `read`.
    /// `linked_entity_id` is the query's linked entity (the only case the
    /// engine attaches `__lookups` for); without one every `__lookups` is
    /// removed.
    pub(crate) fn redact_query_lookups(
        &self,
        state: &EngineState,
        linked_entity_id: Option<uuid::Uuid>,
        response: &mut Value,
    ) {
        let Some(records) = response
            .pointer_mut("/data/records")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        for record in records {
            let Some(row) = record.as_object_mut() else {
                continue;
            };
            let emptied = match row.get_mut("__lookups").and_then(Value::as_object_mut) {
                Some(lookups) => {
                    self.retain_admitted_lookups(state, linked_entity_id, lookups);
                    lookups.is_empty()
                }
                None => row.contains_key("__lookups"),
            };
            if emptied {
                row.remove("__lookups");
            }
        }
    }

    /// D-769: strips, from a serialised `entity_crud::EntityRecordResponse`,
    /// every `lookups` entry into an entity not admitted for `read`. The
    /// record's own `entity_id` names the row entity; the key is removed
    /// when nothing survives, matching the engine's omitted-when-empty shape.
    pub(crate) fn redact_record_lookups(&self, state: &EngineState, record: &mut Value) {
        let row_entity_id = record
            .get("entity_id")
            .and_then(Value::as_str)
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        let Some(row) = record.as_object_mut() else {
            return;
        };
        let emptied = match row.get_mut("lookups").and_then(Value::as_object_mut) {
            Some(lookups) => {
                self.retain_admitted_lookups(state, row_entity_id, lookups);
                lookups.is_empty()
            }
            None => row.contains_key("lookups"),
        };
        if emptied {
            row.remove("lookups");
        }
    }
}

/// Redacts a serialised record for an MCP caller (see
/// [`ReadAdmission::redact_record_lookups`]); a no-op for every other caller.
pub(crate) fn redact_record_for_caller(
    state: &EngineState,
    ctx: &ActionContext,
    record: &mut Value,
) -> Result<(), AppError> {
    if let Some(admission) = ReadAdmission::for_caller(state, ctx)? {
        admission.redact_record_lookups(state, record);
    }
    Ok(())
}

/// The entities a `query.execute` call touches, and the query's linked entity
/// (whose attributes key the rows' `__lookups`).
pub(crate) struct QueryTouched {
    pub(crate) entities: Vec<String>,
    pub(crate) linked_entity_id: Option<uuid::Uuid>,
}

/// The fields of `query_exec::ExecuteQueryRequest` that decide which stored
/// query runs, read from the same arguments. That type's fields are private;
/// unknown fields are ignored here because the executor has already parsed
/// the arguments strictly into the real type before this runs.
#[derive(serde::Deserialize)]
struct QueryTarget {
    #[serde(default)]
    query_id: Option<uuid::Uuid>,
    #[serde(default)]
    view_id: Option<uuid::Uuid>,
    #[serde(default)]
    entity_logical_name: Option<uuid::Uuid>,
    #[serde(default)]
    entity: Option<String>,
    #[serde(default)]
    query_version_id: Option<uuid::Uuid>,
    #[serde(default)]
    related_to: Option<RelatedTarget>,
}

#[derive(serde::Deserialize)]
struct RelatedTarget {
    relationship: String,
}

/// Every entity a `query.execute` call would touch, resolved the way
/// `attome_records::query_exec::execute_stored_query` resolves the query
/// (its private `lookup`, in the same precedence: `query_id`, then `view_id`,
/// then `entity_logical_name`, then `entity`), on the same pinned-aware
/// read-only pool:
///
/// - the query's linked entity (the single-entity branch's root);
/// - every relation in the query's published inventory
///   (`sql_query_version.relations`: the pinned version's when
///   `query_version_id` is given, otherwise the latest — the same row
///   `apply_multi_entity_record_scope` scopes a multi-entity query by);
/// - both sides of a `related_to` relationship.
///
/// An empty result means the query's entities cannot be named (no linked
/// entity and no non-empty inventory), which [`ReadAdmission::require_all`]
/// refuses. A query that does not resolve is `NotFound`, as execution would
/// answer. With no selector at all the list is `Ok(None)`: execution itself
/// refuses that request.
pub(crate) async fn query_touched_entities(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Option<QueryTouched>, AppError> {
    let target: QueryTarget = serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid query.execute arguments: {e}")))?;
    let db = state.base.readonly_query_pool(ctx.security.user_id).await;

    let row: Option<(uuid::Uuid, Option<uuid::Uuid>)> = if let Some(query_id) = target.query_id {
        sqlx::query_as(
            "SELECT id, entity_logical_name FROM sql_query \
             WHERE id = $1 AND is_active = true LIMIT 1",
        )
        .bind(query_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else if let Some(view_id) = target.view_id {
        sqlx::query_as(
            "SELECT q.id, v.entity_logical_name FROM view v \
             JOIN sql_query q ON q.id = v.sql_query_ref \
             WHERE v.id = $1 AND v.is_active = true AND q.is_active = true LIMIT 1",
        )
        .bind(view_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else if let Some(entity_id) = target.entity_logical_name {
        sqlx::query_as(
            "SELECT q.id, v.entity_logical_name FROM view v \
             JOIN sql_query q ON q.id = v.sql_query_ref \
             WHERE v.entity_logical_name = $1 AND v.is_default = true \
               AND v.is_active = true AND q.is_active = true LIMIT 1",
        )
        .bind(entity_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else if let Some(entity) = &target.entity {
        sqlx::query_as(
            "SELECT q.id, v.entity_logical_name FROM view v \
             JOIN sql_query q ON q.id = v.sql_query_ref \
             JOIN entity_info ei ON ei.id = v.entity_logical_name \
             WHERE ei.logicalname = $1 AND v.is_default = true \
               AND v.is_active = true AND q.is_active = true LIMIT 1",
        )
        .bind(entity)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else {
        return Ok(None);
    };
    let (query_id, linked_entity_id) = row.ok_or(AppError::NotFound)?;

    let mut touched: Vec<String> = Vec::new();
    if let Some(entity_id) = linked_entity_id {
        let cached = state
            .entities
            .load()
            .get_by_id(entity_id)
            .map(|meta| meta.logicalname.clone());
        let logicalname = match cached {
            Some(name) => name,
            None => sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1 LIMIT 1")
                .bind(entity_id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
                .ok_or(AppError::NotFound)?,
        };
        touched.push(logicalname);
    }

    let relations: Option<Vec<String>> = match target.query_version_id {
        Some(version_id) => Some(
            sqlx::query_scalar(
                "SELECT relations FROM sql_query_version \
                 WHERE id = $1 AND query_id = $2",
            )
            .bind(version_id)
            .bind(query_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| {
                AppError::Validation("query_version_id does not belong to this query".into())
            })?,
        ),
        None => sqlx::query_scalar(
            "SELECT relations FROM sql_query_version \
             WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(query_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?,
    };
    touched.extend(relations.unwrap_or_default());

    if let Some(related) = &target.related_to {
        let registry = state.relationships.load();
        if let Some(def) = registry.get(&related.relationship).filter(|d| d.is_active) {
            touched.push(def.entity_a.clone());
            touched.push(def.entity_b.clone());
        }
    }

    touched.sort();
    touched.dedup();
    Ok(Some(QueryTouched {
        entities: touched,
        linked_entity_id,
    }))
}

/// Narrows a graph walk to admitted entities. The start node is kept (the
/// executor refused an unadmitted start before walking); every node of an
/// entity that is not admitted is dropped with its edges; and a node that the
/// walk reached only *through* a dropped node is dropped too — otherwise its
/// presence would reveal a connection via a record the agent may not see.
/// Depths are recomputed over the surviving graph, and a node farther than
/// `max_depth` from the start once hidden shortcuts are removed is dropped.
pub(crate) fn filter_traversal(
    outcome: attome_search::graph::TraverseOutcome,
    start: (&str, uuid::Uuid),
    max_depth: u32,
    admits: impl Fn(&str) -> bool,
) -> attome_search::graph::TraverseOutcome {
    use std::collections::{HashMap, VecDeque};

    let attome_search::graph::TraverseOutcome {
        nodes,
        edges,
        truncated,
    } = outcome;
    let key = |entity: &str, id: uuid::Uuid| (entity.to_owned(), id);
    let start_key = key(start.0, start.1);

    let edges: Vec<_> = edges
        .into_iter()
        .filter(|e| admits(&e.from_entity) && admits(&e.to_entity))
        .collect();
    let mut adjacency: HashMap<(String, uuid::Uuid), Vec<(String, uuid::Uuid)>> = HashMap::new();
    for e in &edges {
        let from = key(&e.from_entity, e.from_id);
        let to = key(&e.to_entity, e.to_id);
        adjacency.entry(from.clone()).or_default().push(to.clone());
        adjacency.entry(to).or_default().push(from);
    }

    // Breadth-first from the start over admitted edges only.
    let mut depth_of: HashMap<(String, uuid::Uuid), u32> = HashMap::new();
    depth_of.insert(start_key.clone(), 0);
    let mut queue = VecDeque::from([start_key]);
    while let Some(node) = queue.pop_front() {
        let depth = depth_of[&node];
        if depth >= max_depth {
            continue;
        }
        for next in adjacency.get(&node).into_iter().flatten() {
            if !depth_of.contains_key(next) {
                depth_of.insert(next.clone(), depth + 1);
                queue.push_back(next.clone());
            }
        }
    }

    let nodes = nodes
        .into_iter()
        .filter_map(|mut n| {
            let depth = depth_of.get(&key(&n.entity_logicalname, n.record_id))?;
            n.depth = i32::try_from(*depth).unwrap_or(i32::MAX);
            Some(n)
        })
        .collect();
    let edges = edges
        .into_iter()
        .filter(|e| {
            depth_of.contains_key(&key(&e.from_entity, e.from_id))
                && depth_of.contains_key(&key(&e.to_entity, e.to_id))
        })
        .collect();
    attome_search::graph::TraverseOutcome {
        nodes,
        edges,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::context::tests::security_context;
    use crate::descriptor::RiskTier;

    #[test]
    fn nothing_is_admitted_by_default() {
        let empty = json!({});
        for verb in [Verb::Read, Verb::Create, Verb::Update, Verb::Delete] {
            assert_eq!(classify(&empty, "account", verb), Admission::NotAdmitted);
        }
        assert_eq!(admitted_entity_count(&empty), 0);
    }

    #[test]
    fn a_listed_verb_is_admitted_and_an_unlisted_one_is_not() {
        let setting = json!({ "account": ["read"] });
        assert_eq!(
            classify(&setting, "account", Verb::Read),
            Admission::Admitted
        );
        for verb in [Verb::Create, Verb::Update, Verb::Delete] {
            assert_eq!(classify(&setting, "account", verb), Admission::NotAdmitted);
        }
        assert_eq!(
            classify(&setting, "contact", Verb::Read),
            Admission::NotAdmitted
        );
        assert_eq!(admitted_entity_count(&setting), 1);
    }

    /// A malformed entry never widens: a non-array value, a non-string verb,
    /// a verb outside the closed set, or a non-object setting admits nothing.
    #[test]
    fn a_malformed_setting_admits_nothing() {
        for setting in [
            json!({ "account": "read" }),
            json!({ "account": [1, null, {"read": true}] }),
            json!({ "account": ["READ", "all", "*", "write"] }),
            json!(["account"]),
            json!("account"),
            Value::Null,
        ] {
            assert_eq!(
                classify(&setting, "account", Verb::Read),
                Admission::NotAdmitted,
                "{setting}"
            );
            assert_eq!(admitted_entity_count(&setting), 0, "{setting}");
        }
    }

    /// **MI-3.** Every security-administration, identity, audit and licence
    /// entity is refused even when the setting admits it for every verb.
    #[test]
    fn security_identity_audit_and_licence_entities_are_refused_even_when_admitted() {
        let all = json!(["read", "create", "update", "delete"]);
        let mut names: Vec<String> = EXCLUDED_ENTITIES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        names.extend(
            [
                "audit_header",
                "audit_detail",
                "audit_config",
                "audit_snapshot",
                "s2s_client",
                "s2s_permission",
                "s2s_access_log",
                "user_account_mm_privilege",
                "user_account_mm_team",
            ]
            .map(str::to_owned),
        );
        let setting = Value::Object(names.iter().map(|n| (n.clone(), all.clone())).collect());
        for name in &names {
            for verb in [Verb::Read, Verb::Create, Verb::Update, Verb::Delete] {
                assert!(
                    matches!(classify(&setting, name, verb), Admission::Excluded { .. }),
                    "{name} must be excluded for {verb:?}"
                );
            }
        }
        assert_eq!(
            admitted_entity_count(&setting),
            0,
            "an excluded entity never counts as admitted"
        );
    }

    #[test]
    fn an_ordinary_business_entity_is_not_excluded() {
        for name in ["account", "contact", "service_case", "rw_test_x"] {
            assert_eq!(excluded_reason(name), None, "{name}");
        }
    }

    /// The self-test: every registered `record.*` tool is governed, so a new
    /// record tool cannot reach an entity over MCP without admission.
    #[test]
    fn admission_covers_every_record_tool() {
        let registry = crate::registry::ActionRegistry::new();
        for descriptor in registry.all() {
            let id = descriptor.id.as_str();
            if id.starts_with("record.") {
                assert!(
                    governed_verb(id).is_some(),
                    "{id} is a record tool with no MCP admission entry in GOVERNED_ACTIONS"
                );
            }
        }
        for (id, _) in GOVERNED_ACTIONS {
            assert!(
                registry.resolve(id).is_some(),
                "GOVERNED_ACTIONS names {id}, which is not registered"
            );
        }
    }

    /// Admission is enforced from the action layer: `dispatch` before the
    /// gate, the approved path, and the shared executor tail all call it.
    #[test]
    fn the_action_layer_calls_admission_on_every_path() {
        let source = include_str!("../execute.rs");
        let production = source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        let calls = production.matches("crate::mcp::admission::check(").count();
        assert!(
            calls >= 3,
            "expected admission checks in dispatch, the approved path and run_executor; found {calls}"
        );
        let dispatch = production
            .split_once("pub async fn dispatch(")
            .expect("dispatch exists")
            .1;
        let admission_at = dispatch
            .find("crate::mcp::admission::check(")
            .expect("dispatch checks admission");
        let gate_at = dispatch
            .find("gate::evaluate(")
            .expect("dispatch evaluates the gate");
        assert!(
            admission_at < gate_at,
            "admission must run before the gate, so no confirmation or approval is raised \
             for an unadmitted entity"
        );
    }

    /// Read admission judges `read` only, and excluded entities stay out
    /// whatever the setting lists.
    #[test]
    fn read_admission_needs_read_and_never_admits_an_excluded_entity() {
        let admission = ReadAdmission::from_setting(json!({
            "account": ["read"],
            "contact": ["update"],
            "user_account": ["read"],
            "audit_header": ["read"],
        }));
        assert!(admission.admits("account"));
        assert!(!admission.admits("contact"), "update is not read");
        assert!(!admission.admits("lead"), "not listed");
        assert!(!admission.admits("user_account"), "excluded");
        assert!(!admission.admits("audit_header"), "excluded family");

        let ctx = ActionContext::user(security_context());
        assert!(
            admission
                .require_all("query.execute", &ctx, &["account".into()])
                .is_ok()
        );
        for touched in [
            vec!["account".to_owned(), "lead".to_owned()],
            vec!["account".to_owned(), "user_account".to_owned()],
            Vec::new(),
        ] {
            assert!(
                matches!(
                    admission.require_all("query.execute", &ctx, &touched),
                    Err(AppError::NotFound)
                ),
                "{touched:?}"
            );
        }
    }

    fn node(entity: &str, id: uuid::Uuid, depth: i32) -> attome_search::graph::GraphNode {
        attome_search::graph::GraphNode {
            entity_logicalname: entity.into(),
            record_id: id,
            depth,
        }
    }

    fn edge(from: (&str, uuid::Uuid), to: (&str, uuid::Uuid)) -> attome_search::graph::GraphEdge {
        attome_search::graph::GraphEdge {
            from_entity: from.0.into(),
            from_id: from.1,
            to_entity: to.0.into(),
            to_id: to.1,
            edge_type: "lookup:peer".into(),
        }
    }

    /// A hidden node is dropped with its edges, and so is every node the walk
    /// reached only through it; depths are recomputed without the hidden
    /// shortcut.
    #[test]
    fn a_traversal_never_passes_through_an_unadmitted_node() {
        let a1 = uuid::Uuid::now_v7();
        let a2 = uuid::Uuid::now_v7();
        let a3 = uuid::Uuid::now_v7();
        let hidden = uuid::Uuid::now_v7();
        let user = uuid::Uuid::now_v7();
        // a1 - hidden - a2 (a2 reachable only through the hidden node);
        // a1 - a3 directly; a1 - systemuser (excluded even though listed).
        let outcome = attome_search::graph::TraverseOutcome {
            nodes: vec![
                node("account", a1, 0),
                node("secret", hidden, 1),
                node("user_account", user, 1),
                node("account", a3, 1),
                node("account", a2, 2),
            ],
            edges: vec![
                edge(("account", a1), ("secret", hidden)),
                edge(("account", a2), ("secret", hidden)),
                edge(("account", a1), ("account", a3)),
                edge(("account", a1), ("user_account", user)),
            ],
            truncated: false,
        };
        let admission = ReadAdmission::from_setting(json!({
            "account": ["read"],
            "user_account": ["read"],
        }));
        let filtered = filter_traversal(outcome, ("account", a1), 3, |e| admission.admits(e));
        let ids: Vec<_> = filtered
            .nodes
            .iter()
            .map(|n| (n.record_id, n.depth))
            .collect();
        assert_eq!(ids, vec![(a1, 0), (a3, 1)]);
        assert_eq!(filtered.edges.len(), 1);
        assert_eq!(filtered.edges[0].to_id, a3);
    }

    /// Admitting the intermediate entity restores the path through it.
    #[test]
    fn an_admitted_intermediate_keeps_the_path() {
        let a1 = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        let a2 = uuid::Uuid::now_v7();
        let outcome = attome_search::graph::TraverseOutcome {
            nodes: vec![
                node("account", a1, 0),
                node("b", b, 1),
                node("account", a2, 2),
            ],
            edges: vec![
                edge(("account", a1), ("b", b)),
                edge(("account", a2), ("b", b)),
            ],
            truncated: true,
        };
        let filtered = filter_traversal(outcome, ("account", a1), 2, |_| true);
        assert_eq!(filtered.nodes.len(), 3);
        assert_eq!(filtered.edges.len(), 2);
        assert!(
            filtered.truncated,
            "a bound that cut the walk is still reported"
        );
    }

    /// Each governed read tool's executor consults read admission, and each
    /// named tool is registered.
    #[test]
    fn admission_covers_every_read_tool() {
        let registry = crate::registry::ActionRegistry::new();
        for id in GOVERNED_READ_ACTIONS {
            assert!(
                registry.resolve(id).is_some(),
                "GOVERNED_READ_ACTIONS names {id}, which is not registered"
            );
        }
        for (file, source) in [
            ("actions/read.rs", include_str!("../actions/read.rs")),
            (
                "actions/search_records.rs",
                include_str!("../actions/search_records.rs"),
            ),
            ("actions/graph.rs", include_str!("../actions/graph.rs")),
            (
                "actions/commission.rs",
                include_str!("../actions/commission.rs"),
            ),
            (
                "actions/search_ask.rs",
                include_str!("../actions/search_ask.rs"),
            ),
            ("builder/explain.rs", include_str!("../builder/explain.rs")),
            ("actions/help.rs", include_str!("../actions/help.rs")),
        ] {
            // The test module, not a test-only helper above it.
            let production = source
                .split_once("\n#[cfg(test)]\nmod tests")
                .map_or(source, |(before, _)| before);
            assert!(
                production.contains("admission::ReadAdmission::for_caller("),
                "{file} must consult MCP read admission"
            );
        }
    }

    /// Only an MCP session is governed; every other caller passes through
    /// untouched (the check never needs the settings snapshot for them).
    #[test]
    fn a_non_mcp_caller_is_never_governed() {
        let user = ActionContext::user(security_context());
        assert!(!user.is_mcp_agent());
        let agent = ActionContext::agent(security_context(), RiskTier::Consequential);
        assert!(!agent.is_mcp_agent());
    }
}
