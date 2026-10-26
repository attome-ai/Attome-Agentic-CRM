//! Planning changesets for apply (Solution 7 design §5.2, §5.4).
//!
//! Input: one or more `attome-changeset/v1` documents (the plan route, or the
//! boot path for a compiled platform changeset). Per document:
//!
//! 1. **Parse and check** ([`parse_document`]): format, shape (the Rust
//!    mirror of `validateShape` in `scripts/changesets/lib.mjs`), and the
//!    recomputed JCS checksum ([`super::jcs::document_checksum`]).
//! 2. **Ledger check**: a ledger row with the same `changeset_id` and a
//!    different checksum refuses the whole plan
//!    ([`super::ledger::CHANGESET_CHECKSUM_MISMATCH`]); the same checksum and
//!    `succeeded`/`adopted` reports the changeset `already_applied`.
//! 3. **Order** ([`apply_order`], `applyOrder` in `lib.mjs` is the
//!    reference): `requires.after` plus the implicit previous-number edge per
//!    folder, ties by layer rank, scope, seq. A `requires.after` target
//!    neither in the ledger nor in the batch is `missing_dependency`;
//!    `requires.platform` above this binary is `platform_floor`; a
//!    `requires.modules` entry switched off is `module_off`.
//! 4. **Per operation**: a Phase 2 op, or one this release has no executor
//!    for, is `op_not_supported`; the owner-layer rule against the live row
//!    is `layer_mismatch`; and the bundle planner's own checks and
//!    compare-first diff (`bundle::plan::build_plan` over the objects the
//!    operations fold to, [`Fold`]) give `create | update | noop | blocked`
//!    (field type change, missing lookup target, unknown field type). A
//!    removal is `retire` (or `noop` when the object is already gone).
//! 5. **Persist** one `changeset_apply` row per (changeset, phase)
//!    the document carries, `planned`, with the plan JSON.
//!
//! Folding ([`Fold`]) is also what the applier executes: a role's grants,
//! entity access and profile links, a profile's fields, a state model's
//! transitions and a calendar's holidays and exceptions are set semantics
//! inside their parent's reconcile primitive, so their operations fold onto
//! the parent's current definition (this run's, else the live one) and the
//! parent is reconciled whole.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use attome_core::EngineState;
use attome_core::changeset::{Layer, Op};
use attome_types::AppError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use super::jcs;
use super::ledger::{self, ApplyPhase, ApplySource, ApplyStatus, NewApplyRow};
use crate::bundle::model::*;
use crate::bundle::plan::{PlanAction, PlanOptions, build_plan};
use crate::bundle::{PLATFORM_VERSION, export_bundle};

/// `target.entity` of a multi-entity stored query (no primary entity): the
/// recorder's sentinel, mapped back to `entity: None` here.
pub use attome_records::query_admin::MULTI_ENTITY_QUERY_TARGET;

/// Most documents one plan request carries.
pub const MAX_PLAN_DOCUMENTS: usize = 200;

// ── The parsed document ─────────────────────────────────────────────────────

/// One operation of a checked document.
#[derive(Debug, Clone)]
pub struct DocOp {
    pub seq: i32,
    pub op: Op,
    pub phase: ApplyPhase,
    pub target: Map<String, Value>,
    pub args: Option<Value>,
}

impl DocOp {
    /// `target.<key>` as a string (`""` when absent; the shape check has
    /// already required it).
    pub fn t(&self, key: &str) -> &str {
        self.target.get(key).and_then(Value::as_str).unwrap_or("")
    }

    /// `args.<key>`.
    pub fn arg(&self, key: &str) -> Option<&Value> {
        self.args.as_ref().and_then(|a| a.get(key))
    }

    /// `args.definition` deserialized as `T`.
    pub fn definition<T: DeserializeOwned>(&self) -> Result<T, String> {
        let value = self.arg("definition").cloned().ok_or_else(|| {
            format!(
                "operation {} ({}) has no args.definition",
                self.seq,
                self.op.as_str()
            )
        })?;
        serde_json::from_value(value).map_err(|e| {
            format!(
                "operation {} ({}): args.definition does not match its component shape: {e}",
                self.seq,
                self.op.as_str()
            )
        })
    }

    /// A stored query's entity: `None` for the multi-entity sentinel.
    pub fn query_entity(&self) -> Option<String> {
        let entity = self.t("entity");
        (entity != MULTI_ENTITY_QUERY_TARGET).then(|| entity.to_owned())
    }
}

/// `requires` of a document.
#[derive(Debug, Clone, Default)]
pub struct DocRequires {
    pub platform: String,
    pub after: Vec<String>,
    pub modules: Vec<String>,
}

/// A checked `attome-changeset/v1` document.
#[derive(Debug, Clone)]
pub struct Document {
    /// The document as received (what the ledger stores).
    pub value: Value,
    pub id: Uuid,
    pub layer: Layer,
    pub scope: String,
    pub seq: i32,
    pub name: String,
    pub requires: DocRequires,
    pub checksum: String,
    pub operations: Vec<DocOp>,
}

impl Document {
    /// `<layer>/<scope>/<NNNN>-<name>`.
    pub fn reference(&self) -> String {
        reference(self.layer.as_str(), &self.scope, self.seq, &self.name)
    }

    /// The operations of one phase, in order.
    pub fn ops_of(&self, phase: ApplyPhase) -> Vec<&DocOp> {
        self.operations
            .iter()
            .filter(|o| o.phase == phase)
            .collect()
    }

    /// The phases this document carries operations for.
    pub fn phases(&self) -> Vec<ApplyPhase> {
        [ApplyPhase::Expand, ApplyPhase::Contract]
            .into_iter()
            .filter(|p| self.operations.iter().any(|o| o.phase == *p))
            .collect()
    }

    /// `sha256:` over the JCS `operations` array — what adopt compares with
    /// a local closed changeset's `ops_hash` (design §5.6).
    pub fn ops_hash(&self) -> Result<String, String> {
        let ops = self
            .value
            .get("operations")
            .ok_or_else(|| "the document has no operations".to_owned())?;
        Ok(jcs::sha256_tagged(jcs::canonicalize(ops)?.as_bytes()))
    }
}

pub fn reference(layer: &str, scope: &str, seq: i32, name: &str) -> String {
    format!("{layer}/{scope}/{seq:04}-{name}")
}

/// The `args` keys each op requires (`OPS[op].args` in `lib.mjs`).
pub fn required_args(op: Op) -> &'static [&'static str] {
    match op {
        Op::CreateEntity
        | Op::UpdateEntity
        | Op::AddField
        | Op::UpdateField
        | Op::UpsertRelationship
        | Op::UpsertQuery
        | Op::UpsertView
        | Op::UpsertRule
        | Op::UpsertStateModel
        | Op::UpsertStateTransition
        | Op::UpsertWorkflow
        | Op::UpsertCaseDef
        | Op::UpsertSidebarItem
        | Op::UpsertApp
        | Op::UpsertCalendar
        | Op::AddCalendarHoliday
        | Op::AddCalendarException
        | Op::UpsertCalendarRule
        | Op::UpsertCalendarSeason
        | Op::EnsurePrivilege
        | Op::UpsertRole
        | Op::AddRoleGrantCondition
        | Op::SetEntityDefaultShare
        | Op::UpsertFieldProfile
        | Op::UpsertDataDomain
        | Op::UpsertTheme => &["definition"],
        Op::SetEntityDomain => &["domain"],
        Op::SetEntityMasterData => &["is_master"],
        Op::SetLabel => &["display_name"],
        Op::SetWorkflowDraft => &["graph"],
        Op::GrantRolePrivilege => &["depth"],
        Op::SetRoleEntityAccess => &["access"],
        Op::SetRoleBulkFields => &["fields"],
        Op::SetFieldProfileField => &["permissions"],
        Op::UpsertRecord => &["values"],
        Op::RenameField => &["new_name"],
        Op::ChangeFieldType => &["field_type", "conversion"],
        Op::AddChoiceValue => &["value", "label"],
        Op::RemoveChoiceValue => &["value"],
        Op::SetViewColumns => &["columns"],
        Op::DataStep => &["kind"],
        _ => &[],
    }
}

const TOP_KEYS: &[&str] = &[
    "format",
    "id",
    "layer",
    "scope",
    "seq",
    "name",
    "title",
    "description",
    "requires",
    "author",
    "opened_at",
    "closed_at",
    "checksum",
    "operations",
    "summary",
];
const REQUIRED_TOP: &[&str] = &[
    "format",
    "id",
    "layer",
    "scope",
    "seq",
    "name",
    "title",
    "requires",
    "author",
    "closed_at",
    "checksum",
    "operations",
];

fn is_logical(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36 && Uuid::parse_str(value).is_ok()
}

/// `>=MAJOR.MINOR.PATCH` (or bare) -> the triple.
pub fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let v = value.trim().trim_start_matches(">=").trim();
    let mut parts = v.split('.');
    let triple = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(triple)
}

/// Checks one document's shape and checksum, naming every problem at once.
pub fn parse_document(value: &Value) -> Result<Document, Vec<String>> {
    let mut errs = Vec::new();
    let Some(obj) = value.as_object() else {
        return Err(vec!["a changeset must be a JSON object".into()]);
    };
    for key in REQUIRED_TOP {
        if !obj.contains_key(*key) {
            errs.push(format!("missing required member \"{key}\""));
        }
    }
    for key in obj.keys() {
        if !TOP_KEYS.contains(&key.as_str()) {
            errs.push(format!("unknown member \"{key}\""));
        }
    }
    let str_of = |key: &str| obj.get(key).and_then(Value::as_str).unwrap_or_default();
    if obj.contains_key("format") && str_of("format") != super::FORMAT {
        errs.push(format!("format must be \"{}\"", super::FORMAT));
    }
    let id = Uuid::parse_str(str_of("id"))
        .ok()
        .filter(|u| u.get_version_num() == 7);
    if id.is_none() {
        errs.push("id must be a lowercase UUIDv7".into());
    }
    let layer = Layer::parse(str_of("layer"));
    if layer.is_none() {
        errs.push("layer must be one of platform|product|project|customer".into());
    }
    let scope = str_of("scope").to_owned();
    if !attome_core::changeset::store::is_valid_scope(&scope) {
        errs.push("scope must be lowercase letters and digits joined by - or _".into());
    }
    if layer == Some(Layer::Platform) && scope != "platform" {
        errs.push("a platform changeset has scope \"platform\"".into());
    }
    let seq = obj
        .get("seq")
        .and_then(Value::as_i64)
        .filter(|s| (1..=9999).contains(s))
        .and_then(|s| i32::try_from(s).ok());
    if seq.is_none() {
        errs.push("seq must be an integer 1..9999".into());
    }
    let name = str_of("name").to_owned();
    if !attome_core::changeset::store::is_valid_name(&name) {
        errs.push("name must be kebab-case, at most 60 chars".into());
    }
    let title = str_of("title");
    if title.is_empty() || title.chars().count() > 200 {
        errs.push("title must be a non-empty string, at most 200 chars".into());
    }
    if str_of("author").is_empty() {
        errs.push("author must be a non-empty string".into());
    }
    let checksum = str_of("checksum").to_owned();

    let mut requires = DocRequires::default();
    match obj.get("requires").and_then(Value::as_object) {
        None => errs.push("requires must be an object".into()),
        Some(r) => {
            for key in r.keys() {
                if !["platform", "after", "modules"].contains(&key.as_str()) {
                    errs.push(format!("requires: unknown member \"{key}\""));
                }
            }
            requires.platform = r
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if !requires.platform.starts_with(">=") || parse_version(&requires.platform).is_none() {
                errs.push("requires.platform must be \">=MAJOR.MINOR.PATCH\"".into());
            }
            for (key, out) in [
                ("after", &mut requires.after),
                ("modules", &mut requires.modules),
            ] {
                match r.get(key) {
                    None => {}
                    Some(Value::Array(items)) => {
                        for item in items {
                            match item.as_str() {
                                Some(s) => out.push(s.to_owned()),
                                None => errs.push(format!("requires.{key} holds a non-string")),
                            }
                        }
                    }
                    Some(_) => errs.push(format!("requires.{key} must be an array")),
                }
            }
        }
    }

    let mut operations = Vec::new();
    match obj.get("operations").and_then(Value::as_array) {
        Some(ops) if !ops.is_empty() => {
            for (i, raw) in ops.iter().enumerate() {
                match parse_op(raw, i, layer) {
                    Ok(op) => operations.push(op),
                    Err(mut e) => errs.append(&mut e),
                }
            }
        }
        _ => errs.push("operations must be a non-empty array".into()),
    }

    if errs.is_empty() {
        match jcs::document_checksum(value) {
            Ok(want) if want == checksum => {}
            Ok(want) => errs.push(format!(
                "checksum mismatch (the document says {checksum}, its content is {want}); a \
                 closed changeset is immutable"
            )),
            Err(e) => errs.push(format!("checksum cannot be computed: {e}")),
        }
    }

    match (errs.is_empty(), id, layer, seq) {
        (true, Some(id), Some(layer), Some(seq)) => Ok(Document {
            value: value.clone(),
            id,
            layer,
            scope,
            seq,
            name,
            requires,
            checksum,
            operations,
        }),
        _ => Err(errs),
    }
}

fn parse_op(raw: &Value, index: usize, layer: Option<Layer>) -> Result<DocOp, Vec<String>> {
    let at = format!("operations[{index}]");
    let mut errs = Vec::new();
    let Some(obj) = raw.as_object() else {
        return Err(vec![format!("{at} must be an object")]);
    };
    for key in obj.keys() {
        if !["seq", "op", "phase", "target", "args"].contains(&key.as_str()) {
            errs.push(format!("{at}: unknown member \"{key}\""));
        }
    }
    let seq = obj.get("seq").and_then(Value::as_i64);
    let expected = i64::try_from(index + 1).unwrap_or(i64::MAX);
    if seq != Some(expected) {
        errs.push(format!(
            "{at}.seq must be {expected} (operations are numbered 1..n in order)"
        ));
    }
    let name = obj.get("op").and_then(Value::as_str).unwrap_or_default();
    let Some(op) = Op::parse(name) else {
        errs.push(format!(
            "{at}.op \"{name}\" is not in the v1 operation catalogue"
        ));
        return Err(errs);
    };
    let phase = obj
        .get("phase")
        .and_then(Value::as_str)
        .and_then(ApplyPhase::parse);
    match phase {
        None => errs.push(format!("{at}.phase must be expand|contract")),
        Some(p) if p.as_str() != op.phase().as_str() => errs.push(format!(
            "{at}.phase for {name} must be \"{}\"",
            op.phase().as_str()
        )),
        Some(_) => {}
    }
    let target = obj.get("target").and_then(Value::as_object).cloned();
    match &target {
        None => errs.push(format!("{at}.target must be an object")),
        Some(t) => {
            for key in op.target_keys() {
                if !t.contains_key(*key) {
                    errs.push(format!("{at}.target.{key} is required for {name}"));
                }
            }
            for (key, value) in t {
                if !op.target_keys().contains(&key.as_str()) {
                    errs.push(format!("{at}.target.{key} is not a target key of {name}"));
                }
                if key == "key" {
                    if !value.as_object().is_some_and(|m| !m.is_empty()) {
                        errs.push(format!(
                            "{at}.target.key must be a non-empty business-key object"
                        ));
                    }
                    continue;
                }
                match value.as_str() {
                    Some(s) if !s.is_empty() => {
                        if (key == "entity" || key == "field") && !is_logical(s) {
                            errs.push(format!("{at}.target.{key} must be a logical name"));
                        }
                        if looks_like_uuid(s) {
                            errs.push(format!(
                                "{at}.target.{key} is a UUID; changesets reference objects by \
                                 logical name or business key"
                            ));
                        }
                    }
                    _ => errs.push(format!("{at}.target.{key} must be a non-empty string")),
                }
            }
        }
    }
    let args = obj.get("args").cloned();
    match &args {
        None if !required_args(op).is_empty() => {
            errs.push(format!("{at}.args is required for {name}"));
        }
        None => {}
        Some(Value::Object(a)) => {
            for key in required_args(op) {
                if !a.contains_key(*key) {
                    errs.push(format!("{at}.args.{key} is required for {name}"));
                }
            }
        }
        Some(_) => errs.push(format!("{at}.args must be an object")),
    }
    if layer == Some(Layer::Customer) && customer_forbidden(op) {
        errs.push(format!(
            "{at}: a customer changeset never creates, retires or restructures entities or fields"
        ));
    }
    match (errs.is_empty(), phase, target, seq) {
        (true, Some(phase), Some(target), Some(seq)) => Ok(DocOp {
            seq: i32::try_from(seq).unwrap_or(i32::MAX),
            op,
            phase,
            target,
            args,
        }),
        _ => Err(errs),
    }
}

fn customer_forbidden(op: Op) -> bool {
    matches!(
        op,
        Op::CreateEntity
            | Op::UpdateEntity
            | Op::RetireEntity
            | Op::ReactivateEntity
            | Op::SetEntityDomain
            | Op::SetEntityMasterData
            | Op::AddField
            | Op::RetireField
            | Op::ReactivateField
            | Op::UpsertRelationship
            | Op::RetireRelationship
            | Op::EnsurePrivilege
            | Op::RenameField
            | Op::ChangeFieldType
            | Op::DataStep
            | Op::DeleteField
    )
}

/// Why this release's applier cannot run `op`; `None` when it can.
pub fn unsupported(op: Op) -> Option<&'static str> {
    if op.stage() > attome_core::changeset::model::SUPPORTED_STAGE {
        return Some(
            "op_not_supported: an operation of a later stage; this release cannot apply it",
        );
    }
    match op {
        // Phase 2 ops whose executors land with the data-step lane.
        Op::DataStep => {
            Some("op_not_supported: this release has no executor for this Phase 2 operation yet")
        }
        Op::UpsertWorkflow
        | Op::SetWorkflowDraft
        | Op::PublishWorkflow
        | Op::RetireWorkflow
        | Op::UpsertCaseDef
        | Op::RetireCaseDef => Some(
            "op_not_supported: the workflow and process engines are not reachable from the \
             metadata applier in this release; apply it through their admin API",
        ),
        Op::SetRoleBulkFields
        | Op::SetEntityDefaultShare
        | Op::RemoveEntityDefaultShare
        | Op::UpsertDataDomain
        | Op::PublishRule
        | Op::ClearLabel => Some(
            "op_not_supported: this release has no applier executor for the operation; apply it \
             through the admin API",
        ),
        _ => None,
    }
}

// ── Order ───────────────────────────────────────────────────────────────────

fn layer_rank(layer: Layer) -> usize {
    Layer::ALL
        .iter()
        .position(|l| *l == layer)
        .unwrap_or(usize::MAX)
}

/// Kahn's order over `requires.after` (restricted to the batch) plus the
/// implicit previous-number edge per folder; ties by layer rank, scope, seq.
/// Returns indexes into `docs`.
pub fn apply_order(docs: &[Document]) -> Result<Vec<usize>, String> {
    let refs: HashMap<String, usize> = docs
        .iter()
        .enumerate()
        .map(|(i, d)| (d.reference(), i))
        .collect();
    let deps: Vec<HashSet<usize>> = docs
        .iter()
        .map(|d| {
            let mut out: HashSet<usize> = d
                .requires
                .after
                .iter()
                .filter_map(|r| refs.get(r).copied())
                .collect();
            if let Some(prev) = docs
                .iter()
                .position(|o| o.layer == d.layer && o.scope == d.scope && o.seq == d.seq - 1)
            {
                out.insert(prev);
            }
            out
        })
        .collect();
    let mut done: Vec<bool> = vec![false; docs.len()];
    let mut order = Vec::with_capacity(docs.len());
    while order.len() < docs.len() {
        let next = (0..docs.len())
            .filter(|i| !done[*i] && deps[*i].iter().all(|d| done[*d]))
            .min_by(|a, b| {
                let (x, y) = (&docs[*a], &docs[*b]);
                (layer_rank(x.layer), &x.scope, x.seq).cmp(&(layer_rank(y.layer), &y.scope, y.seq))
            })
            .ok_or_else(|| "requires.after cycle; no apply order exists".to_owned())?;
        done[next] = true;
        order.push(next);
    }
    Ok(order)
}

// ── Folding operations onto definitions ─────────────────────────────────────

/// `set_view_columns`'s `args.columns` (design §3.7): the whole
/// `table_definition`, a non-empty array of column objects, each with a
/// logical `name`, no name twice. Anything else refuses the operation.
fn view_columns(op: &DocOp) -> Result<Value, String> {
    let bad = |why: &str| {
        format!(
            "operation {} (set_view_columns): args.columns {why}",
            op.seq
        )
    };
    let columns = op
        .arg("columns")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| bad("must be a non-empty array"))?;
    let mut seen = HashSet::new();
    for column in columns {
        let name = column
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| is_logical(n))
            .ok_or_else(|| bad("items must be objects with a logical `name`"))?;
        if !seen.insert(name) {
            return Err(bad(&format!("lists \"{name}\" twice")));
        }
    }
    Ok(Value::Array(columns.clone()))
}

/// A system view's default sort is the `ORDER BY` of its stored query's SQL;
/// `view` has no sort of its own. A `set_view_columns` that carries
/// `sort` therefore cannot be applied as a view change (design §3.7): change
/// the query (`upsert_query`) instead.
pub fn view_sort_refusal(op: &DocOp) -> Option<&'static str> {
    (op.op == Op::SetViewColumns && op.arg("sort").is_some_and(|s| !s.is_null())).then_some(
        "view_sort_in_query: a system view's default sort lives in its stored query's SQL; \
         change the sort with upsert_query and set only the columns here",
    )
}

fn replace_or_push<T, K: PartialEq>(list: &mut Vec<T>, item: T, key: impl Fn(&T) -> K) {
    let k = key(&item);
    match list.iter_mut().find(|x| key(x) == k) {
        Some(slot) => *slot = item,
        None => list.push(item),
    }
}

/// The condition key the recorder writes (`field|operator|value`).
pub fn condition_key(c: &GrantCondition) -> String {
    format!("{}|{}|{}", c.field, c.operator, c.value)
}

/// The desired state of the objects a run of operations touches, folded onto
/// `base` (this run's earlier results, seeded by the caller) and then the
/// `live` export. Only touched objects are in `out`.
pub struct Fold<'a> {
    live: &'a Bundle,
    pub out: Bundle,
}

impl std::fmt::Debug for Fold<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fold").finish_non_exhaustive()
    }
}

fn empty_bundle() -> Bundle {
    Bundle::empty(Requires {
        platform_version: ">=0.0.0".into(),
        schema_version: 0,
        modules: Vec::new(),
        depends_on_bundles: Vec::new(),
    })
}

impl<'a> Fold<'a> {
    pub fn new(live: &'a Bundle) -> Self {
        Self {
            live,
            out: empty_bundle(),
        }
    }

    /// Starts from `seed` (objects this run already reconciled).
    pub fn seeded(live: &'a Bundle, seed: Bundle) -> Self {
        Self { live, out: seed }
    }

    fn role(&mut self, name: &str, op: &DocOp) -> Result<&mut RoleDef, String> {
        if !self.out.roles.iter().any(|r| r.name == name) {
            let base = self
                .live
                .roles
                .iter()
                .find(|r| r.name == name)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "operation {} ({}): role \"{name}\" is neither live nor upserted earlier",
                        op.seq,
                        op.op.as_str()
                    )
                })?;
            self.out.roles.push(base);
        }
        self.out
            .roles
            .iter_mut()
            .find(|r| r.name == name)
            .ok_or_else(|| "role vanished".to_owned())
    }

    fn profile(&mut self, name: &str, op: &DocOp) -> Result<&mut FieldSecurityProfileDef, String> {
        if !self
            .out
            .field_security_profiles
            .iter()
            .any(|p| p.name == name)
        {
            let base = self
                .live
                .field_security_profiles
                .iter()
                .find(|p| p.name == name)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "operation {} ({}): field-security profile \"{name}\" is neither live nor \
                         upserted earlier",
                        op.seq,
                        op.op.as_str()
                    )
                })?;
            self.out.field_security_profiles.push(base);
        }
        self.out
            .field_security_profiles
            .iter_mut()
            .find(|p| p.name == name)
            .ok_or_else(|| "profile vanished".to_owned())
    }

    fn model(&mut self, entity: &str, op: &DocOp) -> Result<&mut StateModelDef, String> {
        if !self
            .out
            .state_models
            .iter()
            .any(|m| m.entity_logicalname == entity)
        {
            let base = self
                .live
                .state_models
                .iter()
                .find(|m| m.entity_logicalname == entity)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "operation {} ({}): no state model for \"{entity}\" is live or upserted \
                         earlier",
                        op.seq,
                        op.op.as_str()
                    )
                })?;
            self.out.state_models.push(base);
        }
        self.out
            .state_models
            .iter_mut()
            .find(|m| m.entity_logicalname == entity)
            .ok_or_else(|| "state model vanished".to_owned())
    }

    fn calendar(&mut self, name: &str, op: &DocOp) -> Result<&mut CalendarDef, String> {
        if !self.out.calendars.iter().any(|c| c.name == name) {
            let base = self
                .live
                .calendars
                .iter()
                .find(|c| c.name == name)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "operation {} ({}): calendar \"{name}\" is neither live nor upserted \
                         earlier",
                        op.seq,
                        op.op.as_str()
                    )
                })?;
            self.out.calendars.push(base);
        }
        self.out
            .calendars
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| "calendar vanished".to_owned())
    }

    /// Folds one operation. Removals fold too (a revoke leaves the grant out
    /// of the role). Operations with no bundle component (workflow, labels,
    /// domains, …) are not folded.
    pub fn apply(&mut self, op: &DocOp) -> Result<(), String> {
        match op.op {
            Op::CreateEntity | Op::UpdateEntity => {
                let mut def: EntityDef = op.definition()?;
                let attributes = self
                    .out
                    .entities
                    .iter()
                    .find(|e| e.logicalname == def.logicalname)
                    .map(|e| e.attributes.clone())
                    .unwrap_or_default();
                def.attributes = attributes;
                replace_or_push(&mut self.out.entities, def, |e| e.logicalname.clone());
            }
            Op::AddField | Op::UpdateField => {
                let attr: AttributeDef = op.definition()?;
                let entity = op.t("entity");
                match self
                    .out
                    .entities
                    .iter_mut()
                    .find(|e| e.logicalname == entity)
                {
                    Some(e) => replace_or_push(&mut e.attributes, attr, |a| a.logicalname.clone()),
                    None => replace_or_push(
                        &mut self.out.attribute_patches,
                        AttributePatch {
                            entity: entity.to_owned(),
                            attribute: attr,
                        },
                        |p| (p.entity.clone(), p.attribute.logicalname.clone()),
                    ),
                }
            }
            Op::UpsertRelationship => {
                let def: RelationshipDef = op.definition()?;
                replace_or_push(&mut self.out.relationships, def, |r| r.name.clone());
            }
            Op::UpsertQuery => {
                let mut def: QueryDef = op.definition()?;
                def.entity = op.query_entity();
                replace_or_push(&mut self.out.queries, def, QueryDef::key);
            }
            Op::UpsertView => {
                let def: ViewDef = op.definition()?;
                replace_or_push(&mut self.out.views, def, |v| {
                    (v.entity.clone(), v.name.clone())
                });
            }
            Op::SetViewColumns => {
                let columns = view_columns(op)?;
                let (entity, name) = (op.t("entity"), op.t("view"));
                let same = |v: &&ViewDef| v.entity == entity && v.name == name;
                let mut view = self
                    .out
                    .views
                    .iter()
                    .find(same)
                    .or_else(|| self.live.views.iter().find(same))
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "operation {} (set_view_columns): view \"{name}\" on \"{entity}\" is \
                             neither live nor upserted earlier",
                            op.seq
                        )
                    })?;
                view.table_definition = columns;
                replace_or_push(&mut self.out.views, view, |v| {
                    (v.entity.clone(), v.name.clone())
                });
            }
            Op::UpsertRule => {
                let def: RuleDef = op.definition()?;
                replace_or_push(&mut self.out.rules, def, RuleDef::key);
            }
            Op::UpsertStateModel => {
                let mut def: StateModelDef = op.definition()?;
                def.transitions = self
                    .out
                    .state_models
                    .iter()
                    .find(|m| m.entity_logicalname == def.entity_logicalname)
                    .or_else(|| {
                        self.live
                            .state_models
                            .iter()
                            .find(|m| m.entity_logicalname == def.entity_logicalname)
                    })
                    .map(|m| m.transitions.clone())
                    .unwrap_or_default();
                replace_or_push(&mut self.out.state_models, def, |m| {
                    m.entity_logicalname.clone()
                });
            }
            Op::UpsertStateTransition => {
                let def: StateTransitionDef = op.definition()?;
                let model = self.model(op.t("entity"), op)?;
                replace_or_push(&mut model.transitions, def, |t| {
                    (t.from_state.clone(), t.to_state.clone())
                });
            }
            Op::RetireStateTransition => {
                let key = op.t("transition").to_owned();
                let model = self.model(op.t("entity"), op)?;
                model
                    .transitions
                    .retain(|t| format!("{}->{}", t.from_state, t.to_state) != key);
            }
            Op::UpsertSidebarItem => {
                let def: SidebarDef = op.definition()?;
                replace_or_push(&mut self.out.sidebar, def, |s| s.path.clone());
            }
            Op::UpsertApp => {
                let def: AppDef = op.definition()?;
                replace_or_push(&mut self.out.apps, def, |a| a.name.clone());
            }
            Op::UpsertCalendar => {
                let mut def: CalendarDef = op.definition()?;
                let base = self
                    .out
                    .calendars
                    .iter()
                    .find(|c| c.name == def.name)
                    .or_else(|| self.live.calendars.iter().find(|c| c.name == def.name));
                def.holidays = base.map(|c| c.holidays.clone()).unwrap_or_default();
                def.exceptions = base.and_then(|c| c.exceptions.clone());
                // Z12-T6: rules and seasons ride their own ops.
                def.rules = base.and_then(|c| c.rules.clone());
                def.seasons = base.and_then(|c| c.seasons.clone());
                replace_or_push(&mut self.out.calendars, def, |c| c.name.clone());
            }
            Op::UpsertCalendarRule => {
                let def: HolidayRuleDef = op.definition()?;
                let cal = self.calendar(op.t("calendar"), op)?;
                replace_or_push(cal.rules.get_or_insert_with(Vec::new), def, |r| {
                    r.name.clone()
                });
            }
            Op::RetireCalendarRule => {
                let name = op.t("rule").to_owned();
                let cal = self.calendar(op.t("calendar"), op)?;
                cal.rules
                    .get_or_insert_with(Vec::new)
                    .retain(|r| r.name != name);
            }
            Op::UpsertCalendarSeason => {
                let def: SeasonDef = op.definition()?;
                let cal = self.calendar(op.t("calendar"), op)?;
                replace_or_push(cal.seasons.get_or_insert_with(Vec::new), def, |s| {
                    s.name.clone()
                });
            }
            Op::RetireCalendarSeason => {
                let name = op.t("season").to_owned();
                let cal = self.calendar(op.t("calendar"), op)?;
                cal.seasons
                    .get_or_insert_with(Vec::new)
                    .retain(|s| s.name != name);
            }
            Op::AddCalendarHoliday => {
                let def: HolidayDef = op.definition()?;
                let cal = self.calendar(op.t("calendar"), op)?;
                replace_or_push(&mut cal.holidays, def, |h| h.holiday_date);
            }
            Op::RemoveCalendarHoliday => {
                let date = op.t("date").to_owned();
                let cal = self.calendar(op.t("calendar"), op)?;
                cal.holidays.retain(|h| h.holiday_date.to_string() != date);
            }
            Op::AddCalendarException => {
                let def: CalendarExceptionDef = op.definition()?;
                let cal = self.calendar(op.t("calendar"), op)?;
                replace_or_push(cal.exceptions.get_or_insert_with(Vec::new), def, |x| {
                    x.exception_date
                });
            }
            Op::RemoveCalendarException => {
                let date = op.t("exception").to_owned();
                let cal = self.calendar(op.t("calendar"), op)?;
                if let Some(list) = cal.exceptions.as_mut() {
                    list.retain(|x| x.exception_date.to_string() != date);
                }
            }
            Op::EnsurePrivilege => {
                let def: PrivilegeDef = op.definition()?;
                replace_or_push(&mut self.out.privileges, def, |p| p.key.clone());
            }
            Op::UpsertRole => {
                let mut def: RoleDef = op.definition()?;
                let base = self
                    .out
                    .roles
                    .iter()
                    .find(|r| r.name == def.name)
                    .or_else(|| self.live.roles.iter().find(|r| r.name == def.name));
                if let Some(base) = base {
                    def.privileges = base.privileges.clone();
                    def.entity_access = base.entity_access.clone();
                    def.field_security_profiles = base.field_security_profiles.clone();
                }
                replace_or_push(&mut self.out.roles, def, |r| r.name.clone());
            }
            Op::GrantRolePrivilege => {
                let privilege = op.t("privilege").to_owned();
                let role = self.role(op.t("role"), op)?;
                if !role.privileges.iter().any(|g| g.privilege == privilege) {
                    role.privileges.push(RoleGrant {
                        privilege,
                        conditions: Vec::new(),
                    });
                }
            }
            Op::RevokeRolePrivilege => {
                let privilege = op.t("privilege").to_owned();
                let role = self.role(op.t("role"), op)?;
                role.privileges.retain(|g| g.privilege != privilege);
            }
            Op::AddRoleGrantCondition => {
                let condition: GrantCondition = op.definition()?;
                let privilege = op.t("privilege").to_owned();
                let role = self.role(op.t("role"), op)?;
                let grant = match role
                    .privileges
                    .iter()
                    .position(|g| g.privilege == privilege)
                {
                    Some(i) => &mut role.privileges[i],
                    None => {
                        role.privileges.push(RoleGrant {
                            privilege,
                            conditions: Vec::new(),
                        });
                        let last = role.privileges.len() - 1;
                        &mut role.privileges[last]
                    }
                };
                if !grant.conditions.contains(&condition) {
                    grant.conditions.push(condition);
                }
            }
            Op::RemoveRoleGrantCondition => {
                let key = op.t("condition").to_owned();
                let privilege = op.t("privilege").to_owned();
                let role = self.role(op.t("role"), op)?;
                if let Some(grant) = role
                    .privileges
                    .iter_mut()
                    .find(|g| g.privilege == privilege)
                {
                    grant.conditions.retain(|c| condition_key(c) != key);
                }
            }
            Op::SetRoleEntityAccess => {
                let mut access = op
                    .arg("access")
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or_else(|| {
                        format!("operation {}: args.access must be an object", op.seq)
                    })?;
                access.insert("entity".into(), Value::String(op.t("entity").to_owned()));
                let access: RoleEntityAccess = serde_json::from_value(Value::Object(access))
                    .map_err(|e| {
                        format!(
                            "operation {} (set_role_entity_access): args.access does not match \
                             the role entity access shape: {e}",
                            op.seq
                        )
                    })?;
                let role = self.role(op.t("role"), op)?;
                replace_or_push(&mut role.entity_access, access, |a| a.entity.clone());
            }
            Op::ClearRoleEntityAccess => {
                let entity = op.t("entity").to_owned();
                let role = self.role(op.t("role"), op)?;
                role.entity_access.retain(|a| a.entity != entity);
            }
            Op::AssignFieldProfile => {
                let profile = op.t("profile").to_owned();
                let role = self.role(op.t("role"), op)?;
                if !role.field_security_profiles.contains(&profile) {
                    role.field_security_profiles.push(profile);
                }
            }
            Op::UnassignFieldProfile => {
                let profile = op.t("profile").to_owned();
                let role = self.role(op.t("role"), op)?;
                role.field_security_profiles.retain(|p| *p != profile);
            }
            Op::UpsertFieldProfile => {
                let mut def: FieldSecurityProfileDef = op.definition()?;
                def.fields = self
                    .out
                    .field_security_profiles
                    .iter()
                    .find(|p| p.name == def.name)
                    .or_else(|| {
                        self.live
                            .field_security_profiles
                            .iter()
                            .find(|p| p.name == def.name)
                    })
                    .map(|p| p.fields.clone())
                    .unwrap_or_default();
                replace_or_push(&mut self.out.field_security_profiles, def, |p| {
                    p.name.clone()
                });
            }
            Op::SetFieldProfileField => {
                let perms = op.arg("permissions");
                let flag = |k: &str| perms.and_then(|p| p.get(k)).and_then(Value::as_bool);
                let (Some(can_read), Some(can_update)) = (flag("can_read"), flag("can_update"))
                else {
                    return Err(format!(
                        "operation {} (set_field_profile_field): args.permissions needs boolean \
                         can_read and can_update",
                        op.seq
                    ));
                };
                let field = ProfileField {
                    entity: op.t("entity").to_owned(),
                    field: op.t("field").to_owned(),
                    can_read,
                    can_update,
                };
                let profile = self.profile(op.t("profile"), op)?;
                replace_or_push(&mut profile.fields, field, |f| {
                    (f.entity.clone(), f.field.clone())
                });
            }
            Op::UpsertRecord => {
                let (key_fields, row) = record_parts(op)?;
                let entity = op.t("entity").to_owned();
                match self
                    .out
                    .record_sets
                    .iter_mut()
                    .find(|rs| rs.entity == entity && rs.key_fields == key_fields)
                {
                    Some(rs) => rs.rows.push(row),
                    None => self.out.record_sets.push(RecordSet {
                        entity,
                        key_fields,
                        rows: vec![row],
                    }),
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// An `upsert_record`'s key fields (declared order: `args.key_fields`, else
/// `target.key`'s members) and full row (`args.values` plus the key).
pub fn record_parts(op: &DocOp) -> Result<(Vec<String>, Map<String, Value>), String> {
    let key = op
        .target
        .get("key")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let key_fields: Vec<String> = match op.arg("key_fields").and_then(Value::as_array) {
        Some(list) => list
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("operation {}: args.key_fields must be strings", op.seq))?,
        None => key.keys().cloned().collect(),
    };
    let mut row = op
        .arg("values")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| format!("operation {}: args.values must be an object", op.seq))?;
    for (k, v) in key {
        row.entry(k).or_insert(v);
    }
    Ok((key_fields, row))
}

// ── Classification ──────────────────────────────────────────────────────────

/// One operation's line in a plan.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlannedOp {
    pub seq: i32,
    pub op: String,
    pub phase: ApplyPhase,
    #[schema(value_type = Object)]
    pub target: Value,
    /// `create`, `update`, `retire`, `noop` or `blocked`.
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Phase 1 criteria: a contract operation, or a field made required.
    pub risky: bool,
}

/// One (changeset, phase)'s plan.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlannedPhase {
    pub phase: ApplyPhase,
    /// The ledger row; `None` for a changeset that is already applied or
    /// blocked before any row was written.
    pub apply_id: Option<Uuid>,
    pub status: String,
    /// Nothing in this phase is blocked.
    pub applicable: bool,
    pub operations: Vec<PlannedOp>,
}

/// One changeset's plan.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlannedChangeset {
    pub changeset_id: Uuid,
    #[serde(rename = "ref")]
    pub changeset_ref: String,
    pub layer: String,
    pub scope: String,
    pub seq: i32,
    pub checksum: String,
    /// `planned`, `already_applied` or `blocked`.
    pub status: String,
    /// Changeset-level blocks (`missing_dependency`, `platform_floor`,
    /// `module_off`).
    pub blocked: Vec<String>,
    pub phases: Vec<PlannedPhase>,
}

/// `POST /api/v1/admin/metadata/changesets/plan`'s response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChangesetPlan {
    /// In apply order.
    pub changesets: Vec<PlannedChangeset>,
    /// Every planned expand row, in apply order — what `apply` takes for
    /// `phase = expand`.
    pub apply_ids: Vec<Uuid>,
    /// Every contract row, in apply order.
    pub contract_apply_ids: Vec<Uuid>,
    /// Nothing is blocked anywhere.
    pub applicable: bool,
}

/// How a plan is made.
#[derive(Debug, Clone, Copy)]
pub struct PlanContext {
    pub source: ApplySource,
    pub requested_by: Option<Uuid>,
    /// Boot applies the platform's own definitions: no owner-layer check
    /// (every row is `project` until the stamp step has run) and no module
    /// check (D-383: the platform schema is provisioned whatever the
    /// licence says).
    pub trusted: bool,
}

/// The planner's result before it is persisted.
pub struct Planned {
    pub docs: Vec<Document>,
    pub plan: ChangesetPlan,
}

impl std::fmt::Debug for Planned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Planned").finish_non_exhaustive()
    }
}

/// The Phase 2 field ops (D-788): planned against live metadata by
/// [`crate::field_changes::plan_field_op`], executed by
/// [`crate::field_changes::apply_field_op`].
pub fn is_field_op(op: Op) -> bool {
    matches!(
        op,
        Op::RenameField
            | Op::DeleteField
            | Op::ChangeFieldType
            | Op::AddChoiceValue
            | Op::RemoveChoiceValue
    )
}

fn risky(op: &DocOp) -> bool {
    op.phase == ApplyPhase::Contract
        || matches!(
            op.op,
            Op::RenameField | Op::DeleteField | Op::ChangeFieldType
        )
        || (matches!(op.op, Op::AddField | Op::UpdateField)
            && op
                .arg("definition")
                .and_then(|d| d.get("is_required"))
                .and_then(Value::as_bool)
                .unwrap_or(false))
}

/// The component plan line an expand operation maps to.
fn component_key(op: &DocOp) -> Option<(&'static str, String)> {
    Some(match op.op {
        Op::CreateEntity | Op::UpdateEntity => (COMPONENT_ENTITY, op.t("entity").to_owned()),
        Op::AddField | Op::UpdateField => (
            COMPONENT_ATTRIBUTE,
            format!("{}.{}", op.t("entity"), op.t("field")),
        ),
        Op::UpsertRelationship => (COMPONENT_RELATIONSHIP, op.t("relationship").to_owned()),
        Op::UpsertQuery => (
            COMPONENT_QUERY,
            QueryRef {
                entity: op.query_entity(),
                name: op.t("query").to_owned(),
            }
            .display(),
        ),
        Op::UpsertView | Op::SetViewColumns => (
            COMPONENT_VIEW,
            format!("{}.{}", op.t("entity"), op.t("view")),
        ),
        Op::UpsertRule => (
            COMPONENT_RULE,
            format!("{}:{}", op.t("entity"), op.t("rule")),
        ),
        Op::UpsertStateModel | Op::UpsertStateTransition | Op::RetireStateTransition => {
            (COMPONENT_STATE_MODEL, op.t("entity").to_owned())
        }
        Op::UpsertSidebarItem => (COMPONENT_SIDEBAR, op.t("path").to_owned()),
        Op::UpsertApp => (COMPONENT_APP, op.t("app").to_owned()),
        Op::UpsertCalendar
        | Op::AddCalendarHoliday
        | Op::RemoveCalendarHoliday
        | Op::AddCalendarException
        | Op::RemoveCalendarException
        | Op::UpsertCalendarRule
        | Op::RetireCalendarRule
        | Op::UpsertCalendarSeason
        | Op::RetireCalendarSeason => (COMPONENT_CALENDAR, op.t("calendar").to_owned()),
        Op::EnsurePrivilege => (COMPONENT_PRIVILEGE, op.t("privilege").to_owned()),
        Op::UpsertRole
        | Op::GrantRolePrivilege
        | Op::RevokeRolePrivilege
        | Op::AddRoleGrantCondition
        | Op::RemoveRoleGrantCondition
        | Op::SetRoleEntityAccess
        | Op::ClearRoleEntityAccess
        | Op::AssignFieldProfile
        | Op::UnassignFieldProfile => (COMPONENT_ROLE, op.t("role").to_owned()),
        Op::UpsertFieldProfile | Op::SetFieldProfileField => {
            (COMPONENT_FIELD_SECURITY_PROFILE, op.t("profile").to_owned())
        }
        Op::UpsertRecord => {
            let (key_fields, row) = record_parts(op).ok()?;
            (
                COMPONENT_RECORD,
                crate::bundle::record_key(op.t("entity"), &key_fields, &row),
            )
        }
        _ => return None,
    })
}

/// Whether a removal's object is live (`retire`) or already gone (`noop`).
fn removal_is_live(live: &Bundle, op: &DocOp) -> bool {
    match op.op {
        Op::RetireEntity => live
            .entities
            .iter()
            .any(|e| e.logicalname == op.t("entity")),
        Op::RetireField => live.entities.iter().any(|e| {
            e.logicalname == op.t("entity")
                && e.attributes.iter().any(|a| a.logicalname == op.t("field"))
        }),
        Op::RetireRelationship => live
            .relationships
            .iter()
            .any(|r| r.name == op.t("relationship")),
        Op::RetireQuery => {
            let entity = op.query_entity();
            live.queries
                .iter()
                .any(|q| q.entity == entity && q.name == op.t("query"))
        }
        Op::RetireView => live
            .views
            .iter()
            .any(|v| v.entity == op.t("entity") && v.name == op.t("view")),
        Op::RetireRule => live
            .rules
            .iter()
            .any(|r| r.entity_logicalname == op.t("entity") && r.name == op.t("rule")),
        Op::RetireStateModel => live
            .state_models
            .iter()
            .any(|m| m.entity_logicalname == op.t("entity")),
        Op::RetireSidebarItem => live
            .sidebar
            .iter()
            .any(|s| s.path_display() == op.t("path")),
        Op::RetireApp => live.apps.iter().any(|a| a.name == op.t("app")),
        Op::RetireCalendar => live.calendars.iter().any(|c| c.name == op.t("calendar")),
        _ => true,
    }
}

/// D-791 rule 2: an `upsert_rule`/`retire_rule` on a customer-layer rule is
/// not a `layer_mismatch` (the developer may change any rule).
fn customer_rule_open_to_us(op: Op, owner: &str) -> bool {
    matches!(op, Op::UpsertRule | Op::RetireRule) && owner == Layer::Customer.as_str()
}

/// The plan note of a customer-rule operation the apply would keep as a
/// conflict (D-791 rule 2, Topic 14).
pub const CUSTOMER_RULE_CONFLICT: &str = "conflict: the customer changed this rule since our last \
     release; the apply keeps their version and the release report offers Use mine";

/// D-791 rule 2 + Topic 14, plan side: [`CUSTOMER_RULE_CONFLICT`] when
/// applying this rule operation now would keep the customer's version, else
/// `None`. Read-only, never a block; the apply decides again
/// (`rule_admin::reconcile_rule` / `retire_rule`). A definition that does not
/// resolve here is left to the apply's own validation.
async fn customer_rule_conflict(
    conn: &mut PgConnection,
    op: &DocOp,
) -> Result<Option<String>, AppError> {
    let would = match op.op {
        Op::UpsertRule => match op.definition::<RuleDef>() {
            Ok(def) => match crate::rule_admin::upsert_would_conflict(conn, &def).await {
                Ok(would) => would,
                Err(AppError::Validation(_)) | Err(AppError::NotFound) => false,
                Err(e) => return Err(e),
            },
            Err(_) => false,
        },
        Op::RetireRule => {
            crate::rule_admin::retire_would_conflict(conn, op.t("entity"), op.t("rule")).await?
        }
        _ => false,
    };
    Ok(would.then(|| CUSTOMER_RULE_CONFLICT.to_owned()))
}

/// The `owner_layer` of the live row an operation changes (update, retire,
/// reactivate), for the owner-layer rule (design §1). `None`: no such row
/// (a create), or a kind this check does not cover (child rows: a project
/// changeset may add a grant to a platform role).
async fn row_layer(conn: &mut PgConnection, op: &DocOp) -> Result<Option<String>, AppError> {
    let one = |sql: &'static str| sql;
    let (sql, binds): (&str, Vec<Option<String>>) = match op.op {
        Op::UpdateEntity
        | Op::CreateEntity
        | Op::RetireEntity
        | Op::ReactivateEntity
        | Op::SetEntityDomain
        | Op::SetEntityMasterData => (
            one(
                "SELECT owner_layer FROM entity_info WHERE logicalname = $1 \
                 ORDER BY (is_active IS NULL OR is_active = true) DESC LIMIT 1",
            ),
            vec![Some(op.t("entity").into())],
        ),
        Op::AddField
        | Op::UpdateField
        | Op::RetireField
        | Op::ReactivateField
        | Op::RenameField
        | Op::DeleteField
        | Op::ChangeFieldType
        | Op::AddChoiceValue
        | Op::RemoveChoiceValue => (
            one("SELECT a.owner_layer FROM attribute_info a \
                 JOIN entity_info e ON e.id = a.entity_ref \
                 WHERE e.logicalname = $1 AND a.logicalname = $2 \
                 ORDER BY (a.is_active IS NULL OR a.is_active = true) DESC LIMIT 1"),
            vec![Some(op.t("entity").into()), Some(op.t("field").into())],
        ),
        Op::UpsertRelationship | Op::RetireRelationship => (
            one("SELECT owner_layer FROM relationship_info \
                 WHERE name = $1 AND is_deleted = false LIMIT 1"),
            vec![Some(op.t("relationship").into())],
        ),
        Op::UpsertView | Op::RetireView | Op::SetViewColumns => (
            one("SELECT v.owner_layer FROM view v \
                 JOIN entity_info e ON e.id = v.entity_logical_name \
                 WHERE e.logicalname = $1 AND v.name = $2 AND v.scope = 'system' \
                   AND v.is_active = true LIMIT 1"),
            vec![Some(op.t("entity").into()), Some(op.t("view").into())],
        ),
        Op::UpsertQuery | Op::RetireQuery => (
            one("SELECT q.owner_layer FROM sql_query q \
                 LEFT JOIN entity_info e ON e.id = q.entity_logical_name \
                 WHERE q.record_no = $2 AND COALESCE(q.is_active, true) = true \
                   AND (($1::text IS NULL AND q.entity_logical_name IS NULL) \
                        OR e.logicalname = $1) LIMIT 1"),
            vec![op.query_entity(), Some(op.t("query").into())],
        ),
        Op::UpsertRule | Op::RetireRule => (
            one(
                "SELECT owner_layer FROM rule WHERE entity_logicalname = $1 \
                 AND name = $2 AND is_deleted = false LIMIT 1",
            ),
            vec![Some(op.t("entity").into()), Some(op.t("rule").into())],
        ),
        Op::UpsertApp | Op::RetireApp => (
            one(
                "SELECT owner_layer FROM app WHERE name = $1 AND is_deleted = false \
                 LIMIT 1",
            ),
            vec![Some(op.t("app").into())],
        ),
        Op::UpsertCalendar | Op::RetireCalendar => (
            one(
                "SELECT owner_layer FROM calendar WHERE name = $1 AND is_active = true \
                 LIMIT 1",
            ),
            vec![Some(op.t("calendar").into())],
        ),
        Op::UpsertRole => (
            one(
                "SELECT owner_layer FROM role WHERE name = $1 AND is_deleted = false \
                 LIMIT 1",
            ),
            vec![Some(op.t("role").into())],
        ),
        Op::UpsertFieldProfile => (
            one(
                "SELECT owner_layer FROM field_security_profile WHERE name = $1 \
                 AND is_deleted = false LIMIT 1",
            ),
            vec![Some(op.t("profile").into())],
        ),
        Op::UpsertStateModel | Op::RetireStateModel => (
            one(
                "SELECT owner_layer FROM state_model WHERE entity_logicalname = $1 \
                 AND record_type IS NULL AND is_deleted = false LIMIT 1",
            ),
            vec![Some(op.t("entity").into())],
        ),
        _ => return Ok(None),
    };
    let mut query = sqlx::query_scalar::<_, String>(sql);
    for bind in binds {
        query = query.bind(bind);
    }
    query
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// `create_entity`/`add_field` of an object that does not exist yet is a
/// create; checking its layer is meaningless, and the ops that name only an
/// existing row are the ones the rule covers.
fn is_create_only(op: Op) -> bool {
    matches!(op, Op::CreateEntity | Op::AddField)
}

/// The module keys switched off on this deployment among `modules`.
fn modules_off(state: &EngineState, modules: &[String]) -> Vec<String> {
    let license = state.modules.load();
    modules
        .iter()
        .filter(|m| {
            attome_modules::MODULE_MAP
                .iter()
                .find(|(name, _)| *name == m.as_str())
                .is_none_or(|(_, id)| !license.has(*id))
        })
        .cloned()
        .collect()
}

/// Upserts `desired`'s touched components into `into` (the simulated live
/// state the next changeset of the batch is planned against).
fn merge_into(into: &mut Bundle, desired: &Bundle) {
    for e in &desired.entities {
        match into
            .entities
            .iter_mut()
            .find(|x| x.logicalname == e.logicalname)
        {
            Some(x) => {
                let mut attrs = x.attributes.clone();
                for a in &e.attributes {
                    replace_or_push(&mut attrs, a.clone(), |y| y.logicalname.clone());
                }
                *x = EntityDef {
                    attributes: attrs,
                    ..e.clone()
                };
            }
            None => into.entities.push(e.clone()),
        }
    }
    for p in &desired.attribute_patches {
        if let Some(x) = into.entities.iter_mut().find(|x| x.logicalname == p.entity) {
            replace_or_push(&mut x.attributes, p.attribute.clone(), |y| {
                y.logicalname.clone()
            });
        }
    }
    macro_rules! merge {
        ($field:ident, $key:expr) => {
            for item in &desired.$field {
                replace_or_push(&mut into.$field, item.clone(), $key);
            }
        };
    }
    merge!(queries, QueryDef::key);
    merge!(views, |v: &ViewDef| (v.entity.clone(), v.name.clone()));
    merge!(calendars, |c: &CalendarDef| c.name.clone());
    merge!(sidebar, |s: &SidebarDef| s.path.clone());
    merge!(roles, |r: &RoleDef| r.name.clone());
    merge!(privileges, |p: &PrivilegeDef| p.key.clone());
    merge!(field_security_profiles, |p: &FieldSecurityProfileDef| p
        .name
        .clone());
    merge!(state_models, |m: &StateModelDef| m
        .entity_logicalname
        .clone());
    merge!(relationships, |r: &RelationshipDef| r.name.clone());
    merge!(apps, |a: &AppDef| a.name.clone());
    merge!(rules, RuleDef::key);
}

/// Plans `values` (design §5.2 steps 1–4). Refuses the whole plan (422) when
/// a document is malformed, and (409) on a checksum mismatch; everything
/// else is reported per changeset and operation. Writes nothing.
pub async fn plan(
    state: &EngineState,
    values: &[Value],
    ctx: PlanContext,
) -> Result<Planned, AppError> {
    if values.is_empty() {
        return Err(AppError::Validation(
            "changesets: at least one document is required".into(),
        ));
    }
    if values.len() > MAX_PLAN_DOCUMENTS {
        return Err(AppError::Validation(format!(
            "changesets: at most {MAX_PLAN_DOCUMENTS} documents per plan"
        )));
    }
    let mut docs = Vec::with_capacity(values.len());
    let mut problems = Vec::new();
    for (i, value) in values.iter().enumerate() {
        match parse_document(value) {
            Ok(doc) => docs.push(doc),
            Err(errs) => problems.extend(errs.into_iter().map(|e| format!("changesets[{i}]: {e}"))),
        }
    }
    let mut seen = HashSet::new();
    for doc in &docs {
        if !seen.insert(doc.id) {
            problems.push(format!(
                "changeset id {} appears twice in the batch",
                doc.id
            ));
        }
    }
    if !problems.is_empty() {
        return Err(AppError::Validation(problems.join("; ")));
    }

    let db = &state.base.db_migrator;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;

    // Step 2: the checksum refusal and what is already applied.
    let mut done: HashMap<Uuid, BTreeSet<&'static str>> = HashMap::new();
    for doc in &docs {
        for (phase, checksum, status) in ledger::checksums_of(&mut conn, doc.id).await? {
            if checksum != doc.checksum {
                return Err(AppError::Conflict(ledger::CHANGESET_CHECKSUM_MISMATCH));
            }
            if status.is_done() {
                done.entry(doc.id).or_default().insert(phase.as_str());
            }
        }
    }

    // Step 3: order, dependencies, floor, modules.
    let order = apply_order(&docs).map_err(AppError::Validation)?;
    let batch_refs: HashSet<String> = docs.iter().map(Document::reference).collect();
    let after_refs: Vec<String> = docs
        .iter()
        .flat_map(|d| d.requires.after.iter().cloned())
        .filter(|r| !batch_refs.contains(r))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let applied_refs: HashSet<String> = if after_refs.is_empty() {
        HashSet::new()
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT ref FROM changeset_apply \
             WHERE ref = ANY($1) AND phase = 'expand' AND status IN ('succeeded', 'adopted')",
        )
        .bind(&after_refs)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect()
    };
    let running = parse_version(PLATFORM_VERSION);

    // Step 4: per operation, against live metadata as the batch changes it.
    let mut simulated = export_bundle(db).await?;
    let full_license = attome_modules::ModuleSet::from_bits([u64::MAX; 4]);

    // D-787 rule 7: declared business keys as the batch changes them.
    let mut keys = super::business_key::PlanKeys::default();
    let mut planned = Vec::with_capacity(docs.len());
    for index in &order {
        let doc = &docs[*index];
        let mut blocked = Vec::new();
        for after in &doc.requires.after {
            if !batch_refs.contains(after) && !applied_refs.contains(after) {
                blocked.push(format!(
                    "missing_dependency: requires.after \"{after}\" is neither applied here nor \
                     in this plan"
                ));
            }
        }
        if let (Some(floor), Some(mine)) = (parse_version(&doc.requires.platform), running)
            && floor > mine
        {
            blocked.push(format!(
                "platform_floor: the changeset requires platform {} but this server is \
                 {PLATFORM_VERSION}",
                doc.requires.platform
            ));
        }
        if !ctx.trusted {
            for module in modules_off(state, &doc.requires.modules) {
                blocked.push(format!(
                    "module_off: module \"{module}\" is switched off on this deployment"
                ));
            }
        }

        let already = done.get(&doc.id).cloned().unwrap_or_default();
        let mut phases = Vec::new();
        for phase in doc.phases() {
            let ops = doc.ops_of(phase);
            let mut lines = Vec::with_capacity(ops.len());
            // The bundle planner's view of the objects this phase upserts.
            let mut fold = Fold::new(&simulated);
            let mut fold_errors: HashMap<i32, String> = HashMap::new();
            for op in &ops {
                if let Err(e) = fold.apply(op) {
                    fold_errors.insert(op.seq, e);
                }
            }
            let bundle_plan = build_plan(
                &simulated,
                &fold.out,
                PlanOptions {
                    allow_retire: false,
                    additive_only: true,
                },
                &full_license,
                i64::MAX,
                PLATFORM_VERSION,
            );
            let mut actions: HashMap<(&str, String), (PlanAction, Option<String>)> = HashMap::new();
            for e in bundle_plan.entries.iter().chain(&bundle_plan.blocked) {
                let entry = actions
                    .entry((e.component, e.key.clone()))
                    .or_insert((e.action, e.reason.clone()));
                if e.action == PlanAction::Blocked {
                    *entry = (e.action, e.reason.clone());
                }
            }
            // Record rows are planned against the live tables.
            if !fold.out.record_sets.is_empty() {
                let records = crate::bundle::plan_record_sets(db, &simulated, &fold.out).await?;
                for e in records.entries.iter().chain(&records.blocked) {
                    actions.insert((e.component, e.key.clone()), (e.action, e.reason.clone()));
                }
            }

            for op in &ops {
                let (action, reason) = if let Some(reason) = unsupported(op.op) {
                    ("blocked".to_owned(), Some(reason.to_owned()))
                } else if let Some(e) = fold_errors.get(&op.seq) {
                    (
                        "blocked".to_owned(),
                        Some(format!("invalid_operation: {e}")),
                    )
                } else if let Some(reason) = view_sort_refusal(op) {
                    ("blocked".to_owned(), Some(reason.to_owned()))
                } else if is_field_op(op.op) {
                    // Phase 2 (D-788): against live metadata; a field an
                    // earlier op of this batch creates counts as present.
                    let in_batch = simulated.entities.iter().any(|e| {
                        e.logicalname == op.t("entity")
                            && e.attributes.iter().any(|a| a.logicalname == op.t("field"))
                    });
                    let (action, reason) = crate::field_changes::plan_field_op(
                        &mut conn,
                        op.op,
                        op.t("entity"),
                        op.t("field"),
                        op.args.as_ref(),
                    )
                    .await?;
                    if action == "blocked"
                        && in_batch
                        && reason
                            .as_deref()
                            .is_some_and(|r| r.starts_with("field_not_found"))
                    {
                        ("update".to_owned(), None)
                    } else {
                        (action, reason)
                    }
                } else if phase == ApplyPhase::Contract
                    || matches!(
                        op.op,
                        Op::ReactivateEntity
                            | Op::ReactivateField
                            | Op::SetEntityDomain
                            | Op::SetEntityMasterData
                            | Op::SetLabel
                    )
                {
                    if op.phase == ApplyPhase::Contract && !removal_is_live(&simulated, op) {
                        ("noop".to_owned(), None)
                    } else if op.phase == ApplyPhase::Contract {
                        ("retire".to_owned(), None)
                    } else {
                        ("update".to_owned(), None)
                    }
                } else {
                    match component_key(op).and_then(|k| actions.get(&k).cloned()) {
                        Some((PlanAction::Blocked, reason)) => (
                            "blocked".to_owned(),
                            Some(format!(
                                "blocked: {}",
                                reason.unwrap_or_else(|| "the bundle planner refused it".into())
                            )),
                        ),
                        Some((PlanAction::Create, _)) => ("create".to_owned(), None),
                        Some((PlanAction::Noop, _)) => ("noop".to_owned(), None),
                        Some((PlanAction::Retire, _)) => ("retire".to_owned(), None),
                        Some((PlanAction::Update, _)) | None => ("update".to_owned(), None),
                    }
                };
                // D-787 rule 7 (design §3.8, §5.2): an `upsert_record` names
                // exactly the declared key (`business_key_mismatch`), an
                // entity without one is `business_key_missing` outside the
                // platform layer, and a new key live rows duplicate is
                // `business_key_duplicates`. Checked for every op so a
                // declaration is noted for the ops after it.
                let key_refusal = keys.check(db, doc.layer, op).await?;
                let (action, reason) = match key_refusal {
                    Some(refusal) if action != "blocked" => ("blocked".to_owned(), Some(refusal)),
                    _ => (action, reason),
                };
                let (action, reason) =
                    if action != "blocked" && !ctx.trusted && !is_create_only(op.op) {
                        match row_layer(&mut conn, op).await? {
                            // D-791 rule 2: our changesets may change or
                            // retire any rule, customer-layer ones included.
                            // Topic 14: when the customer changed it since our
                            // last release, the apply keeps their version and
                            // reports a conflict; the plan says so (never a
                            // block).
                            Some(owner) if customer_rule_open_to_us(op.op, &owner) => {
                                match customer_rule_conflict(&mut conn, op).await? {
                                    Some(note) => (action, Some(note)),
                                    None => (action, reason),
                                }
                            }
                            Some(owner) if owner != doc.layer.as_str() => (
                                "blocked".to_owned(),
                                Some(format!(
                                    "layer_mismatch: the object is owned by the {owner} layer; \
                                 change it in a {owner} changeset"
                                )),
                            ),
                            _ => (action, reason),
                        }
                    } else {
                        (action, reason)
                    };
                lines.push(PlannedOp {
                    seq: op.seq,
                    op: op.op.as_str().to_owned(),
                    phase,
                    target: Value::Object(op.target.clone()),
                    risky: risky(op),
                    action,
                    reason,
                });
            }
            if phase == ApplyPhase::Expand {
                let Fold { out: desired, .. } = fold;
                merge_into(&mut simulated, &desired);
            }
            let applicable = blocked.is_empty() && lines.iter().all(|l| l.action != "blocked");
            let status = if already.contains(phase.as_str()) {
                "already_applied"
            } else if applicable {
                "planned"
            } else {
                "blocked"
            };
            phases.push(PlannedPhase {
                phase,
                apply_id: None,
                status: status.to_owned(),
                applicable,
                operations: lines,
            });
        }
        let status = if !blocked.is_empty() {
            "blocked"
        } else if phases.iter().all(|p| p.status == "already_applied") {
            "already_applied"
        } else {
            "planned"
        };
        planned.push(PlannedChangeset {
            changeset_id: doc.id,
            changeset_ref: doc.reference(),
            layer: doc.layer.as_str().to_owned(),
            scope: doc.scope.clone(),
            seq: doc.seq,
            checksum: doc.checksum.clone(),
            status: status.to_owned(),
            blocked,
            phases,
        });
    }
    let applicable = planned
        .iter()
        .all(|c| c.blocked.is_empty() && c.phases.iter().all(|p| p.applicable));
    let ordered_docs = order.iter().map(|i| docs[*i].clone()).collect();
    Ok(Planned {
        docs: ordered_docs,
        plan: ChangesetPlan {
            changesets: planned,
            apply_ids: Vec::new(),
            contract_apply_ids: Vec::new(),
            applicable,
        },
    })
}

/// Writes one `planned` ledger row per (changeset, phase) not already
/// applied, in the caller's transaction, filling the plan's apply ids.
pub async fn persist(
    tx: &mut attome_db::Tx<'_>,
    planned: &mut Planned,
    ctx: PlanContext,
) -> Result<(), AppError> {
    let mut apply_ids = Vec::new();
    let mut contract_ids = Vec::new();
    for (doc, cs) in planned.docs.iter().zip(planned.plan.changesets.iter_mut()) {
        for phase in &mut cs.phases {
            if phase.status == "already_applied" {
                continue;
            }
            let plan_json = json!({
                "changeset_status": cs.status,
                "blocked": cs.blocked,
                "applicable": phase.applicable && cs.blocked.is_empty(),
                "operations": phase.operations,
            });
            let id = ledger::upsert_planned(
                tx,
                &NewApplyRow {
                    changeset_id: doc.id,
                    changeset_ref: &cs.changeset_ref,
                    layer: doc.layer.as_str(),
                    scope: &doc.scope,
                    seq: doc.seq,
                    phase: phase.phase,
                    checksum: &doc.checksum,
                    document: &doc.value,
                    plan: &plan_json,
                    status: ApplyStatus::Planned,
                    source: ctx.source,
                    platform_version: PLATFORM_VERSION,
                    requested_by: ctx.requested_by,
                },
            )
            .await?;
            phase.apply_id = Some(id);
            match phase.phase {
                ApplyPhase::Expand => apply_ids.push(id),
                ApplyPhase::Contract => contract_ids.push(id),
            }
        }
    }
    planned.plan.apply_ids = apply_ids;
    planned.plan.contract_apply_ids = contract_ids;
    Ok(())
}

/// The plan JSON a trusted boot apply stores: every operation `apply`d by
/// its compare-first executor (boot does not diff first; a platform
/// changeset's own reconcile primitives decide what changes).
pub fn boot_plan_json(doc: &Document, phase: ApplyPhase) -> Value {
    let ops: Vec<Value> = doc
        .ops_of(phase)
        .iter()
        .map(|op| {
            json!({
                "seq": op.seq,
                "op": op.op.as_str(),
                "action": if unsupported(op.op).is_some() { "blocked" } else { "apply" },
            })
        })
        .collect();
    let applicable = doc
        .ops_of(phase)
        .iter()
        .all(|op| unsupported(op.op).is_none());
    json!({ "applicable": applicable, "operations": ops, "source": "boot" })
}

/// The operations of a checked document grouped by the bundle component
/// they fold to — the reassembled bundle (`Fold` over an empty live state).
/// Used by the conversion test and by callers that need a document's
/// desired state without a database.
pub fn to_bundle(doc: &Document) -> Result<Bundle, String> {
    let empty = empty_bundle();
    let mut fold = Fold::new(&empty);
    for op in &doc.operations {
        fold.apply(op)?;
    }
    Ok(fold.out)
}

/// Order-insensitive keys, for comparisons in tests.
#[doc(hidden)]
pub fn component_counts(bundle: &Bundle) -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("entities", bundle.entities.len()),
        (
            "attributes",
            bundle.entities.iter().map(|e| e.attributes.len()).sum(),
        ),
        ("attribute_patches", bundle.attribute_patches.len()),
        ("queries", bundle.queries.len()),
        ("views", bundle.views.len()),
        ("roles", bundle.roles.len()),
        ("privileges", bundle.privileges.len()),
        ("state_models", bundle.state_models.len()),
        ("relationships", bundle.relationships.len()),
        ("record_sets", bundle.record_sets.len()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changeset::platform_index::PLATFORM_CHANGESETS;

    fn doc(json: &str) -> Document {
        let value: Value = serde_json::from_str(json).expect("json");
        parse_document(&value).unwrap_or_else(|e| panic!("{e:?}"))
    }

    /// Every compiled platform changeset parses, its checksum verifies in
    /// Rust (JCS), and folding its operations reproduces exactly the platform
    /// bundle it was converted from — so applying it applies that bundle's
    /// content (the pure half of the Phase 1.5 equivalence proof).
    #[test]
    fn every_platform_changeset_reassembles_to_its_bundle() {
        for entry in PLATFORM_CHANGESETS {
            let d = doc(entry.json);
            assert_eq!(d.name, entry.name, "{}", entry.file);
            assert_eq!(d.layer, Layer::Platform);
            let (_, bundle_json) = crate::changeset::layers::PLATFORM_BUNDLES
                .iter()
                .find(|(name, _)| *name == entry.name)
                .unwrap_or_else(|| {
                    panic!("{}: no platform bundle named {}", entry.file, entry.name)
                });
            let mut want =
                crate::bundle::parse_bundle(bundle_json.as_bytes()).expect("bundle parses");
            let mut got = to_bundle(&d).unwrap_or_else(|e| panic!("{}: {e}", entry.file));
            // What a changeset does not carry: the bundle's identity and floor.
            got.name.clone_from(&want.name);
            got.version.clone_from(&want.version);
            got.requires = want.requires.clone();
            got.normalize();
            want.normalize();
            assert_eq!(
                component_counts(&got),
                component_counts(&want),
                "{}",
                entry.file
            );
            assert_eq!(
                got, want,
                "{} does not reassemble to its bundle",
                entry.file
            );
        }
    }

    #[test]
    fn the_required_args_mirror_the_schema() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../schemas/attome-changeset-v1.schema.json"
        ))
        .expect("schema parses");
        for op in Op::ALL {
            let def = &schema["$defs"][format!("op_{}", op.as_str())];
            let mut want: Vec<String> = def["properties"]["args"]["required"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let mut got: Vec<String> = required_args(*op).iter().map(|s| (*s).to_owned()).collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "{}", op.as_str());
        }
    }

    #[test]
    fn a_tampered_document_fails_its_checksum_and_shape_rules_are_named() {
        let entry = PLATFORM_CHANGESETS
            .first()
            .expect("at least one platform changeset");
        let mut value: Value = serde_json::from_str(entry.json).expect("json");
        value["title"] = json!("changed");
        let errs = parse_document(&value).expect_err("tampered");
        assert!(
            errs.iter().any(|e| e.contains("checksum mismatch")),
            "{errs:?}"
        );

        let mut bad: Value = serde_json::from_str(entry.json).expect("json");
        bad["operations"][0]["target"] =
            json!({ "privilege": "0192a0b1-0000-7000-8000-000000000000" });
        bad["operations"][0]["seq"] = json!(9);
        let errs = parse_document(&bad).expect_err("bad op");
        assert!(errs.iter().any(|e| e.contains("seq must be 1")), "{errs:?}");
    }

    #[test]
    fn the_apply_order_follows_folders_and_requires_after() {
        let base: Value =
            serde_json::from_str(PLATFORM_CHANGESETS.first().expect("one").json).expect("json");
        let make = |layer: &str, scope: &str, seq: i64, name: &str, after: &[&str]| {
            let mut v = base.clone();
            v["id"] = json!(Uuid::now_v7());
            v["layer"] = json!(layer);
            v["scope"] = json!(scope);
            v["seq"] = json!(seq);
            v["name"] = json!(name);
            v["requires"] = json!({ "platform": ">=0.0.0", "after": after });
            v.as_object_mut().map(|m| m.remove("checksum"));
            let checksum = jcs::document_checksum(&v).expect("checksum");
            v["checksum"] = json!(checksum);
            parse_document(&v).unwrap_or_else(|e| panic!("{e:?}"))
        };
        let docs = vec![
            make("project", "acme", 2, "second", &[]),
            make("project", "acme", 1, "first", &["product/crm/0001-base"]),
            make("product", "crm", 1, "base", &[]),
        ];
        let order: Vec<&str> = apply_order(&docs)
            .expect("an order")
            .into_iter()
            .map(|i| docs[i].name.as_str())
            .collect();
        assert_eq!(order, ["base", "first", "second"]);
    }

    #[test]
    fn folding_keeps_live_children_and_applies_removals() {
        let mut live = empty_bundle();
        live.roles.push(RoleDef {
            name: "Agent".into(),
            description: None,
            access_level: 3,
            position_hierarchy_enabled: false,
            is_customized: false,
            privileges: vec![
                RoleGrant {
                    privilege: "a.read".into(),
                    conditions: Vec::new(),
                },
                RoleGrant {
                    privilege: "b.read".into(),
                    conditions: Vec::new(),
                },
            ],
            entity_access: Vec::new(),
            field_security_profiles: vec!["P".into()],
        });
        let op = |json: Value| DocOp {
            seq: 1,
            op: Op::parse(json["op"].as_str().unwrap_or_default()).expect("op"),
            phase: ApplyPhase::Expand,
            target: json["target"].as_object().cloned().unwrap_or_default(),
            args: json.get("args").cloned(),
        };
        let mut fold = Fold::new(&live);
        fold.apply(&op(
            json!({ "op": "upsert_role", "target": { "role": "Agent" },
            "args": { "definition": { "name": "Agent", "access_level": 2 } } }),
        ))
        .expect("upsert");
        fold.apply(&op(json!({ "op": "grant_role_privilege", "target": { "role": "Agent", "privilege": "c.read" }, "args": { "depth": null } })))
            .expect("grant");
        fold.apply(&op(json!({ "op": "revoke_role_privilege", "target": { "role": "Agent", "privilege": "a.read" } })))
            .expect("revoke");
        fold.apply(&op(json!({ "op": "set_role_entity_access", "target": { "role": "Agent", "entity": "account" },
            "args": { "access": { "read_access_level": 3, "write_access_level": 1, "delete_access_level": 0 } } })))
            .expect("access");
        let role = &fold.out.roles[0];
        assert_eq!(role.access_level, 2);
        let grants: Vec<&str> = role
            .privileges
            .iter()
            .map(|g| g.privilege.as_str())
            .collect();
        assert_eq!(grants, ["b.read", "c.read"]);
        assert_eq!(role.field_security_profiles, ["P"]);
        assert_eq!(role.entity_access[0].entity, "account");

        let missing = fold.apply(&op(json!({ "op": "grant_role_privilege",
            "target": { "role": "Ghost", "privilege": "x" }, "args": { "depth": null } })));
        assert!(missing.is_err());
    }

    #[test]
    fn set_view_columns_replaces_the_live_views_columns_and_refuses_a_sort() {
        let mut live = empty_bundle();
        live.views.push(
            serde_json::from_value(json!({
                "entity": "account", "name": "Active", "query": { "entity": "account", "name": "active" },
                "table_definition": [{ "name": "name" }], "view_metadata": { "filters": [] }
            }))
            .expect("view def"),
        );
        let op = |args: Value, view: &str| DocOp {
            seq: 3,
            op: Op::SetViewColumns,
            phase: ApplyPhase::Expand,
            target: json!({ "entity": "account", "view": view })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            args: Some(args),
        };
        let columns = json!([{ "name": "name" }, { "name": "created_at", "is_visible": true }]);
        let set = op(json!({ "columns": columns }), "Active");
        assert_eq!(unsupported(Op::SetViewColumns), None, "an executor exists");
        assert_eq!(view_sort_refusal(&set), None);
        assert_eq!(
            component_key(&set),
            Some((COMPONENT_VIEW, "account.Active".to_owned()))
        );

        let mut fold = Fold::new(&live);
        fold.apply(&set).expect("fold");
        assert_eq!(fold.out.views.len(), 1);
        assert_eq!(fold.out.views[0].table_definition, columns);
        assert_eq!(
            fold.out.views[0].view_metadata,
            json!({ "filters": [] }),
            "everything but the columns is the live view's"
        );
        // Set semantics: the same columns again change nothing further.
        fold.apply(&set).expect("again");
        assert_eq!(fold.out.views.len(), 1);
        assert_eq!(fold.out.views[0].table_definition, columns);

        let sorted = op(
            json!({ "columns": columns, "sort": [{ "field": "name", "direction": "asc" }] }),
            "Active",
        );
        assert!(
            view_sort_refusal(&sorted).is_some_and(|r| r.starts_with("view_sort_in_query")),
            "a system view's sort is its query's ORDER BY"
        );

        for (args, why) in [
            (json!({ "columns": [] }), "empty"),
            (json!({ "columns": [{ "label": "x" }] }), "no name"),
            (
                json!({ "columns": [{ "name": "a" }, { "name": "a" }] }),
                "twice",
            ),
            (json!({}), "missing"),
        ] {
            assert!(
                Fold::new(&live).apply(&op(args, "Active")).is_err(),
                "{why}"
            );
        }
        assert!(
            Fold::new(&live)
                .apply(&op(json!({ "columns": columns }), "Ghost"))
                .is_err(),
            "a view that is neither live nor upserted earlier"
        );
    }

    #[test]
    fn versions_compare_as_triples() {
        assert_eq!(parse_version(">=4.2.0"), Some((4, 2, 0)));
        assert_eq!(parse_version("4.10.1"), Some((4, 10, 1)));
        assert!(parse_version(">=4.2").is_none());
        assert!(parse_version(">=4.2.0") < parse_version(">=4.10.0"));
    }

    #[test]
    fn our_changesets_may_change_or_retire_a_customer_rule() {
        assert!(customer_rule_open_to_us(Op::UpsertRule, "customer"));
        assert!(customer_rule_open_to_us(Op::RetireRule, "customer"));
        assert!(!customer_rule_open_to_us(Op::UpsertRule, "platform"));
        assert!(!customer_rule_open_to_us(Op::UpsertView, "customer"));
    }
}
