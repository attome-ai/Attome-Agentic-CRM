//! The active-model metadata registry (Plan 1.2): a snapshot of
//! `entity_info` + `attribute_info`, keyed by logicalname, served
//! from `EngineState.entities` (an arc-swap `MetadataCache`) instead of a
//! per-request Postgres query. This is now the only metadata registry: the
//! dormant `EntityRegistry`/`EntitySchema` (`registry.rs`/`schema.rs`) this
//! module was once kept deliberately separate from were deleted under D-003
//! once P1.2 moved `EngineState.entities` onto `EntityMetaRegistry`.

use std::collections::HashMap;

use attome_cache::Store;
use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::change_log::ChangeLogRow;

/// P-data-lifecycle item (c): per-lookup delete behavior, enforced by the
/// generic delete handler when a lookup's target record is soft-deleted.
/// `Orphan` is today's behavior (pre-existing dangling references are left
/// exactly as-is) and the column default, so no existing deployment's
/// behavior changes until an admin opts a specific lookup attribute in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnTargetDelete {
    /// Block the delete (409) while a live (is_active) record still
    /// references the target through this lookup field.
    Restrict,
    /// Today's behavior: the delete proceeds; the dependent's lookup value
    /// is left pointing at the now-inactive target (a dangling reference).
    #[default]
    Orphan,
    /// The delete proceeds and cascades: every live dependent referencing
    /// the target through this lookup field is soft-deleted too, and each
    /// dependent's own lookups' rules apply in turn, at every depth (A7-T1,
    /// `attome_records::cascade`): a restrict lookup anywhere below refuses
    /// the whole delete.
    CascadeDeactivate,
}

impl OnTargetDelete {
    /// Never fails — an unrecognized stored string (there shouldn't be one;
    /// the column has a `CHECK` constraint) degrades to `Orphan`, today's
    /// behavior, rather than rejecting the read.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "restrict" => Self::Restrict,
            "cascade-deactivate" => Self::CascadeDeactivate,
            _ => Self::Orphan,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Restrict => "restrict",
            Self::Orphan => "orphan",
            Self::CascadeDeactivate => "cascade-deactivate",
        }
    }
}

/// A1-T1: how sensitive a field's values are. `internal` until a builder
/// says otherwise; `public` may be shown to anyone who can see the record,
/// `personal`, `financial` and `health` carry their own handling rules, and
/// `secret` is the strictest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    #[default]
    Internal,
    Personal,
    Financial,
    Health,
    Secret,
}

impl Sensitivity {
    /// Every label, least sensitive first.
    pub const ALL: [Self; 6] = [
        Self::Public,
        Self::Internal,
        Self::Personal,
        Self::Financial,
        Self::Health,
        Self::Secret,
    ];

    /// The stored value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Personal => "personal",
            Self::Financial => "financial",
            Self::Health => "health",
            Self::Secret => "secret",
        }
    }

    /// The label a stored value names; an unknown one reads as `internal`.
    pub fn from_db_str(s: &str) -> Self {
        Self::parse(s).unwrap_or_default()
    }

    /// The label `s` names, if it names one.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s.trim())
    }

    /// Q15-T2: whether a field with this label needs a field-security read
    /// grant: Personal, Financial, Health and Secret.
    pub fn is_gated(self) -> bool {
        matches!(
            self,
            Self::Personal | Self::Financial | Self::Health | Self::Secret
        )
    }

    /// The label an older `data_classification` maps to.
    pub fn from_classification(c: DataClassification) -> Self {
        match c {
            DataClassification::General => Self::Internal,
            DataClassification::Personal => Self::Personal,
            DataClassification::SensitiveSpecialCategory => Self::Health,
        }
    }
}

/// P-data-protection-governance §4 "Classification metadata" — a broader
/// governance taxonomy alongside (not replacing) `AttrInfo::is_sensitive`,
/// which keeps its narrower, already-relied-upon meaning (audit-output
/// masking only). This is what `data_classification::assert_transfer_allowed`
/// and per-record legal-hold scoping key off. `General` is the column
/// default, so no existing attribute's classification changes until an admin
/// opts a specific field in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    /// No PDPL/GDPR-relevant sensitivity — the column default.
    #[default]
    General,
    /// Personal data under Bahrain PDPL/GCC PDPLs/GDPR — identifies or
    /// relates to a natural person, but not a "special category".
    Personal,
    /// The narrower "special category"/sensitive-personal-data subset (health,
    /// religion, biometric, criminal record, etc.) most of these regimes
    /// single out for stricter handling.
    SensitiveSpecialCategory,
}

impl DataClassification {
    /// Never fails — an unrecognized stored string (there shouldn't be one;
    /// the column has a `CHECK` constraint) degrades to `General` rather than
    /// rejecting the read, same defensive posture as `OnTargetDelete::from_db_str`.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "personal" => Self::Personal,
            "sensitive_special_category" => Self::SensitiveSpecialCategory,
            _ => Self::General,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Personal => "personal",
            Self::SensitiveSpecialCategory => "sensitive_special_category",
        }
    }
}

/// Same shape `resolve_entity` has always returned per-attribute, plus the
/// P1.11(h) sortable/filterable flags — cheap to carry here since the
/// registry is already an arc-swap in-memory read, letting `query_exec.rs`
/// check "is this attribute's index expected to exist" with no extra DB call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttrInfo {
    pub logicalname: String,
    pub field_type_int: i32,
    #[serde(default)]
    pub is_required: bool,
    #[serde(default)]
    pub max_length: Option<i32>,
    pub is_sensitive: bool,
    /// D-507: a write to this field needs the caller's `can_update`
    /// field-security grant, exactly as an `is_sensitive` field's does — but
    /// the field stays readable and unmasked. Use
    /// [`AttrInfo::requires_field_write_grant`] rather than reading either
    /// flag directly at an enforcement point. `#[serde(default)]` so a
    /// pre-existing Redis registry snapshot still decodes.
    #[serde(default)]
    pub is_write_restricted: bool,
    pub is_sortable: bool,
    pub is_filterable: bool,
    /// The entity a "lookup" field (field_type_int == 11) points to — `None`
    /// for every non-lookup field, and (pre-existing bug, D-057) for lookup
    /// fields created before `ensure_attribute` started persisting this.
    /// `#[serde(default)]` so a Redis-cached registry snapshot written before
    /// this field existed still deserializes.
    #[serde(default)]
    pub lookup_entity_ref: Option<Uuid>,
    /// P-data-lifecycle item (c) — meaningless for non-lookup fields.
    /// `#[serde(default)]` so a pre-existing Redis snapshot still decodes.
    #[serde(default)]
    pub on_target_delete: OnTargetDelete,

    /// P-data-protection-governance §4 — see `DataClassification`'s doc
    /// comment. `#[serde(default)]` so a pre-existing Redis snapshot written
    /// before this field existed still deserializes.
    #[serde(default)]
    pub data_classification: DataClassification,

    /// A1-T1: the attribute's sensitivity label. `#[serde(default)]` so a
    /// pre-existing Redis snapshot still decodes.
    #[serde(default)]
    pub sensitivity: Sensitivity,

    /// A1-T1: whether a builder set the label (the migration mapped older
    /// fields from `data_classification` unconfirmed). Q15-T2 gates reads by
    /// a confirmed label only. `#[serde(default)]`: an older snapshot reads
    /// as unconfirmed, so it gates nothing it did not gate before.
    #[serde(default)]
    pub sensitivity_confirmed: bool,

    /// F004/F012 (migration 0029): type-specific config — `ChoiceOptions` for
    /// Choice fields, `TextOptions` for masked Text fields (see `attome-field`).
    /// `#[serde(default)]` for the same pre-existing-snapshot reason as
    /// `lookup_entity_ref` above.
    #[serde(default)]
    pub options: Option<serde_json::Value>,
}

impl AttrInfo {
    /// D-507: the one write rule for field-level security. A payload that
    /// sets this field needs `has_field_write_grant`
    /// (`field_security_profile_field.can_update`, D-141) when the
    /// field is read-sensitive **or** write-restricted.
    ///
    /// Read gating and audit masking are deliberately not part of this rule:
    /// they stay keyed on `is_sensitive` alone, which is what lets a field be
    /// readable by everyone who can see the record but writable only with a
    /// grant.
    pub fn requires_field_write_grant(&self) -> bool {
        self.is_sensitive || self.is_write_restricted
    }

    /// Q15-T2: the one read rule for field-level security. Reading this
    /// field needs a field-security read grant when it is `is_sensitive`
    /// (kept as Secret) or its confirmed label is Personal, Financial, Health
    /// or Secret. A label the migration mapped and nobody confirmed gates
    /// nothing, so existing deployments see no field disappear until a
    /// builder confirms its label.
    pub fn is_read_gated(&self) -> bool {
        self.is_sensitive || (self.sensitivity_confirmed && self.sensitivity.is_gated())
    }

    /// The declared [`FieldType`](crate::FieldType) (`field_type_int`
    /// decoded through the one codec).
    pub fn field_type(&self) -> crate::FieldType {
        crate::FieldType::from_int(self.field_type_int).unwrap_or(crate::FieldType::Text)
    }

    /// The type this field is *stored and cast* as — see
    /// [`FieldType::storage`](crate::FieldType::storage): a `formula`'s
    /// result type, `rich_text` as `text`, `image` as `file`. Every
    /// storage-level decision (bind cast, filter cast, "is this a file-key
    /// column", rule typing) reads this rather than `field_type_int`.
    pub fn storage_type(&self) -> crate::FieldType {
        self.field_type().storage(self.options.as_ref())
    }

    /// The type a reader of this field's value sees — see
    /// [`FieldType::presentation`](crate::FieldType::presentation).
    pub fn presentation_type(&self) -> crate::FieldType {
        self.field_type().presentation(self.options.as_ref())
    }

    /// `true` for a `formula` field (B-R6, D-604): computed on every write,
    /// never written by a client.
    pub fn is_formula(&self) -> bool {
        self.field_type() == crate::FieldType::Formula
    }

    /// Y2-T11: a formula the database computes (`"generated": true`): the
    /// entity engine neither computes nor writes it.
    pub fn is_generated_formula(&self) -> bool {
        self.is_formula()
            && self
                .options
                .as_ref()
                .and_then(|o| o.get("generated"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
    }

    /// `true` for a field whose column holds uploaded-file object keys
    /// (`file`, and `image`, which is a `file` restricted to images).
    pub fn is_file_backed(&self) -> bool {
        self.storage_type() == crate::FieldType::File
    }
}

/// Same shape `resolve_entity` has always returned per-entity, now cached.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityMeta {
    pub entity_id: Uuid,
    pub logicalname: String,
    pub attrs: Vec<AttrInfo>,
    pub is_append_only: bool,
    /// The attribute logicalname whose value best displays a record of this
    /// entity (e.g. "name") — used to resolve a lookup's tombstone/audit
    /// display name. `None` when the entity declares no primary name
    /// attribute. `#[serde(default)]` so a pre-existing Redis snapshot still
    /// decodes.
    #[serde(default)]
    pub primary_name_attribute: Option<String>,
}

/// Snapshot of the active entity/attribute metadata, keyed by logicalname.
/// Swapped in atomically by `MetadataCache<EntityMetaRegistry>` — see
/// `state.rs`. `Serialize`/`Deserialize` back the Redis pre-warm snapshot
/// (Plan 1.14) — see `save_snapshot`/`load_snapshot` below.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(from = "EntityMetaRegistryWire")]
pub struct EntityMetaRegistry {
    by_logicalname: HashMap<String, EntityMeta>,
    /// Secondary index for `get_by_id` (T4-2, review item 3.3): entity id ->
    /// logicalname, always derived from `by_logicalname` by `from_map` — the
    /// one constructor every production and test path funnels through — so
    /// the two maps can never disagree. Never serialized: the Redis snapshot
    /// (`save_snapshot`/`load_snapshot`) carries `by_logicalname` only, and
    /// the `#[serde(from)]` above rebuilds this on decode, which also keeps
    /// a snapshot written by a pre-T4-2 node decodable by this one and vice
    /// versa (the wire shape is unchanged).
    #[serde(skip)]
    by_id: HashMap<Uuid, String>,
    /// Y12-T8: per entity, the old names of renamed attributes still in their
    /// alias period, each mapped to the attribute's current name. Loaded from
    /// `attribute_alias` by [`build_registry`] and [`apply_change_log`].
    #[serde(default)]
    aliases: HashMap<String, HashMap<String, String>>,
    /// AA7-T2: what `GET /api/v1/schema/{logicalname}` shows of each entity,
    /// by entity id ([`fetch_schema_facts`]). Empty in a snapshot written
    /// before it existed; the route then reads the database.
    #[serde(default)]
    schema: HashMap<Uuid, SchemaEntity>,
}

/// AA7-T2: what the schema route shows of an entity beyond the enforcement
/// metadata in [`EntityMeta`]: its display name and, in form order, each
/// attribute's id, display name and stored options (an option set
/// unexpanded, as the route has always served it).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SchemaEntity {
    pub display_name: Option<String>,
    /// By `sort_order`, then creation time, then name.
    pub fields: Vec<SchemaField>,
}

/// One attribute as the schema route shows it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct SchemaField {
    pub id: Uuid,
    pub logicalname: Option<String>,
    pub display_name: Option<String>,
    pub field_type_int: Option<i32>,
    pub required: Option<bool>,
    pub lookup_entity_ref: Option<Uuid>,
    /// The lookup target's name and primary name attribute when the
    /// attribute was read (the route prefers the live registry's).
    pub lookup_entity_ln: Option<String>,
    pub lookup_display_field: Option<String>,
    pub options: Option<serde_json::Value>,
}

/// Wire shape of the Redis snapshot — `by_logicalname` only. `EntityMetaRegistry`
/// deserializes through this (`#[serde(from)]`) so `by_id` is rebuilt rather
/// than trusted from the wire.
#[derive(Deserialize)]
struct EntityMetaRegistryWire {
    by_logicalname: HashMap<String, EntityMeta>,
    #[serde(default)]
    aliases: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    schema: HashMap<Uuid, SchemaEntity>,
}

impl From<EntityMetaRegistryWire> for EntityMetaRegistry {
    fn from(wire: EntityMetaRegistryWire) -> Self {
        Self::from_map(wire.by_logicalname)
            .with_aliases(wire.aliases)
            .with_schema(wire.schema)
    }
}

impl EntityMetaRegistry {
    /// Builds a registry from an explicit set of entities.
    ///
    /// The database loader below is the only production constructor; this is
    /// for callers that already hold the metadata — tests that need a known
    /// registry without a `core_entity` round trip, and any future consumer
    /// projecting against a snapshot rather than the live cache. Last entry
    /// wins on a duplicate logicalname, matching the loader.
    pub fn from_entities(entities: Vec<EntityMeta>) -> Self {
        Self::from_map(
            entities
                .into_iter()
                .map(|e| (e.logicalname.clone(), e))
                .collect(),
        )
    }

    /// The single constructor behind every registry: derives the `by_id`
    /// index from the finished `by_logicalname` map. Rebuilding the index
    /// from scratch (O(entities), tens–hundreds) on every snapshot rather
    /// than maintaining it incrementally through `apply_change_log` is what
    /// makes "the two maps agree" true by construction instead of by
    /// discipline; `MetadataCache` swaps whole snapshots anyway.
    fn from_map(by_logicalname: HashMap<String, EntityMeta>) -> Self {
        let by_id = by_logicalname
            .values()
            .map(|e| (e.entity_id, e.logicalname.clone()))
            .collect();
        Self {
            by_logicalname,
            by_id,
            aliases: HashMap::new(),
            schema: HashMap::new(),
        }
    }

    /// AA7-T2: this registry with the schema route's facts, by entity id.
    #[must_use]
    pub fn with_schema(mut self, schema: HashMap<Uuid, SchemaEntity>) -> Self {
        self.schema = schema;
        self
    }

    /// AA7-T2: what the schema route shows of the entity `entity_id`, when
    /// this snapshot carries it.
    pub fn schema(&self, entity_id: Uuid) -> Option<&SchemaEntity> {
        self.schema.get(&entity_id)
    }

    /// Y12-T8: this registry with `aliases` (entity, then old name to
    /// current name).
    #[must_use]
    pub fn with_aliases(mut self, aliases: HashMap<String, HashMap<String, String>>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Y12-T8: the current name of `entity`'s attribute once called
    /// `old_name`, while its alias period lasts.
    pub fn alias(&self, entity: &str, old_name: &str) -> Option<&str> {
        self.aliases
            .get(entity)
            .and_then(|names| names.get(old_name))
            .map(String::as_str)
    }

    /// Y12-T8: whether `entity` has any live alias (so a caller skips the
    /// per-key lookups when it has none).
    pub fn has_aliases(&self, entity: &str) -> bool {
        self.aliases
            .get(entity)
            .is_some_and(|names| !names.is_empty())
    }

    pub fn get(&self, logicalname: &str) -> Option<&EntityMeta> {
        self.by_logicalname.get(logicalname)
    }

    /// Served from the `by_id` secondary index (see the field doc). This
    /// used to be a linear scan justified by "one caller"; that claim was
    /// stale — a workspace grep at the time of T4-2 found 16 call sites in
    /// 5 files (`attome-server`'s `query_exec.rs`, `entity_mutation.rs`,
    /// `entity_crud/mutations.rs`, `entity_crud/response.rs`, and
    /// `attome-search`'s `aggregate.rs`), including the per-lookup-field
    /// target resolution on every record read/list/write response.
    pub fn get_by_id(&self, entity_id: Uuid) -> Option<&EntityMeta> {
        self.by_id
            .get(&entity_id)
            .and_then(|logicalname| self.by_logicalname.get(logicalname))
    }

    /// Conservative response guard for custom stored queries, which may not
    /// have a single entity scope from which to derive field sensitivity.
    /// Q15-T2: every field whose reads are gated ([`AttrInfo::is_read_gated`]).
    pub fn sensitive_field_names(&self) -> std::collections::HashSet<&str> {
        self.by_logicalname
            .values()
            .flat_map(|entity| entity.attrs.iter())
            .filter(|attr| attr.is_read_gated())
            .map(|attr| attr.logicalname.as_str())
            .collect()
    }

    /// P-data-lifecycle item (c): every (dependent entity logicalname, lookup
    /// field logicalname, configured delete mode) triple whose lookup field
    /// targets `target_entity_id` — the reverse of the forward
    /// `lookup_entity_ref` a normal read follows. There is no maintained
    /// reverse index for this (unlike `get_by_id`, which grew one under
    /// T4-2): it runs once per delete, over a registry sized in entities
    /// (tens-hundreds), not rows — add a real index only if a second, hotter
    /// caller shows up.
    pub fn dependents_of(&self, target_entity_id: Uuid) -> Vec<(String, String, OnTargetDelete)> {
        self.by_logicalname
            .values()
            .flat_map(|meta| {
                meta.attrs
                    .iter()
                    .filter(move |attr| attr.lookup_entity_ref == Some(target_entity_id))
                    .map(|attr| {
                        (
                            meta.logicalname.clone(),
                            attr.logicalname.clone(),
                            attr.on_target_delete,
                        )
                    })
            })
            .collect()
    }

    /// Every active entity's metadata, in no particular order.
    ///
    /// M38 Phase 1's edge catalogue is the first caller outside this module:
    /// a graph traversal derives its lookup-field edges by walking every
    /// entity's `attrs` once (registry-sized, tens-hundreds — not a per-row
    /// cost), the same order of work `dependents_of` already accepts above.
    /// Returning an iterator rather than a `Vec` avoids a clone the caller
    /// doesn't need: it is folded into an edge list immediately.
    pub fn iter(&self) -> impl Iterator<Item = &EntityMeta> {
        self.by_logicalname.values()
    }

    pub fn len(&self) -> usize {
        self.by_logicalname.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_logicalname.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct EntityRow {
    id: Uuid,
    logicalname: String,
    is_append_only: Option<bool>,
    primary_name_attribute: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AttrRow {
    entity_ref: Uuid,
    logicalname: String,
    field_type_int: i32,
    is_required: bool,
    max_length: Option<i32>,
    is_sensitive: bool,
    is_write_restricted: bool,
    is_sortable: bool,
    is_filterable: bool,
    lookup_entity_ref: Option<Uuid>,
    on_target_delete: String,
    data_classification: String,
    sensitivity: String,
    sensitivity_confirmed: bool,
    options: Option<serde_json::Value>,
}

impl From<AttrRow> for AttrInfo {
    fn from(row: AttrRow) -> Self {
        Self {
            logicalname: row.logicalname,
            field_type_int: row.field_type_int,
            is_required: row.is_required,
            max_length: row.max_length,
            is_sensitive: row.is_sensitive,
            is_write_restricted: row.is_write_restricted,
            is_sortable: row.is_sortable,
            is_filterable: row.is_filterable,
            lookup_entity_ref: row.lookup_entity_ref,
            on_target_delete: OnTargetDelete::from_db_str(&row.on_target_delete),
            data_classification: DataClassification::from_db_str(&row.data_classification),
            sensitivity: Sensitivity::from_db_str(&row.sensitivity),
            sensitivity_confirmed: row.sensitivity_confirmed,
            options: row.options,
        }
    }
}

/// A5-T1: an attribute's `options`, with a choice field that names an option
/// set (`{"option_set": "<name>"}`) given that set's published, not retired
/// codes as `choices`, in order, so every choice check works unchanged.
/// Public so a path that reads `attribute_info` without the registry
/// (`attome_records`'s database resolve) sees the same choices.
pub const OPTIONS_SQL: &str = "CASE WHEN options ? 'option_set' THEN \
    options || jsonb_build_object('choices', COALESCE(( \
        SELECT jsonb_agg(val->'code' ORDER BY COALESCE((val->>'order')::bigint, 9223372036854775807)) \
        FROM metadata_object o \
        JOIN LATERAL (SELECT v.doc FROM metadata_object_version v \
                      WHERE v.object_id = o.id AND v.state = 'published' \
                      ORDER BY v.version_no DESC LIMIT 1) p ON true \
        CROSS JOIN LATERAL jsonb_array_elements(p.doc->'values') val \
        WHERE o.kind = 'option_set' AND o.is_active AND o.name = options->>'option_set' \
          AND COALESCE((val->>'retired')::boolean, false) = false), '[]'::jsonb)) \
    ELSE options END";

/// Builds a full registry snapshot from Postgres: one query over
/// `entity_info`, one grouped query over `attribute_info` — no
/// N+1. Mirrors the exact `WHERE`/`COALESCE` clauses the pre-1.2
/// `resolve_entity` used, so behavior is unchanged for existing rows.
pub async fn build_registry(db: &DbPool) -> Result<EntityMetaRegistry, AppError> {
    let entities: Vec<EntityRow> = sqlx::query_as(
        "SELECT id, COALESCE(logicalname, '') AS logicalname, is_append_only,
                primary_name_attribute
         FROM entity_info
         WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL AND logicalname <> ''",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let attrs: Vec<AttrRow> = sqlx::query_as(&format!(
        r#"SELECT entity_ref,
                  COALESCE(logicalname, '')      AS logicalname,
                  COALESCE("type", 3)            AS field_type_int,
                  COALESCE(required, false)       AS is_required,
                  max_length,
                  COALESCE(is_sensitive, false)  AS is_sensitive,
                  COALESCE(is_write_restricted, false) AS is_write_restricted,
                  COALESCE(is_sortable, false)   AS is_sortable,
                  COALESCE(is_filterable, false) AS is_filterable,
                  lookup_entity_ref,
                  COALESCE(on_target_delete, 'orphan') AS on_target_delete,
                  COALESCE(data_classification, 'general') AS data_classification,
                  COALESCE(sensitivity, 'internal') AS sensitivity,
                  COALESCE(sensitivity_confirmed, false) AS sensitivity_confirmed,
                  {OPTIONS_SQL} AS options
           FROM attribute_info
           WHERE (is_active IS NULL OR is_active = true)
             AND entity_ref IS NOT NULL AND logicalname IS NOT NULL AND logicalname <> ''
           ORDER BY entity_ref"#
    ))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut attrs_by_entity: HashMap<Uuid, Vec<AttrInfo>> = HashMap::with_capacity(entities.len());
    for row in attrs {
        attrs_by_entity
            .entry(row.entity_ref)
            .or_default()
            .push(row.into());
    }

    let mut by_logicalname = HashMap::with_capacity(entities.len());
    for row in entities {
        let attrs = attrs_by_entity.remove(&row.id).unwrap_or_default();
        by_logicalname.insert(
            row.logicalname.clone(),
            EntityMeta {
                entity_id: row.id,
                logicalname: row.logicalname,
                attrs,
                is_append_only: row.is_append_only.unwrap_or(false),
                primary_name_attribute: row.primary_name_attribute,
            },
        );
    }

    Ok(EntityMetaRegistry::from_map(by_logicalname)
        .with_aliases(load_aliases(db).await?)
        .with_schema(fetch_schema_facts(db, None).await?))
}

/// AA7-T2: the schema route's facts for the live entities `entity_ids`
/// (every live entity for `None`): two queries, as the route ran them.
pub async fn fetch_schema_facts(
    db: &DbPool,
    entity_ids: Option<&[Uuid]>,
) -> Result<HashMap<Uuid, SchemaEntity>, AppError> {
    let entities: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, name FROM entity_info \
         WHERE (is_active IS NULL OR is_active = true) \
           AND logicalname IS NOT NULL AND logicalname <> '' \
           AND ($1::uuid[] IS NULL OR id = ANY($1))",
    )
    .bind(entity_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if entities.is_empty() {
        return Ok(HashMap::new());
    }
    let found: Vec<Uuid> = entities.iter().map(|(id, _)| *id).collect();
    let rows: Vec<(Uuid, SchemaField)> = {
        #[derive(sqlx::FromRow)]
        struct Row {
            entity_ref: Uuid,
            #[sqlx(flatten)]
            field: SchemaField,
        }
        let rows: Vec<Row> = sqlx::query_as(
            r#"SELECT a.entity_ref,
                      a.id,
                      a.logicalname,
                      a.name                     AS display_name,
                      a."type"                   AS field_type_int,
                      a.required,
                      a.lookup_entity_ref,
                      lei.logicalname            AS lookup_entity_ln,
                      lei.primary_name_attribute AS lookup_display_field,
                      a.options
               FROM attribute_info a
               LEFT JOIN entity_info lei ON lei.id = a.lookup_entity_ref
               WHERE a.entity_ref = ANY($1) AND (a.is_active IS NULL OR a.is_active = true)
               ORDER BY a.entity_ref, a.sort_order ASC, a.created_at ASC NULLS LAST, a.logicalname"#,
        )
        .bind(&found)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        rows.into_iter().map(|r| (r.entity_ref, r.field)).collect()
    };
    let mut schema: HashMap<Uuid, SchemaEntity> = entities
        .into_iter()
        .map(|(id, display_name)| {
            (
                id,
                SchemaEntity {
                    display_name,
                    fields: Vec::new(),
                },
            )
        })
        .collect();
    for (entity_ref, field) in rows {
        if let Some(entity) = schema.get_mut(&entity_ref) {
            entity.fields.push(field);
        }
    }
    Ok(schema)
}

/// Y12-T8: every live attribute alias, by entity: an old name to the
/// attribute's current name (a second rename moves the alias with it).
pub async fn load_aliases(
    db: &DbPool,
) -> Result<HashMap<String, HashMap<String, String>>, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT a.entity, a.old_name, ai.logicalname \
           FROM attribute_alias a \
           JOIN attribute_info ai ON ai.id = a.attribute_id \
          WHERE a.expires_at > now() AND (ai.is_active IS NULL OR ai.is_active = true) \
            AND ai.logicalname IS NOT NULL AND ai.logicalname <> a.old_name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (entity, old_name, current) in rows {
        out.entry(entity).or_default().insert(old_name, current);
    }
    Ok(out)
}

/// Re-fetches one entity's row + active attributes — the single-entity
/// counterpart of `build_registry`, used to patch one key of the registry
/// instead of rebuilding it. `None` means the entity is gone or inactive
/// (soft- or hard-deleted since the change-log row was written).
///
/// A thin wrapper over `fetch_entity_snapshots` so there is exactly one copy
/// of the snapshot `WHERE`/`COALESCE` clauses to keep in step with
/// `build_registry`.
pub async fn fetch_entity_snapshot(
    db: &DbPool,
    entity_id: Uuid,
) -> Result<Option<EntityMeta>, AppError> {
    Ok(fetch_entity_snapshots(db, &[entity_id])
        .await?
        .remove(&entity_id))
}

/// Re-fetches a whole set of entities' rows + active attributes in **two**
/// queries (`= ANY($1)` over each table), whatever the set's size — the batched
/// counterpart of `fetch_entity_snapshot`, so a catch-up that touches N
/// entities costs 2 round trips rather than 2N sequential ones.
///
/// Returned map is keyed by entity id. An id that is absent from the result was
/// gone or inactive at query time; callers distinguish "gone" from "found" by
/// diffing the requested ids against the returned keys.
pub async fn fetch_entity_snapshots(
    db: &DbPool,
    entity_ids: &[Uuid],
) -> Result<HashMap<Uuid, EntityMeta>, AppError> {
    if entity_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let entities: Vec<EntityRow> = sqlx::query_as(
        "SELECT id, COALESCE(logicalname, '') AS logicalname, is_append_only,
                primary_name_attribute
         FROM entity_info
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL AND logicalname <> ''",
    )
    .bind(entity_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if entities.is_empty() {
        return Ok(HashMap::new());
    }

    // Bind the ids that actually came back, not the requested set: attributes
    // of an entity that turned out inactive would be fetched and discarded.
    let found_ids: Vec<Uuid> = entities.iter().map(|row| row.id).collect();

    let attrs: Vec<AttrRow> = sqlx::query_as(&format!(
        r#"SELECT entity_ref,
                  COALESCE(logicalname, '')      AS logicalname,
                  COALESCE("type", 3)            AS field_type_int,
                  COALESCE(required, false)       AS is_required,
                  max_length,
                  COALESCE(is_sensitive, false)  AS is_sensitive,
                  COALESCE(is_write_restricted, false) AS is_write_restricted,
                  COALESCE(is_sortable, false)   AS is_sortable,
                  COALESCE(is_filterable, false) AS is_filterable,
                  lookup_entity_ref,
                  COALESCE(on_target_delete, 'orphan') AS on_target_delete,
                  COALESCE(data_classification, 'general') AS data_classification,
                  COALESCE(sensitivity, 'internal') AS sensitivity,
                  COALESCE(sensitivity_confirmed, false) AS sensitivity_confirmed,
                  {OPTIONS_SQL} AS options
           FROM attribute_info
           WHERE (is_active IS NULL OR is_active = true)
             AND entity_ref = ANY($1) AND logicalname IS NOT NULL AND logicalname <> ''"#
    ))
    .bind(&found_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut attrs_by_entity: HashMap<Uuid, Vec<AttrInfo>> = HashMap::with_capacity(entities.len());
    for row in attrs {
        attrs_by_entity
            .entry(row.entity_ref)
            .or_default()
            .push(row.into());
    }

    Ok(entities
        .into_iter()
        .map(|row| {
            let attrs = attrs_by_entity.remove(&row.id).unwrap_or_default();
            (
                row.id,
                EntityMeta {
                    entity_id: row.id,
                    logicalname: row.logicalname,
                    attrs,
                    is_append_only: row.is_append_only.unwrap_or(false),
                    primary_name_attribute: row.primary_name_attribute,
                },
            )
        })
        .collect())
}

/// Patches `base` with `rows` and returns the result — never mutates `base`
/// in place, so callers build the fully patched map before doing one atomic
/// `MetadataCache::swap` (readers never observe an intermediate state).
///
/// Rows are deduped by `entity_ref`, keeping only the last occurrence,
/// before any re-query happens: an `upsert` re-reads current truth rather
/// than applying a delta, so replaying an earlier row for the same entity in
/// the same batch is redundant work. This is what keeps a bulk edit (many
/// writes touching a handful of entities) proportional to entities touched,
/// not edits made.
///
/// The deduped `upsert` set is then re-queried in one batch
/// (`fetch_entity_snapshots`), so a catch-up touching N entities costs two
/// round trips rather than 2N sequential ones. `delete` rows are applied
/// first — they need no query, and settling them before the batch makes the
/// outcome deterministic when a delete and an upsert in the same batch collide
/// on one logicalname (the live entity wins), where iterating the `HashMap`
/// in one pass left it up to hash order.
pub async fn apply_change_log(
    db: &DbPool,
    base: &EntityMetaRegistry,
    rows: &[ChangeLogRow],
) -> Result<EntityMetaRegistry, AppError> {
    let mut by_logicalname = base.by_logicalname.clone();
    let mut schema = base.schema.clone();

    let mut deduped: HashMap<Uuid, &ChangeLogRow> = HashMap::with_capacity(rows.len());
    for row in rows {
        deduped.insert(row.entity_ref, row);
    }

    let mut upserts: Vec<&ChangeLogRow> = Vec::with_capacity(deduped.len());
    for row in deduped.into_values() {
        match row.kind.as_str() {
            "delete" => {
                by_logicalname.remove(&row.logicalname);
                schema.remove(&row.entity_ref);
            }
            _ /* "upsert" */ => upserts.push(row),
        }
    }

    // Deduped by `entity_ref` above, so this id set carries no duplicates and
    // each fetched snapshot is consumed exactly once.
    let upsert_ids: Vec<Uuid> = upserts.iter().map(|row| row.entity_ref).collect();
    let mut fetched = fetch_entity_snapshots(db, &upsert_ids).await?;

    for row in upserts {
        match fetched.remove(&row.entity_ref) {
            Some(meta) => {
                by_logicalname.insert(meta.logicalname.clone(), meta);
            }
            None => {
                // Gone or inactive by the time we re-queried (e.g. a later
                // delete already landed) — the registry must not keep serving
                // it.
                by_logicalname.remove(&row.logicalname);
            }
        }
    }

    // Y12-T8: a rename changes an entity's aliases; deletes alone keep them.
    let aliases = if upsert_ids.is_empty() {
        base.aliases.clone()
    } else {
        load_aliases(db).await?
    };
    // AA7-T2: the schema route's facts follow the same entities.
    if !upsert_ids.is_empty() {
        let mut fresh = fetch_schema_facts(db, Some(&upsert_ids)).await?;
        for id in &upsert_ids {
            match fresh.remove(id) {
                Some(entity) => {
                    schema.insert(*id, entity);
                }
                None => {
                    schema.remove(id);
                }
            }
        }
    }
    Ok(EntityMetaRegistry::from_map(by_logicalname)
        .with_aliases(aliases)
        .with_schema(schema))
}

const SNAPSHOT_REDIS_KEY: &str = "attome-core:metadata:registry_snapshot";

/// P1.15 §4(c)/(d): metadata pub/sub + its snapshot are a cache-coherence
/// concern, not a security control — degrade-and-recover is correct here (the
/// caller already falls back to a full Postgres rebuild on any error), so
/// this bounds latency only, it does not change the fail-open-to-stale
/// posture that's already correct per guidelines' Multi-Server section.
const OP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Serialize, Deserialize)]
struct RegistrySnapshot {
    log_id: i64,
    registry: EntityMetaRegistry,
}

/// Best-effort — a Redis hiccup here must never fail a rebuild; the caller
/// already has a correct in-memory registry regardless of whether the
/// snapshot write succeeds.
pub async fn save_snapshot(
    redis: &Store,
    log_id: i64,
    registry: &EntityMetaRegistry,
) -> Result<(), AppError> {
    let json = serde_json::to_string(&RegistrySnapshot {
        log_id,
        registry: registry.clone(),
    })
    .map_err(AppError::internal)?;

    tokio::time::timeout(OP_TIMEOUT, redis.set(SNAPSHOT_REDIS_KEY, &json, None))
        .await
        .map_err(|_| AppError::internal("redis metadata snapshot write timed out"))??;

    Ok(())
}

/// Whether every `entity_id` the registry claims is still a real, active
/// `entity_info` row. `false` means at least one logicalname maps to
/// an id Postgres has no matching row for at all — not "changed since", which
/// the watermark/change-log catch-up already handles, but "never existed in
/// this database" — the signature of a Redis snapshot left over from a
/// different or since-reset Postgres volume that happens to share the same
/// Redis instance. `attome-server::system::pre_warm_registry` is the one caller:
/// it treats `false` the same as an unusable snapshot (discard, rebuild from
/// Postgres) rather than handing a caller an id that will fail a foreign-key
/// write the moment it's used.
pub async fn verify_ids_exist(
    db: &DbPool,
    registry: &EntityMetaRegistry,
) -> Result<bool, AppError> {
    if registry.is_empty() {
        return Ok(true);
    }
    let ids: Vec<Uuid> = registry.iter().map(|e| e.entity_id).collect();
    let known: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_info \
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&ids)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(known as usize == ids.len())
}

/// `Ok(None)` covers both "no snapshot yet" (cold Redis, first boot) and "the
/// stored snapshot didn't decode" — either way the caller falls back to a
/// full rebuild, never a hard error. Returns `(registry, log_id)` — same
/// tuple order as `build_registry`'s callers use for a full rebuild.
pub async fn load_snapshot(redis: &Store) -> Result<Option<(EntityMetaRegistry, i64)>, AppError> {
    let json: Option<String> = tokio::time::timeout(OP_TIMEOUT, redis.get(SNAPSHOT_REDIS_KEY))
        .await
        .map_err(|_| AppError::internal("redis metadata snapshot read timed out"))?
        .map_err(AppError::internal)?;

    let Some(json) = json else { return Ok(None) };

    match serde_json::from_str::<RegistrySnapshot>(&json) {
        Ok(snap) => Ok(Some((snap.registry, snap.log_id))),
        Err(e) => {
            tracing::warn!(error = %e, "metadata registry snapshot failed to decode — falling back to full rebuild");
            Ok(None)
        }
    }
}

// ── Tests (P-audit-item-17: pure-logic denial/degrade paths, no DB) ──────────
// `record_is_held` (legal_hold.rs) and `apply_change_log`'s "upsert" branch
// are DB-only and have no pure-unit-testable seam — see the audit item's TODO
// note for those. What's covered here is the everything-else-is-degrade-not-
// reject behavior these two enums and the registry's lookup methods actually
// have, none of which existed as tests before.
#[cfg(test)]
mod tests {
    use super::*;

    fn attr_with(is_sensitive: bool, is_write_restricted: bool) -> AttrInfo {
        AttrInfo {
            logicalname: "amount".to_owned(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive,
            is_write_restricted,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::Orphan,
            data_classification: DataClassification::General,
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    /// D-507: the write rule is `is_sensitive OR is_write_restricted` — the
    /// full truth table, so neither flag can silently stop counting.
    #[test]
    fn field_write_grant_is_required_when_sensitive_or_write_restricted() {
        for (is_sensitive, is_write_restricted, expected) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(
                attr_with(is_sensitive, is_write_restricted).requires_field_write_grant(),
                expected,
                "is_sensitive={is_sensitive} is_write_restricted={is_write_restricted}"
            );
        }
    }

    /// A registry snapshot serialized before D-507 has no
    /// `is_write_restricted` key; it must decode as unrestricted (the column's
    /// own default) rather than fail the whole registry load.
    #[test]
    fn a_pre_d507_attr_snapshot_decodes_as_not_write_restricted() {
        let mut json = serde_json::to_value(attr_with(false, true)).expect("serialize");
        json.as_object_mut()
            .expect("object")
            .remove("is_write_restricted");
        let decoded: AttrInfo = serde_json::from_value(json).expect("decode");
        assert!(!decoded.is_write_restricted);
    }

    #[test]
    fn on_target_delete_from_db_str_degrades_unrecognized_input_to_orphan() {
        // The column has a CHECK constraint so this should never see a real
        // unrecognized value in production — this proves the defensive
        // fallback itself, not a scenario expected to occur.
        assert_eq!(
            OnTargetDelete::from_db_str("garbage"),
            OnTargetDelete::Orphan
        );
        assert_eq!(OnTargetDelete::from_db_str(""), OnTargetDelete::Orphan);
        assert_eq!(
            OnTargetDelete::from_db_str("restrict"),
            OnTargetDelete::Restrict
        );
        assert_eq!(
            OnTargetDelete::from_db_str("cascade-deactivate"),
            OnTargetDelete::CascadeDeactivate
        );
    }

    #[test]
    fn on_target_delete_round_trips_through_db_str() {
        for variant in [
            OnTargetDelete::Restrict,
            OnTargetDelete::Orphan,
            OnTargetDelete::CascadeDeactivate,
        ] {
            assert_eq!(OnTargetDelete::from_db_str(variant.as_db_str()), variant);
        }
    }

    #[test]
    fn data_classification_from_db_str_degrades_unrecognized_input_to_general() {
        assert_eq!(
            DataClassification::from_db_str("garbage"),
            DataClassification::General
        );
        assert_eq!(
            DataClassification::from_db_str("personal"),
            DataClassification::Personal
        );
        assert_eq!(
            DataClassification::from_db_str("sensitive_special_category"),
            DataClassification::SensitiveSpecialCategory
        );
    }

    #[test]
    fn data_classification_round_trips_through_db_str() {
        for variant in [
            DataClassification::General,
            DataClassification::Personal,
            DataClassification::SensitiveSpecialCategory,
        ] {
            assert_eq!(
                DataClassification::from_db_str(variant.as_db_str()),
                variant
            );
        }
    }

    #[test]
    fn registry_get_returns_none_for_an_unregistered_logicalname() {
        let registry = EntityMetaRegistry::default();
        assert!(registry.get("does_not_exist").is_none());
    }

    #[test]
    fn registry_get_by_id_returns_none_for_an_unregistered_id() {
        let registry = EntityMetaRegistry::default();
        assert!(registry.get_by_id(Uuid::now_v7()).is_none());
    }

    #[test]
    fn registry_dependents_of_returns_empty_for_an_unregistered_entity() {
        let registry = EntityMetaRegistry::default();
        assert!(registry.dependents_of(Uuid::now_v7()).is_empty());
    }

    #[test]
    fn registry_get_finds_an_inserted_entity_and_rejects_every_other_key() {
        let mut by_logicalname = HashMap::new();
        let entity_id = Uuid::now_v7();
        by_logicalname.insert(
            "account".to_owned(),
            EntityMeta {
                entity_id,
                logicalname: "account".to_owned(),
                attrs: vec![],
                is_append_only: false,
                primary_name_attribute: None,
            },
        );
        let registry = EntityMetaRegistry::from_map(by_logicalname);

        assert!(registry.get("account").is_some());
        assert!(registry.get("contact").is_none());
        assert!(registry.get_by_id(entity_id).is_some());
        assert!(registry.get_by_id(Uuid::now_v7()).is_none());
    }

    fn meta(logicalname: &str, entity_id: Uuid) -> EntityMeta {
        EntityMeta {
            entity_id,
            logicalname: logicalname.to_owned(),
            attrs: vec![],
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    /// Every constructor funnels through `from_map`, so `get` and `get_by_id`
    /// must name the same `EntityMeta` for every entry — including after the
    /// registry has been rebuilt from the Redis snapshot wire shape, which
    /// carries `by_logicalname` only and must re-derive `by_id` on decode.
    #[test]
    fn registry_get_by_id_and_get_agree_after_a_snapshot_rebuild() {
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
        let registry = EntityMetaRegistry::from_entities(vec![
            meta("account", ids[0]),
            meta("contact", ids[1]),
            meta("lead", ids[2]),
        ]);

        let assert_agree = |reg: &EntityMetaRegistry| {
            assert_eq!(reg.len(), 3);
            for (name, id) in [("account", ids[0]), ("contact", ids[1]), ("lead", ids[2])] {
                let by_name = reg.get(name).expect("present by name");
                let by_id = reg.get_by_id(id).expect("present by id");
                assert_eq!(by_name.entity_id, id);
                assert_eq!(by_id.logicalname, name);
                assert!(
                    std::ptr::eq(by_name, by_id),
                    "both lookups must resolve the same entry"
                );
            }
            assert!(reg.get_by_id(Uuid::now_v7()).is_none());
        };
        assert_agree(&registry);

        // The Redis pre-warm path: serialize, decode through the wire shape,
        // and the derived index must come back identical.
        let json = serde_json::to_string(&registry).expect("serialize");
        assert!(
            !json.contains("by_id"),
            "by_id is derived and must never be on the wire: {json}"
        );
        let rebuilt: EntityMetaRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_agree(&rebuilt);
    }

    /// `from_entities` is last-entry-wins on a duplicate logicalname (the
    /// loader's rule); the loser's id must not be resolvable either, or
    /// `get_by_id` would hand back an entity `get` no longer serves.
    #[test]
    fn registry_get_by_id_forgets_the_loser_of_a_duplicate_logicalname() {
        let loser = Uuid::now_v7();
        let winner = Uuid::now_v7();
        let registry = EntityMetaRegistry::from_entities(vec![
            meta("account", loser),
            meta("account", winner),
        ]);

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get("account").unwrap().entity_id, winner);
        assert!(registry.get_by_id(winner).is_some());
        assert!(registry.get_by_id(loser).is_none());
    }
}
