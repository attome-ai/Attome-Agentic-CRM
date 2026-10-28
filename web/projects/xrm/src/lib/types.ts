// Mirrors Rust attome-core types

export type FieldType =
  | 'text' | 'number' | 'currency' | 'date' | 'bool' | 'choice' | 'lookup' | 'file' | 'icon' | 'color'
  // U9 (D-604, D-605): a computed `formula` (read-only, never sent back),
  // sanitized `rich_text` HTML, and an `image` (a `file` limited to images).
  | 'formula' | 'rich_text' | 'image'
  // Y2-T1: a moment (TIMESTAMPTZ); `date` is a calendar day.
  | 'date_time'
  // A2-T1: a time of day (TIME), `HH:MM[:SS]`.
  | 'time'
  // A2-T3: a point `{lat, lng}` and a JSON document (both JSONB).
  | 'geolocation' | 'json';

// Mirrors attome_core::formula::FormulaOptions (B-R6, D-604). The value
// is computed by the server on every write; the form shows it read-only.
export type FormulaResultType = 'text' | 'number' | 'currency' | 'date' | 'date_time' | 'bool';
// A9-T1: `read_time` is computed on every read (never stale over today());
// `stored` (the default) on every write.
export interface FormulaOptions {
  expression: string; result_type: FormulaResultType; generated?: boolean; mode?: 'stored' | 'read_time';
}

// Per-value display hints for a `choice` field — a colored pill and/or icon
// in the grid instead of plain text. Mirrors attome_field::ChoiceStyle.
export interface ChoiceStyle { color?: string | null; icon?: string | null; }
export interface ChoiceOptions {
  choices:        string[];
  multi:          boolean;
  choice_styles?: Record<string, ChoiceStyle> | null;
  // M05/D-426: `choices[i]` -> its resolved label (requested locale ->
  // deployment default -> the raw stored value itself, since a choice value
  // has no separate "base display name" the way an entity/attribute does).
  // Only present when at least one option actually has a translated label —
  // `crates/engine/attome-api/src/schema.rs::get_schema` omits the key entirely
  // otherwise, so an untranslated entity's `options` shape is unchanged.
  option_labels?: Record<string, string> | null;
}
export interface LookupOptions {
  target_entity_id:   string | null;
  target_entity_name: string | null;  // resolved server-side from target_entity_id
  display_field:      string | null;
}
// Mirrors attome_field::FileOptions. `multi: true` -> JSONB array-of-keys column
// (multi-attachment.component.ts); `multi: false`/absent -> the original
// scalar TEXT column (field-input.component.ts's inline file case).
export interface FileOptions { multi: boolean; }

// Mirrors attome_field::DateOptions (AG1-T7): how a date field is shown and
// entered; absent follows the person's own calendar setting.
export interface DateOptions { display_calendar?: 'gregorian' | 'hijri' | 'both' | null; }

// Mirrors attome_field::TextOptions (migration 0029's `options` JSONB — no new
// column). `text_type` is C-29 (M01 §7)'s metadata-driven replacement for
// `field-input.component.ts` guessing "email"/"tel"/"url" from the field's
// *name*: an admin sets it explicitly through the field editor; a field with
// no `text_type` (every field created before this option existed) keeps
// falling back to that same name heuristic.
export interface TextOptions {
  pattern?:          string | null;
  mask_description?: string | null;
  text_type?:        'text' | 'email' | 'tel' | 'url' | null;
  /** A2-T2: a built-in format every write must match (`attome_field::formats`). */
  format?:           string | null;
}

// Mirrors attome_field::NumberOptions: an inclusive range for number and
// currency fields.
export interface NumberOptions { min?: number | null; max?: number | null; }

export interface FieldSchema {
  id:           string;
  entity_id:    string;
  name:         string;        // logicalname — used as form control key
  display_name: string;        // human-readable label
  field_type:   FieldType;
  options:      ChoiceOptions | LookupOptions | FileOptions | TextOptions | FormulaOptions | DateOptions | NumberOptions | null;
  sort_order:   number;
  is_required:  boolean;
}

// ── Business rules (D-789) ────────────────────────────────────────────────────
// Mirrors `crates/engine/attome-core/src/business_rules.rs` (`ConditionTree`,
// `ConditionLeaf`, `BusinessRuleOp`, `PolicyDef`, `PolicyType`, `Severity`,
// `SetMode`) and `crates/engine/attome-api/src/schema.rs::BusinessRuleClient`.
// The runtime helpers (operator table, guards) are in
// `@attome/xrm/core/admin/data`; the client evaluator in `@attome/xrm/core/entity`.
// Kept hand-written and narrower than the generated `ApiComponents['schemas']`
// `ConditionTree`/`PolicyDef` (an omitted key is absent, never `null`:
// `skip_serializing_if`); `business-rules.service.ts` (`Narrows<>`) checks at
// compile time that they stay assignable to the generated ones.

/** Leaf operators (`BusinessRuleOp`, snake_case serde). */
export type BusinessRuleOp =
  | 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte'
  | 'in' | 'not_in' | 'contains' | 'starts_with'
  | 'is_empty' | 'is_not_empty';

/** `{"all": [...]}` — AND. The root `{"all": []}` means "always". */
export interface ConditionAll { all: ConditionTree[] }
/** `{"any": [...]}` — OR (at least one child). */
export interface ConditionAny { any: ConditionTree[] }
/** Advanced leaf: a `attome-rules` boolean. Server-only; never delivered to the form. */
export interface ConditionExpression { expression: string }
/** Structured leaf. `value` is absent for `is_empty`/`is_not_empty`, a list for `in`/`not_in`. */
export interface ConditionLeaf {
  field: string;
  op: BusinessRuleOp;
  value?: unknown;
}

/** `ConditionTree` (`#[serde(untagged)]`). */
export type ConditionTree = ConditionAll | ConditionAny | ConditionExpression | ConditionLeaf;

export type PolicyType = 'hidden' | 'disabled' | 'error' | 'set_value' | 'required' | 'allowed_values'
  | 'add_tag' | 'remove_tag';
export type RuleSeverity = 'error' | 'warning';
export type SetMode = 'always' | 'default';

/**
 * `PolicyDef`: `type` is the policy; every other key is omitted when unset
 * (`skip_serializing_if`). `ordinal` is `#[serde(skip)]` — the list order is
 * the policy order.
 */
export interface PolicyDef {
  type: PolicyType;
  field?: string;
  message?: string;
  severity?: RuleSeverity;
  value?: unknown;
  expression?: string;
  mode?: SetMode;
}

/** One rule as `GET /api/v1/schema/{entity}` delivers it (`BusinessRuleClient`). */
export interface BusinessRuleClient {
  name: string;
  display_name: string | null;
  condition: ConditionTree;
  /** Only `hidden`, `disabled` and field-attached `error` policies are delivered. */
  policies: PolicyDef[];
}

/**
 * How a field behaves inside a condition (`ConditionFieldKind`). A formula
 * field is its result type; rich text, file and image cannot be a leaf.
 */
export type ConditionFieldKind =
  | 'text' | 'number' | 'date' | 'bool' | 'choice' | 'multi_choice' | 'lookup';

export interface EntitySchema {
  id:            string;
  name:          string;
  plural_name:   string;
  fields:        FieldSchema[];
  relationships: RelationshipSchema[];
  /**
   * D-789 section 5 (additive): the active business rules that apply to the
   * caller and carry a client-side policy (hidden, disabled, field-attached
   * error) under a structured condition. UX only; the server enforces.
   */
  business_rules?: BusinessRuleClient[];
  /** L1-T9: master data (golden records from source systems); absent when not. */
  is_master?: boolean;
  /**
   * Q10-T11: the operations the caller may perform on this entity (`read`,
   * `create`, `update`, `delete`, `assign`, `share`, `export`, `bulk`), decided
   * as the API decides them. Screens hide what is not listed.
   */
  allowed_actions?: string[];
}

// M01 Core P3 gap (D-455) — one `relationship_info` row touching
// this entity, oriented from the entity's own point of view.
// `crates/engine/attome-api/src/schema.rs::RelationshipSchemaEntry`. Previously
// (pre-D-455) this interface described a speculative shape
// (`from_entity_id`/`to_entity_id`/`rel_type`) that `get_schema` never
// actually populated — `relationships` was hardcoded to `[]`. This is the
// real, now-populated wire shape.
export interface RelationshipSchema {
  name:         string;
  // The label THIS entity's own form should show for the sub-grid of
  // linked `other_entity` records.
  label:        string;
  other_entity: string;
  cascade:      'restrict' | 'orphan' | 'cascade_deactivate';
}

// ── Record ────────────────────────────────────────────────────────────────────

// Mirrors attome-api's LookupMeta (D-077) — one entry per populated lookup
// field, resolved server-side from the target's primary_name_attribute.
// `exists: false` means the target row is gone (hard-deleted or never
// existed); `is_active: false` with `exists: true` means soft-deleted.
export interface LookupMeta {
  exists:    boolean;
  is_active: boolean;
  name:      string | null;
}

export interface EntityRecord {
  id:          string;
  entity_id:   string;
  data:        Record<string, unknown>;
  /** Per-lookup-field display metadata, keyed by field name. Populated on
   * single-record reads (D-077) and on query/execute list pages for a
   * single-entity query — absent for a multi-entity/custom query, which has
   * no single attribute set to resolve lookup targets against. */
  lookups?:    Record<string, LookupMeta>;
  created_at:  string;
  updated_at:  string;
  row_version: number;
}

// ── Query params ──────────────────────────────────────────────────────────────

export type FilterOp = 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'null' | 'notnull';

export interface ListFilter {
  field: string;
  op:    FilterOp;
  value?: string;
}

export interface ListSort { field: string; dir: 'asc' | 'desc'; }

export interface ListParams {
  filters?: ListFilter[];
  sorts?:   ListSort[];
  limit?:   number;
  offset?:  number;
}

