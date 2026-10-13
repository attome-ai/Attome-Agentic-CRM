// Wire shapes for the `declarative_widget` widget type — mirrors
// `crates/engine/attome-dashboard/src/declarative_widget.rs`'s Rust types exactly
// (field names, enum tags) since a config saved through
// `POST /api/v1/attome-dashboard/widget/validate-config` must deserialize
// identically on both sides. Keep the two in lockstep by hand (this widget
// type has no `#[serde(...)]` -> TypeScript codegen today, same as every
// other hand-mirrored wire type in this workspace) rather than drifting.

export type ConditionOperator =
  | 'eq'
  | 'ne'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'contains'
  | 'is_empty'
  | 'is_not_empty';

export interface Condition {
  field: string;
  operator: ConditionOperator;
  value?: unknown;
}

export interface ConditionalColorRule {
  when: Condition;
  /** `#RGB`/`#RRGGBB`/`#RRGGBBAA` — anything else is treated as absent by
   * the renderer (fail-safe, see `declarative-widget.util.ts`). */
  color: string;
}

export type ColumnFormat =
  | { kind: 'text' }
  | { kind: 'number'; decimals?: number }
  | { kind: 'date'; pattern?: string }
  | { kind: 'currency'; currency_code?: string }
  | { kind: 'badge' };

/** A cell's outbound link — `external` is a scheme-checked URL template with
 * `{field}` placeholders; `action` names an `attome-ai` action id. The renderer
 * shows an `action` cell as plain text: nothing invokes dashboard actions yet
 * (Dashboard 10/10 Phase 4.5), and publish warns about the config. */
export type LinkSpec =
  | { kind: 'external'; target: string }
  | { kind: 'action'; action_id: string };

export interface DeclarativeWidgetColumn {
  field: string;
  label: string;
  label_ar?: string;
  format?: ColumnFormat;
  conditional_colors?: ConditionalColorRule[];
  link?: LinkSpec;
}

export interface DeclarativeWidgetConfig {
  query_ref: string;
  columns: DeclarativeWidgetColumn[];
  actions?: string[];
}
