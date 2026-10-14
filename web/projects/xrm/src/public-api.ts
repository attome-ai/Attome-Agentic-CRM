// Root entry — deliberately minimal. Everything component/service-level lives
// in a secondary entry point (@attome/xrm/entity, /admin, /security, /s2s,
// /license, /jobs, /profiler, /query, /forms, /shell) so a `loadComponent()`
// lazy route only pulls in the feature it actually renders instead of the
// whole library (see DECISIONS.md — packaging: xrm barrel splitting).
// Import a specific secondary entry point, not this one, unless you genuinely
// only need these framework-agnostic types.
export type {
  FieldType, FieldSchema, EntitySchema, RelationshipSchema,
  ChoiceOptions, ChoiceStyle, LookupOptions, FileOptions, TextOptions, DateOptions,
  // U9 (D-604) — formula field options.
  FormulaOptions, FormulaResultType,
  EntityRecord, LookupMeta,
  ListFilter, ListSort, ListParams, FilterOp,
  // D-789 — business-rule condition and policy types (EntitySchema.business_rules).
  BusinessRuleOp, ConditionAll, ConditionAny, ConditionExpression, ConditionLeaf, ConditionTree,
  PolicyType, RuleSeverity, SetMode, PolicyDef, BusinessRuleClient, ConditionFieldKind,
} from './lib/types';
