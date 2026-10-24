// Services and wire types only — no components (D-314).
//
// This is the highest-traffic of the three data entry points: `shell`,
// `security` (record-shares, role-entity-access) and `query` (view-editor) all
// want `AdminService`/`EntityMeta` for entity metadata, and each of them used to
// pull `EntityManagerComponent`, `EntityEditorComponent`, `SidebarManagerComponent`
// and `SystemSettingsComponent` along with it. Anything outside `admin/` imports
// this entry point; the components stay behind `@attome/xrm/admin`.
//
// This exports `admin.service.ts`'s *whole* surface, which is wider than what
// `@attome/xrm/admin` re-exports: the scaffold and autovalue types were only
// ever reached by a relative `./admin.service` import from a sibling component,
// and those imports are now package-path imports that need a real export. The
// parent barrel deliberately still re-exports only what it always did, so this
// split stays additive to the published API.
export { AdminService } from './services/admin.service';
export type {
  EntityMeta, EntityDetail, AttributeMeta,
  CreateEntityBody, UpdateEntityBody,
  CreateAttributeBody, UpdateAttributeBody,
  SidebarItem,
  SidebarAdminItem, SidebarPrivilege, SidebarMutation,
  CalendarAdminItem, CalendarMutation, CalendarTimeRange,
  CalendarHoliday, CalendarHolidayMutation,
  CalendarException, CalendarExceptionMutation,
  MetadataLabel, MetadataLabelMutation,
  RelationshipDef, CreateRelationshipBody, UpdateRelationshipBody,
} from './services/admin.service';
export { XRM_FIELD_TYPES } from './services/admin.service';
export type { XrmFieldType } from './services/admin.service';
export type { ScaffoldKind, DevToolsInfo, ScaffoldResult } from './services/admin.service';
export { AUTOVALUE_ENTITY, AUTOVALUE_RESET_SCOPES } from './services/admin.service';
export type {
  AutoValueResetScope, AutoValueRule, AutoValueMutation,
} from './services/admin.service';
// PERF-3 - consumed by `@attome/xrm/core/entity`'s schema cache. Exported from
// this `/data` entry point precisely so that consumer never has to import a
// component barrel to reach it (D-314).
export { EntityMetadataChangeService } from './services/entity-metadata-change.service';
export { SidebarPreferencesService } from './services/sidebar-preferences.service';
export type { SidebarStyle } from './services/sidebar-preferences.service';
// M02/D-412 — the typed runtime-settings API System Settings drives.
export { SettingsService } from './services/settings.service';
export { CacheAdminService } from './services/cache-admin.service';
export type { CacheStatsRow } from './services/cache-admin.service';
export { SecretsAdminService } from './services/secrets-admin.service';
export type { SecretInventoryRow, ConfigStartRow, ConfigChange } from './services/secrets-admin.service';
export type { SettingValueView, SettingListResponse, SettingScope } from './services/settings.service';
// M95/D-430 — the feature-flag client and its `*xrmFeatureFlag` structural
// directive companion.
export { FeatureFlagsService } from './services/feature-flags.service';
export type {
  FeatureFlagPolicy, FeatureFlagView, FeatureFlagListResponse, EffectiveFeaturesResponse,
} from './services/feature-flags.service';
export { FeatureFlagDirective } from './services/feature-flag.directive';
// D-778 — Module Management's client (moved here from the retired
// `@attome/xrm/license/data` entry point). The sidebar manager reads it too.
export { ModuleAdminService } from './services/module-admin.service';
export type {
  ModuleConfiguration, RuntimeModule, ProjectSection, ProjectArea,
} from './services/module-admin.service';
// D-432 / M13 — match-rule/survivorship-rule admin CRUD and the duplicate
// candidate steward queue. Exported from the `/data` entry point (not just
// from the component-bearing `admin/duplicates-manager` barrel) so the
// record form's "possible duplicate" banner (`@attome/xrm/core/entity`) can
// use `DuplicatesService`/`DuplicateCandidate` without pulling in the
// admin-only review page component.
export { DuplicatesService, MATCH_COMPARATORS, ON_SAVE_MODES } from './services/duplicates.service';
export type {
  MatchComparator, MatchField, MatchRule, MatchRulesPage, CreateMatchRuleBody,
  SurvivorshipStrategy, SurvivorshipRule, SurvivorshipRulesPage, CreateSurvivorshipRuleBody,
  SourceSystemRankConfig,
  CandidateStatus, DuplicateCandidate, DuplicateCandidatesPage, MergeResponse,
  OnSave, DuplicateCheckResult, MergePicks, MergePreview, MergeUndone,
  FieldExplanation, CandidateExplanation, DuplicateStats, RulePreview, RuleProposal,
} from './services/duplicates.service';
// M36 Phase 0+1 (Predictive Intelligence, D-473) — same "exported from the
// /data entry point so the record form's banner can use it without pulling
// in an admin-only page" reasoning as `DuplicatesService` above. This module
// has no admin-only review page yet, only the banner consumer.
export { PredictionsService } from './services/predictions.service';
export type { Prediction, PredictionsPage, FeatureContribution } from './services/predictions.service';
// D-789 (business rules; D-790 removed `/api/v1/admin/rules*`) — the
// `/api/v1/admin/business-rules` client, and the condition/policy wire types
// and operator table the record form's evaluator (`@attome/xrm/core/entity`)
// shares with the business-rule editor.
export { BusinessRulesService, LEGACY_RULE_KINDS } from './services/business-rules.service';
export type {
  BusinessRule, BusinessRuleBody, BusinessRulePatch, BusinessRuleKind, RuleAppliesTo,
  RuleRoleRef, RuleEditorWarning, RuleIssue, RuleValidateResponse, RuleTestRequest,
  RuleTestAudience, RuleTestResponse, BusinessRuleFilter, AudienceRoleOption,
} from './services/business-rules.service';
export {
  BUSINESS_RULE_OPS, CONDITION_SYSTEM_FIELDS, OPS_BY_KIND, opTakesList, opTakesNoValue,
  isConditionAll, isConditionAny, isConditionExpression, isConditionLeaf, conditionHasExpression,
  conditionFieldKind,
} from './services/business-rule.model';
export type {
  BusinessRuleOp, ConditionTree, ConditionAll, ConditionAny, ConditionExpression, ConditionLeaf,
  ConditionFieldKind, PolicyDef, PolicyType, RuleSeverity, SetMode, BusinessRuleClient,
} from './services/business-rule.model';
// Basic Units U19 (M14/M18/M89) and U8 (M07) — the governance screens'
// services. Exported from this `/data` entry point (D-314); the components
// live in `@attome/xrm/core/admin/governance`.
export {
  DataQualityService, QUALITY_DIMENSIONS, SCORE_DIMENSIONS, QUALITY_ISSUE_STATUSES,
  RULE_DIMENSIONS, RULE_SEVERITIES, QUALITY_FIXES, MAX_FIX_RECORDS,
} from './services/data-quality.service';
export type {
  QualityScore, QualityIssue, QualityDimension, QualityIssueStatus, QualityIssueFilter,
  QualityRule, QualityTarget, CreateQualityRule, UpdateQualityRule, PutQualityTarget,
  QualityFixBody, QualityFixPreview, QualityFixSubmitted, QualityFixKind,
} from './services/data-quality.service';
export { DataCatalogService } from './services/data-catalog.service';
export type {
  CatalogEntitySummary, CatalogEntityDetail, CatalogField, CatalogLineageEntry,
  CatalogGlossaryTerm, CatalogSearch,
} from './services/data-catalog.service';
// L6-T7 — data profiles: the catalog's profile panel and the field list's fill-rate badge.
export { DataProfileService, fillRate, fillRates, profileFields } from './services/data-profile.service';
export type { DataProfileRow, FieldProfile } from './services/data-profile.service';
// S10-T1 — API usage and per-key quotas.
export { ApiUsageService, MAX_KEY_QUOTA, USAGE_WINDOWS } from './services/api-usage.service';
export type { ApiKeyQuotaSet, ApiKeyUsageRow, ApiUsageSummaryRow } from './services/api-usage.service';
// L5-T7 — the lineage graph, version compare, cleanup and a change's impact.
export { LINEAGE_KINDS, LINEAGE_MAX_DEPTH, LineageService } from './services/lineage.service';
export type {
  ImpactAffected, ImpactBreaking, ImpactChange, ImpactReport, LineageCleanup, LineageComparison,
  LineageDirection, LineageEdge, LineageGraph, LineageNode, LineageNodeRef, LineageWalk,
} from './services/lineage.service';
export { ChangeFeedService, CHANGE_KINDS } from './services/change-feed.service';
export type { ChangeConsumer } from './services/change-feed.service';
export type { ChangeFeedEntry, ChangeFeedPage, ChangeKind, ChangeFeedFilter } from './services/change-feed.service';
export { StateModelsService } from './services/state-models.service';
export type {
  StateModelListItem, StateModelDetail, StateTransition,
  CreateStateModelBody, UpdateStateModelBody, CreateTransitionBody, UpdateTransitionBody,
} from './services/state-models.service';
// Solution 7 (D-785) — the open changeset the designer records into, and the
// layer it edits. Services only; the badge and the picker import it.
export { ChangesetContextService } from './services/changeset-context.service';
export type { ChangesetSummary, ChangesetListStatus } from './services/changeset-context.service';
// Solution 7 Phase 2 (D-788, D-791) — the release report, the field structure
// changes (rename, delete, change type, choices, run abandon) and the 30-day
// recovery archive. Services and wire types only; the pages live in
// `@attome/xrm/core/admin/release-reports` and the dialogs in `core/admin`.
export {
  AdminHttp, STABLE_ERROR_CODES, stableErrorCode, toAdminApiError,
} from './services/admin-http';
export type { AdminApiError, AdminRequestOptions, StableErrorCode } from './services/admin-http';
export {
  ReleaseReportService, REPORT_ITEM_KINDS, REPORT_ITEM_STATUSES, RELEASE_REPORT_SOURCES,
  RELEASE_REPORT_STATUSES, ARCHIVE_BACKED_KINDS,
} from './services/release-report.service';
export type {
  ReleaseReport, ReportItem, ReportItemView, ReportItemKind, ReportItemStatus,
  ReleaseReportSource, ReleaseReportStatus, ReleaseReportSummary, ConflictValues,
  RestoreCounts, ItemRestoreResult, ReportFilter, ItemFilter,
} from './services/release-report.service';
export {
  FieldChangeService, CONVERTIBLE_FIELD_TYPES, FIELD_CONVERSIONS, CONVERSION_DATE_FORMATS,
  ARCHIVE_REASONS, conversionTargets,
} from './services/field-change.service';
export type {
  ConvertibleFieldType, FieldReference, FieldBlocker, FieldReportDraft, FieldChangeOp,
  FieldChangeResult, FieldChangeOutcome, ConversionInput, AddChoiceInput, AbandonedFieldRun,
  DataStepRunStatus,
  ArchiveReason, ArchiveRow, ArchiveFilter,
} from './services/field-change.service';
export { structureErrorText } from './services/structure-error-text';
// L1-T9 — a golden record's provenance and system ids, the held queue, and the steward's actions.
export { MasterDataService } from './services/master-data.service';
export type {
  MasterContributionStatus, MasterField, MasterHeldContribution, MasterProvenance, MasterRebuildQueued,
  MasterSystemId, MasterXrefGolden,
} from './services/master-data.service';
