// ── Entity model ──────────────────────────────────────────────────────────────
export { EntityService }              from './services/entity.service';
// P-api-contract Phase 2 — the backend's real single-record wire shape,
// derived from the generated OpenAPI types rather than hand-written.
export type { EntityRecordResponse }  from './services/entity.service';
// M07/M64 — state transition wire types (kanban's drag-and-drop contract).
export type {
  AvailableTransition, TransitionRequestBody, TransitionResult, PaginatedAvailableTransitions,
} from './services/entity.service';
export { EntityListComponent, resolveRouteTemplate } from './list/entity-list.component';
export { RelatedGridComponent }       from './related-grid/related-grid.component';
export { TagPageComponent }           from './record-tags/tag-page.component';
export { RecycleBinComponent }        from './recycle-bin/recycle-bin.component';
export { BulkTagComponent }           from './record-tags/bulk-tag.component';
// The bounded poll loop for durable jobs (bulk edit, export) — also used by
// the report runner (U16), so it is public rather than list-internal.
export { BulkJobRunner, DEFAULT_POLL_INTERVAL_MS, DEFAULT_MAX_POLLS } from './list/bulk-job-runner.service';
export type { PollOptions }           from './list/bulk-job-runner.service';
export type {
  RelatedGridFilter, RelatedGridType, RelationshipPickerConfig,
} from './related-grid/related-grid.component';
// M01 Core P3 gap (D-455) — the generic M:M relationship sub-grid, driven by
// `EntitySchema.relationships` (`getSchema`), one instance per configured
// relationship. NOT `RelatedGridComponent`: see the component's own doc
// comment for why a `_mm_`-table-registered-as-an-entity subgrid and a
// dedicated-join-table subgrid need two different mechanisms.
export { RelationshipGridComponent }  from './relationship-grid/relationship-grid.component';
export { DocumentFolderBrowserComponent } from './document-folder/document-folder-browser.component';
export { ShareTargetComponent } from './share-target/share-target.component';
export { CommunicationsPanelComponent } from './communications/communications-panel.component';
export { EmailComposerComponent } from './communications/email-composer.component';
export { NotesPanelComponent }          from './notes/notes-panel.component';
// U4 (D-602) — "Remind me" on the record form header.
export { RemindMeComponent, REMINDER_ENTITY } from './reminders/remind-me.component';
export { FollowButtonComponent, FOLLOW_ENTITY } from './follow-button/follow-button.component';
// B16-T11 — record codes; the `/r/{entity}/{id}` route is the host app's.
export { RecordCodeComponent, recordLink } from './record-code/record-code.component';
export { FollowingListComponent } from './follow-button/following-list.component';
// U7 Phase A — admin-only Assign / Share on the record form header and the
// list's bulk bar. Only the button pair is exported; its dialog is deferred
// inside it and stays out of this entry's shared chunk.
export { RecordAccessActionsComponent } from './record-access/record-access-actions.component';
export { RecordSharingService, SHARE_CAPABILITIES } from './record-access/record-sharing.service';
export type {
  RecordShareItem, CreateRecordShareBody, ReassignOwnerBody, OwnerItem, ShareCapability,
} from './record-access/record-sharing.service';
// Generic "Tags" section, mounted by EntityFormComponent and (as the first
// hand-written form to carry it) UserFormComponent — see the component's
// own doc comment.
export { TagsPanelComponent }           from './tags/tags-panel.component';
// M24 (D-428) — generic "Consent" tab, mounted by EntityFormComponent.
export { ConsentPanelComponent }        from './consent/consent-panel.component';
export { ConsentAdminService }          from './consent/consent-admin.service';
export type { WithdrawConsentBody, ConsentRow } from './consent/consent-admin.service';
export { TeamRolesPanelComponent }      from './team-roles-panel/team-roles-panel.component';
// D-429/M64 — the kanban/calendar/timeline view kinds live in
// `@attome/xrm/core/entity/views` (U13 moved them out to keep this entry's
// shared widget chunk inside the lazy-chunk budget).
// U14 — the generic record tabs (Documents, Communications, Notes, Tags,
// Consent, Relationships) as a tab-definition helper plus one panels
// component, shared by EntityFormComponent and any hand-written
// EngineFormBase subclass that wants the same tabs (the service ticket form).
export { recordTabDefs, RECORD_TAB_IDS, withGoldenTab } from './record-tabs/record-tabs';
export type { RecordTabId }             from './record-tabs/record-tabs';
export { RecordTabPanelsComponent }     from './record-tabs/record-tab-panels.component';
// D-432 / M13 — the "possible duplicate" banner. Depends on
// `@attome/xrm/core/admin/data`'s `DuplicatesService`, same "widely-used
// services live in /data, this barrel is fine depending on it" shape
// `EntityMetadataChangeService`'s own doc comment already describes for the
// reverse direction.
export { ConflictDialogComponent }      from './conflict-dialog/conflict-dialog.component';
export { RecordTypePickerComponent }    from './record-type-picker/record-type-picker.component';
export { PendingTimersComponent }       from './pending-timers/pending-timers.component';
export type { PendingTimer }           from './pending-timers/pending-timers.component';
export type { RecordTypeOption }        from './record-type-picker/record-type-picker.component';
export type { ConflictChoice, ConflictChoices } from './conflict-dialog/conflict-dialog.component';
export { DuplicateBannerComponent }     from './duplicate-banner/duplicate-banner.component';
export { duplicateWarningsOf }          from './duplicate-banner/duplicate-notice';
export type { DuplicateNotice }         from './duplicate-banner/duplicate-notice';
export { MergeDialogComponent }         from './merge-dialog/merge-dialog.component';
export { MergeUndoBarComponent }        from './merge-dialog/merge-undo-bar.component';
export { RecordChangedBannerComponent } from './record-changed-banner/record-changed-banner.component';
export type { ServerChange }            from './record-changed-banner/record-changed-banner.component';
// M36 Phase 0+1 (Predictive Intelligence, D-473) — the record form's
// "prediction" banner. Depends on `@attome/xrm/core/admin/data`'s
// `PredictionsService`, same shape as `DuplicateBannerComponent` above.
export { PredictionBannerComponent }    from './prediction-banner/prediction-banner.component';
// M38 Phase 1 — the entity form's "Relationships" tab, over
// `POST /api/v1/graph/traverse`.
export { RelationshipExplorerComponent } from './relationship-explorer/relationship-explorer.component';
export type {
  GraphDirection, GraphEdge, GraphNode, TraverseRequest, TraverseResponse,
} from './relationship-explorer/relationship-explorer.component';
// EntityFormComponent, EntityRouterComponent, and the pages/* wrappers
// around them live in `@attome/xrm/core/entity/dispatcher` instead of here —
// the generic metadata-driven form (full schema/tab rendering, save/conflict
// handling) is large and only the wildcard entity route actually needs it.
// Every per-entity form only needs the widgets and base class above, plus
// EntityListComponent (kept here, not split out, because RelatedGridComponent
// is built directly on top of it — the split boundary follows what's
// actually separable, not "list vs form"), so keeping the dispatcher *form*
// in this same entry would force its full weight into every module that
// registers a bespoke form — see that entry's public-api.ts doc comment for
// the concrete regression this split fixed (D-314 packaging).
export { EntityRouteRegistry }        from './entity-route-registry.service';
export type {
  EntityRouteOverride, ListCellRenderers, SelectionAction,
} from './entity-route-registry.service';
export {
  logicalToUrlPath,
  urlPathToLogical,
  urlPathCandidates,
  resolveEntityUrlPath,
  entityMatchesUrlPath,
  entityListRoute,
  entityFormRoute,
} from './services/entity-url.utils';
export type { EntityUrlResolution } from './services/entity-url.utils';

// ── Shared form base (every xrm form extends this) ──────────────────────────
// Lives here, not a separate `core/base` entry, because it genuinely depends
// on EntityService — a separate entry would create a circular dependency the
// moment any component in this entry (EntityFormComponent) also needed to
// extend it. Forms in other modules (core/security, workflow, …) import it
// from here absolutely; that's a one-directional edge, not a cycle, since
// this entry never imports anything back from them.
export { EngineFormBase, SAVED_CONFIRMATION_MS } from './base/xrm-form.base';
export type { XrmFormTabDef } from './base/xrm-form.base';
// D-773 — the template half of the base form: every form wraps its own
// content in <xrm-base-form [form]="this" [formGroup]="form()">.
export { XrmBaseFormComponent }       from './base/base-form/xrm-base-form.component';
export { XrmTabDirective }             from './base/base-form/xrm-tab.directive';
// D-789 (business rules, design section 5) — the client condition interpreter
// (UX only; the server enforces), the field-policy token <xrm-base-form>
// provides to attome-field-input, and *xrmFieldVisible for a field rendered
// outside attome-field-input.
export {
  evaluateBusinessRuleCondition, fieldKindResolver,
} from './business-rules/business-rule-condition';
export type { ConditionResult, FieldKindResolver } from './business-rules/business-rule-condition';
// The condition/policy wire types and the operator table live in
// `@attome/xrm/core/admin/data` (D-314: wire types in a /data entry point),
// shared with the business-rule editor.
export {
  XRM_FIELD_POLICY, computeFieldPolicies, fieldErrorsFromApiError, writeWarnings, ruleLabel,
  FIELD_LOCKED_CODES,
} from './business-rules/field-policy';
export type {
  XrmFieldPolicy, FieldLockEffect, FieldLockState, FieldRuleMessage, FieldPolicyOutcome,
  RuleWriteWarning,
} from './business-rules/field-policy';
export { XrmFieldVisibleDirective }     from './business-rules/field-visible.directive';
// Dashboard 10/10 Phase 1.4 — generic "leave with unsaved work?" route guard.
export { unsavedChangesGuard }        from './guards/unsaved-changes.guard';
export type { HasUnsavedChanges }     from './guards/unsaved-changes.guard';

// ── Field model (D-144 file upload pipeline) — only consumed by entity forms,
// and field-input.component.ts itself imports EntityService, so it lives in
// this entry point rather than a separate leaf entry (splitting it out would
// just duplicate EntityService into two chunks for no real code-splitting
// gain — see the "packaging: xrm barrel splitting" note in DECISIONS.md). ──
export { FieldInputComponent }        from './field/field-input/field-input.component';
export { ImageUploadComponent }       from './field/image-upload/image-upload.component';
// U9 (D-605) — the rich_text editor, and the image field's list thumbnail.
export { RichTextEditorComponent }    from './field/rich-text-editor/rich-text-editor.component';
export { ImageThumbComponent }        from './field/image-thumb/image-thumb.component';
export { AttachmentComponent }        from './field/attachment/attachment.component';
export { FileUploadService }          from './field/file-upload.service';
// U18 (M55 P2) — the single-file field's "Versions" panel, and the signal it
// uses to tell the hosting form the record moved on the server.
export { FileVersionsComponent }      from './field/file-versions/file-versions.component';
export { RecordChangeNotifier }       from './services/record-change-notifier.service';
export type { RecordChange }          from './services/record-change-notifier.service';
export { UploadPipeline }             from './field/upload-pipeline';
export type {
  UploadTarget, UploadHandlers, UploadResult,
} from './field/upload-pipeline';
export type {
  UploadSessionRequest, UploadSessionResponse, FinalizeResponse,
  SessionStatusResponse, DownloadUrlResponse,
  FileVersion, FileVersionPage, RestoreVersionResponse, DownloadTarget,
} from './field/file-upload.service';

// provideAttomeXrm lives here (not in the root `@attome/xrm` entry) because it
// wires up EntityService, which this entry already owns.
export { provideAttomeXrm }           from './services/provide';

// G15-T1: the customer 360 panel, on the account and contact pages and in the
// agent workspace's context panel.
export { Customer360Component, SECTION_ROWS, sectionsFor } from './customer-360/customer-360.component';
export type { Customer360Filter, Customer360Section } from './customer-360/customer-360.component';
