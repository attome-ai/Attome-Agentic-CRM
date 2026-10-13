// The services and their wire types now live in `@attome/xrm/core/admin/data` and are
// re-exported here so this entry point's public API is unchanged (D-314).
// Consumers outside `admin/` should import `@attome/xrm/core/admin/data` — importing
// them from here still pulls all four admin components in.
export { AdminService, XRM_FIELD_TYPES, SidebarPreferencesService } from '@attome/xrm/core/admin/data';
export type {
  EntityMeta, EntityDetail, AttributeMeta,
  CreateEntityBody, UpdateEntityBody,
  CreateAttributeBody, UpdateAttributeBody,
  SidebarItem,
  SidebarAdminItem, SidebarPrivilege, SidebarMutation,
  XrmFieldType, SidebarStyle,
  CalendarAdminItem, CalendarMutation, CalendarTimeRange,
  CalendarHoliday, CalendarHolidayMutation,
} from '@attome/xrm/core/admin/data';
// D-789 (business rules; D-790 removed `/api/v1/admin/rules*`) — the
// `/api/v1/admin/business-rules` client and its wire types.
export { BusinessRulesService, LEGACY_RULE_KINDS } from '@attome/xrm/core/admin/data';
export type {
  BusinessRule, BusinessRuleBody, BusinessRulePatch, BusinessRuleKind, RuleAppliesTo,
  RuleRoleRef, RuleEditorWarning, RuleIssue, RuleValidateResponse, RuleTestRequest,
  RuleTestAudience, RuleTestResponse, BusinessRuleFilter, AudienceRoleOption,
} from '@attome/xrm/core/admin/data';
export { EntityManagerComponent }     from './entity-metadata/list/entity-manager/entity-manager.component';
export { EntityEditorComponent }      from './entity-metadata/form/entity-editor/entity-editor.component';
export { SidebarManagerComponent }    from './sidebar-manager/sidebar-manager.component';
export { SystemSettingsComponent }    from './system-settings/system-settings.component';
export { CalendarManagerComponent }   from './calendar-manager/calendar-manager.component';
// D-432 / M13 — the duplicate-candidate steward queue.
export { DuplicatesManagerComponent } from './duplicates-manager/duplicates-manager.component';
// D-789 section 10 — the business-rule editor (the rules admin page's route).
export { RulesManagerComponent }      from './rules-manager/rules-manager.component';
