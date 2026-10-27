// @attome/xrm/portal — web portal administration (D-576; web portal plan
// Phase 13 step 6). The staff side only: the portal web app itself is a
// separate project that never imports @attome/xrm (plan Phase 6).
export { PortalAdminService } from './portal-admin.service';
export type {
  PortalDetail, PortalUserDetail, RoleSummary, RoleView, GrantSpec, GrantView,
  ConditionSpec, FieldSpec, EntityConfigView, ErasureRequest, ExportResult,
} from './portal-admin.service';
export { PortalAdminComponent } from './portal-admin/portal-admin.component';

// Every entity's own form (SYSTEM-CHANGES.md Topic 14).
export { registerPortalEntityForms } from './provide-portal-entity-forms';
// Y14-T4: this screen's own catalogue.
export { portalAdminAr, portalAdminEn } from './portal-admin.i18n';
