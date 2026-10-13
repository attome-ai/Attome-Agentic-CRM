import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AuditConfigFormComponent } from './audit-config/form/audit-config-form/audit-config-form.component';
import { AuditHeaderFormComponent } from './forms/audit-header-form/audit-header-form.component';
import { AuditDetailFormComponent } from './forms/audit-detail-form/audit-detail-form.component';
import { AuditSnapshotFormComponent } from './forms/audit-snapshot-form/audit-snapshot-form.component';
import { AuditConsentPurposeFormComponent } from './forms/audit-consent-purpose-form/audit-consent-purpose-form.component';
import { AuditConsentFormComponent } from './forms/audit-consent-form/audit-consent-form.component';
import { AuditLegalMatterFormComponent } from './forms/audit-legal-matter-form/audit-legal-matter-form.component';

// `audit_header`/`detail`/`snapshot` are append-only (the hash-chained
// ledger itself, is_append_only=true) — the generic entity engine already
// rejects update/delete against them server-side
// (attome-records/src/entity_crud/mutations.rs), regardless of which
// Angular form issues the request, so giving them the same hand-coded form
// as every other platform entity here is no more permissive than the
// generic dispatcher they used to render through.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerAuditEntityForms(registry: EntityRouteRegistry): void {
  registry.register('audit_config', { formComponent: AuditConfigFormComponent });
  registry.register('audit_header', { formComponent: AuditHeaderFormComponent });
  registry.register('audit_detail', { formComponent: AuditDetailFormComponent });
  registry.register('audit_snapshot', { formComponent: AuditSnapshotFormComponent });
  registry.register('audit_consent_purpose', { formComponent: AuditConsentPurposeFormComponent });
  registry.register('audit_consent', { formComponent: AuditConsentFormComponent });
  registry.register('audit_legal_matter', { formComponent: AuditLegalMatterFormComponent });
}
