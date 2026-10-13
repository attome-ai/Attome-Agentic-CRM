// New top-level entry (D-099-era `audit` module: attome-audit is a real,
// fully-implemented crate, but had no dedicated Angular home until this
// form — the ledger itself stays on the generic entity list pages).
export { AuditConfigFormComponent } from './audit-config/form/audit-config-form/audit-config-form.component';
export { registerAuditEntityForms } from './provide-audit-entity-forms';

// M19 gap list — the dedicated audit search page + its service
// (`GET /api/v1/admin/audit/search` / `/export`).
export { AuditSearchComponent } from './search/audit-search/audit-search.component';
export {
  AuditSearchService,
  type AuditExportFormat,
  type AuditSearchFilters,
  type AuditSearchResponse,
  type AuditSearchRow,
} from './search/data/audit-search.service';
