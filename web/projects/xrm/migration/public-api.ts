// M17 (Data Migration, D-433) — the migration wizard: source -> mapping ->
// dry run -> approve -> run -> report, built entirely on top of the existing
// staged-import mechanism (bulk.rs) and this module's own migration-project/
// run admin surface (migration.rs). No bespoke list/form component for
// `migration_project`/`migration_run` themselves beyond the wizard —
// they are infra tables (D-005), not metadata-driven entities, so the
// generic entity grid/form has nothing to render them from.
export { MigrationWizardComponent } from './migration-wizard/migration-wizard.component';
// U11 / D-606 — CSV import (the wizard's file step).
export { CsvImportComponent } from './csv-import/csv-import.component';
// Y14-T4: this screen's own catalogue.
export { migrationAr, migrationEn } from './migration.i18n';
