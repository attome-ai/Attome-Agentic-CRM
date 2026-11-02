// A22-T5 — the environments page (`/xrm/admin/environments`): what was
// promoted into this deployment, what waits for approval, and a plan of
// uploaded changesets against it. Promotion itself stays in the CLI
// (V2-D1595 (3)).
//
// Its own secondary entry point, like `metadata-versions`, so routes that
// load the `@attome/xrm/core/admin` barrel do not download this page too
// (D-314).
export { EnvironmentsComponent, EnvironmentsService, planCounts } from './environments.component';
export type { ChangesetPlan, LedgerRow, PlannedChangeset, PlannedOp } from './environments.component';
