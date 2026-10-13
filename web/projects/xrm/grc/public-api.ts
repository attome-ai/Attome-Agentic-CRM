// M20 Phase 1 (Governance, Risk & Compliance, D-427) - most `grc_*`
// entities get no bespoke component (the generic metadata-driven pages
// already render every field they declare); this entry adds the two views
// the generic grid cannot express - a control-x-requirement coverage matrix
// and a status/expiry-aware policy register - plus the two lifecycle
// selection actions (`assessmentActions`/`findingActions`) that call this
// module's bespoke start/remediate routes.
export { registerGrcEntityForms } from './registration/provide-grc-entity-forms';
export { ControlMatrixComponent } from './control-matrix/control-matrix.component';
export { PolicyListComponent } from './policy-list/policy-list.component';
