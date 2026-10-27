// @attome/xrm/core/security/access-admin — Q10-T12: the permission sets,
// conflict rules and role templates pages.
//
// Their own entry point so the security administration chunk stays inside
// its lazy-chunk budget (scripts/chunk-budget.mjs, D-314): each route loads
// this entry point with a dynamic `import()`, and a deployment that keeps the
// feature switches off never downloads it.
export { PermissionSetsComponent, defaultSetAccess } from './permission-sets.component';
export { RoleConflictsComponent }                    from './role-conflicts.component';
export type { ConflictKind }                         from './role-conflicts.component';
export { RoleTemplatesComponent }                    from './role-templates.component';
