// Split out from `@attome/xrm/core/security` (D-314 packaging: xrm barrel
// splitting) — this entry holds only the thin form overrides that
// `EntityRouteRegistry` needs, kept separate from the parent entry's heavier
// standalone admin pages (RoleFormComponent, SecurityAdminOverviewComponent,
// RoleEntityAccessComponent, UserAccessComponent, UsersListComponent,
// OrganizationsListComponent, RecordSharesComponent,
// FieldSecurityProfilesComponent). The app's composition root
// (`src/app/attome-metadata-form-loaders.ts`) lazily `import()`s this entry and
// calls `registerSecurityEntityForms` only once an entity that needs it is
// actually routed to — see EntityRouteRegistry's doc comment for why (a
// static import here, even just for the registration function, would force
// those heavier pages into the same eager chunk; ng-packagr bundles one
// entry point as one unit, so importing anything from the parent entry pulls
// all of it in — same reasoning as `core/admin/data`'s own doc comment).
export { UserFormComponent }            from './system-user/form/user-form/user-form.component';
export { userAccountStateActions }      from './services/user-account-state.actions';
export { OrganizationFormComponent }    from './organization/form/organization-form/organization-form.component';
export { TeamFormComponent }            from './team/form/team-form/team-form.component';
export { PrivilegeFormComponent }       from './privilege/form/privilege-form/privilege-form.component';
export { registerSecurityEntityForms }  from './provide-security-entity-forms';
