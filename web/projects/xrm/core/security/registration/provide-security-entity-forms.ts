import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { UserFormComponent } from './system-user/form/user-form/user-form.component';
import { userAccountStateActions } from './services/user-account-state.actions';
import { OrganizationFormComponent } from './organization/form/organization-form/organization-form.component';
import { TeamFormComponent } from './team/form/team-form/team-form.component';
import { PrivilegeFormComponent } from './privilege/form/privilege-form/privilege-form.component';
import { CoreRoleFormComponent } from './forms/role-form/core-role-form.component';
import { CoreSystemuserMmTeamFormComponent } from './forms/systemuser-mm-team-form/core-systemuser-mm-team-form.component';
import { CoreSystemuserMmPrivilegeFormComponent } from './forms/systemuser-mm-privilege-form/core-systemuser-mm-privilege-form.component';

// 'user_account' -> UserFormComponent: the sectioned/iconed user form.
// It was briefly unregistered on 2026-08-05 in favor of the generic
// EntityFormPageComponent on the grounds that FieldInputComponent already
// renders every field type generically — true for *behavior*, but the
// generic renderer is a flat field list with no sections, icons, helper
// text, or grouped layout, and that presentation is the point of this
// override. Restored 2026-08-07 at the user's request.
//
// Also swaps the grid's stock Delete for Deactivate/Activate/Delete. Generic
// entity delete soft-deletes by flipping `is_active` and nothing else, which
// for an *account* leaves live API keys authenticating against a user the
// admin believes is gone; `…/security/users/{id}/disable` is the endpoint
// that actually revokes. `hideDeleteAction` therefore stays on — but the
// toolbar is no longer missing a Delete: `userAccountStateActions` supplies
// its own, which runs the generic delete and the revoking disable in that
// order. See user-account-state.actions.ts for why the order is fixed.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap,
// scripts/chunk-budget.mjs). The loader that reaches this function lives in
// the app's composition root (`src/app/attome-metadata-form-loaders.ts`), which is
// the one place allowed to know about every xrm module's registration at
// once; this function itself stays a plain export so it's trivial to call
// once that dynamic import resolves.
export function registerSecurityEntityForms(registry: EntityRouteRegistry): void {
  registry.register('user_account', {
    formComponent:    UserFormComponent,
    hideDeleteAction: true,
    selectionActions: userAccountStateActions(),
  });
  registry.register('organization', { formComponent: OrganizationFormComponent });
  registry.register('team', { formComponent: TeamFormComponent });
  registry.register('privilege', { formComponent: PrivilegeFormComponent });
  registry.register('role', { formComponent: CoreRoleFormComponent });
  // The two user junction tables are managed through the User form's
  // relationship grids; they still get their own form (SYSTEM-CHANGES.md
  // Topic 14: every entity has one), a scaffold to be designed later (D-773).
  registry.register('user_account_mm_team', { formComponent: CoreSystemuserMmTeamFormComponent });
  registry.register('user_account_mm_privilege', { formComponent: CoreSystemuserMmPrivilegeFormComponent });
}
