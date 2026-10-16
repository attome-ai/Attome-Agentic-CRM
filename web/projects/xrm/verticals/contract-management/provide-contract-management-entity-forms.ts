import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AmendmentFormComponent } from './forms/amendment-form/amendment-form.component';
import { ClauseFormComponent } from './forms/clause-form/clause-form.component';
import { ContractFormComponent } from './forms/contract-form/contract-form.component';
import { ObligationFormComponent } from './forms/obligation-form/obligation-form.component';
import { ContractPlaybookRuleFormComponent } from './forms/contract-playbook-rule-form/contract-playbook-rule-form.component';
import { ContractVersionFormComponent } from './forms/contract-version-form/contract-version-form.component';
import { ContractComparisonFormComponent } from './forms/contract-comparison-form/contract-comparison-form.component';
import { ContractImportFormComponent } from './forms/contract-import-form/contract-import-form.component';

// The contract-management vertical's entity forms (verticals/contract-management/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerContractManagementEntityForms(registry: EntityRouteRegistry): void {
  registry.register('amendment', { formComponent: AmendmentFormComponent });
  registry.register('clause', { formComponent: ClauseFormComponent });
  registry.register('contract', { formComponent: ContractFormComponent });
  registry.register('obligation', { formComponent: ObligationFormComponent });
  registry.register('contract_playbook_rule', { formComponent: ContractPlaybookRuleFormComponent });
  registry.register('contract_version', { formComponent: ContractVersionFormComponent });
  registry.register('contract_comparison', { formComponent: ContractComparisonFormComponent });
  registry.register('contract_import', { formComponent: ContractImportFormComponent });
}
