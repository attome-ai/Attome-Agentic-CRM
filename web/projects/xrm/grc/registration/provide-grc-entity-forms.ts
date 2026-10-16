import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { ControlMatrixComponent } from '../control-matrix/control-matrix.component';
import { PolicyListComponent } from '../policy-list/policy-list.component';
import { assessmentActions, findingActions } from './grc.actions';
import { GrcRegulationFormComponent } from '../forms/grc-regulation-form/grc-regulation-form.component';
import { GrcRequirementFormComponent } from '../forms/grc-requirement-form/grc-requirement-form.component';
import { GrcControlFormComponent } from '../forms/grc-control-form/grc-control-form.component';
import { GrcAssessmentItemFormComponent } from '../forms/grc-assessment-item-form/grc-assessment-item-form.component';
import { GrcEvidenceFormComponent } from '../forms/grc-evidence-form/grc-evidence-form.component';
import { GrcRiskFormComponent } from '../forms/grc-risk-form/grc-risk-form.component';
import { GrcRiskDependencyFormComponent } from '../forms/grc-risk-dependency-form/grc-risk-dependency-form.component';
import { GrcPolicyAckFormComponent } from '../forms/grc-policy-ack-form/grc-policy-ack-form.component';
import { GrcControlRequirementFormComponent } from '../forms/grc-control-requirement-form/grc-control-requirement-form.component';
import { GrcPolicyFormComponent } from '../forms/grc-policy-form/grc-policy-form.component';
import { GrcAssessmentFormComponent } from '../forms/grc-assessment-form/grc-assessment-form.component';
import { GrcFindingFormComponent } from '../forms/grc-finding-form/grc-finding-form.component';
import { GrcRegulatoryChangeFormComponent } from '../forms/grc-regulatory-change-form/grc-regulatory-change-form.component';
import { GrcRegulatoryChangeLinkFormComponent } from '../forms/grc-regulatory-change-link-form/grc-regulatory-change-link-form.component';

/**
 * M20-grc.md Phase 1 checklist's Angular entry. `grc_control_requirement`
 * and `grc_policy` get bespoke list views (a coverage matrix and a
 * status/expiry-aware register) the generic grid can't express, and
 * `grc_assessment`/`grc_finding` get lifecycle selection actions on
 * top of their hand-coded forms. Every other `grc_*` entity now also has
 * a hand-coded form component (the platform-wide move away from the generic
 * metadata-driven renderer for built-in xrm/base entities) registered below.
 *
 * Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()` — see
 * that class's doc comment for why. The loader that reaches this function
 * lives in the app's composition root (`src/app/attome-metadata-form-loaders.ts`).
 */
export function registerGrcEntityForms(registry: EntityRouteRegistry): void {
  registry.register('grc_control_requirement', {
    listComponent: ControlMatrixComponent, formComponent: GrcControlRequirementFormComponent,
  });
  registry.register('grc_policy', { listComponent: PolicyListComponent, formComponent: GrcPolicyFormComponent });
  registry.register('grc_assessment', {
    selectionActions: assessmentActions(), formComponent: GrcAssessmentFormComponent,
  });
  registry.register('grc_finding', { selectionActions: findingActions(), formComponent: GrcFindingFormComponent });
  registry.register('grc_regulation', { formComponent: GrcRegulationFormComponent });
  registry.register('grc_requirement', { formComponent: GrcRequirementFormComponent });
  registry.register('grc_control', { formComponent: GrcControlFormComponent });
  registry.register('grc_assessment_item', { formComponent: GrcAssessmentItemFormComponent });
  registry.register('grc_evidence', { formComponent: GrcEvidenceFormComponent });
  registry.register('grc_risk', { formComponent: GrcRiskFormComponent });
  registry.register('grc_risk_dependency', { formComponent: GrcRiskDependencyFormComponent });
  registry.register('grc_policy_ack', { formComponent: GrcPolicyAckFormComponent });
  registry.register('grc_regulatory_change', { formComponent: GrcRegulatoryChangeFormComponent });
  registry.register('grc_regulatory_change_link', { formComponent: GrcRegulatoryChangeLinkFormComponent });
}
