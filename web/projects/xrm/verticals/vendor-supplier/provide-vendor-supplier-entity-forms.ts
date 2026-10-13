import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { VendorFormComponent } from './forms/vendor-form/vendor-form.component';
import { VendorComplianceDocumentFormComponent } from './forms/vendor-compliance-document-form/vendor-compliance-document-form.component';
import { VendorEvaluationFormComponent } from './forms/vendor-evaluation-form/vendor-evaluation-form.component';

// The vendor-supplier vertical's entity forms (verticals/vendor-supplier/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerVendorSupplierEntityForms(registry: EntityRouteRegistry): void {
  registry.register('vendor', { formComponent: VendorFormComponent });
  registry.register('vendor_compliance_document', { formComponent: VendorComplianceDocumentFormComponent });
  registry.register('vendor_evaluation', { formComponent: VendorEvaluationFormComponent });
}
