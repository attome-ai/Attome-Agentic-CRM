// A12-T3 — the form designer: a form's draft on the shared canvas, the
// entity's fields to place, checks, and a live preview. Its own entry point
// so only the designer route loads it.
export { FormDesignerComponent } from './form-designer.component';
export {
  FIELD_BUDGET, RELATED_BUDGET, allSections, checkForm, fromDesign, previewFieldType, toDesign,
} from './form-doc';
export type { DesignDoc, DesignNode, FormCheck, FormDoc, SectionDoc, TabDoc } from './form-doc';
