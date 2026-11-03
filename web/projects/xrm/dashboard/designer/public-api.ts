// P5-T1 — the dashboard designer on the shared canvas, its own entry point
// so only the designer route loads it.
export { DashboardDesignerComponent } from './dashboard-designer.component';
export {
  PAGE_KEYS, PREVIEW_COLUMNS, SECTION_KEYS, WIDGET_KEYS, misplaced, planSave, previewBoxes, resolveLinks, toDesign,
} from './dashboard-doc';
export type { Breakpoint, DDoc, DNode, ParentLink, PreviewBox, SaveOp } from './dashboard-doc';
