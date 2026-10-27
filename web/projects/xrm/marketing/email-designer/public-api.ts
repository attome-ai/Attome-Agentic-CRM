// @attome/xrm/marketing/email-designer — E2-T1: the email designer on the
// shared canvas, producing the block JSON the server renders (E2-T2).
export { DESIGN_ENTITY, EmailDesignerComponent } from './email-designer.component';
export type { SavedDesign } from './email-designer.component';
export { MAX_WIDTH, MIN_WIDTH, PALETTE, fromCanvas, linkOk, newNode, problems, toCanvas } from './email-design.model';
export type { DesignDoc, DesignNode, Direction, EmailBlock, EmailDesign, PaletteType } from './email-design.model';
