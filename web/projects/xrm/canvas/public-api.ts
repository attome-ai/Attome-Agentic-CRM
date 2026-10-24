// Y14-T1 — the shared canvas engine every designer edits on: selection,
// drag and drop, a property panel, unlimited undo and redo as Y1 edit
// commands, and other editors' presence.
export { CanvasComponent, afterRemoval, flatten, moveCommand } from './canvas.component';
export type { CanvasNode, CanvasPresence, PlacedNode } from './canvas.component';
export { CommandStack } from './command-stack';
export { applyCommand, escapeSegment, inverseOf, valueAt } from './commands';
export type { EditCommand } from './commands';
