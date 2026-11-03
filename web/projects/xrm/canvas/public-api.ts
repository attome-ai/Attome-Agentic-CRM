// Y14-T1 — the shared canvas engine every designer edits on: selection,
// drag and drop, a property panel, unlimited undo and redo as Y1 edit
// commands, and other editors' presence.
export { CanvasComponent, afterRemoval, flatten, moveCommand } from './canvas.component';
export type { CanvasNode, CanvasPresence, PlacedNode } from './canvas.component';
export { CommandStack } from './command-stack';
export { applyCommand, escapeSegment, inverseOf, valueAt } from './commands';
export type { EditCommand } from './commands';
// M2-T1 — graph mode: nodes placed freely, edges between typed ports.
export { GraphCanvasComponent } from './graph-canvas.component';
export {
  CARD, ON_ERROR_PORT, cardHeight, checkConnection, connectCommand, droppableInputs, edgeKey, ensureLists, freshId,
  groupBox, moveNodeCommand, outputsOf, portPoint, portsCompatible, reaches, removeNodeCommands, wirePath,
} from './graph';
export type {
  GraphDoc, GraphDocEdge, GraphDocGroup, GraphDocNode, GraphDocNote, GraphNodeKind, GraphNodeMark, GraphPortSpec, PortRef, Refusal,
} from './graph';
