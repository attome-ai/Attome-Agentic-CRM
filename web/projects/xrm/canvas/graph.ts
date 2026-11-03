/**
 * M2-T1 — the canvas's graph mode: a document of nodes placed freely, edges
 * between typed ports, and the groups and notes a builder adds around them.
 * Pure functions only; `graph-canvas.component.ts` renders and edits it, and
 * every change is an edit command (`commands.ts`), so undo, redo and the
 * unsaved command list work as on the tree canvas.
 *
 * The document is the workflow engine's graph (`attome_workflow::graph::Graph`):
 * `nodes` (id, type, config, and `ports` — the editor's own position, opaque
 * to the engine) and `edges` (`from_node:from_port -> to_node:to_port`).
 * `groups` and `notes` are extra members the engine ignores and stores as
 * sent.
 */
import { EditCommand } from './commands';

/** A typed port of a node kind. */
export interface GraphPortSpec { name: string; portType: string; required?: boolean }

/** What the canvas knows about a node type: its ports and whether it starts a flow. */
export interface GraphNodeKind {
  type: string;
  label: string;
  inputs: GraphPortSpec[];
  outputs: GraphPortSpec[];
  isEntry?: boolean;
}

export interface GraphDocNode {
  id: string;
  type: string;
  config?: Record<string, unknown>;
  /** The node's place on the canvas (editor-owned). */
  ports: { x: number; y: number; [k: string]: unknown };
}

export interface GraphDocEdge { from_node: string; from_port: string; to_node: string; to_port: string }

/** A frame around nodes, with a label. */
export interface GraphDocGroup { id: string; label: string; nodes: string[] }

/** A free-standing note on the canvas. */
export interface GraphDocNote { id: string; text: string; x: number; y: number }

export interface GraphDoc {
  nodes: GraphDocNode[];
  edges: GraphDocEdge[];
  groups?: GraphDocGroup[];
  notes?: GraphDocNote[];
}

/** One end of a connection being dragged. */
export interface PortRef { node: string; port: string }

/** The error port every node but an entry has (`attome_workflow::node_types::ON_ERROR_PORT`). */
export const ON_ERROR_PORT = 'on_error';

/** Why a connection is refused; the key is an i18n key under `graphCanvas.refuse`. */
export interface Refusal { key: string; params?: Record<string, string> }

/**
 * Mirrors `PortType::compatible_with`: `any` meets everything, otherwise the
 * types must be equal. Pure.
 */
export function portsCompatible(out: string, input: string): boolean {
  return out === 'any' || input === 'any' || out === input;
}

/** The output ports of a node, the error port included for non-entry kinds. Pure. */
export function outputsOf(kind: GraphNodeKind | undefined): GraphPortSpec[] {
  if (!kind) return [];
  return kind.isEntry ? kind.outputs : [...kind.outputs, { name: ON_ERROR_PORT, portType: 'json' }];
}

/** Whether `to` is reachable from `from` along the edges. Pure. */
export function reaches(edges: readonly GraphDocEdge[], from: string, to: string): boolean {
  const seen = new Set<string>();
  const stack = [from];
  while (stack.length) {
    const n = stack.pop() as string;
    if (n === to) return true;
    if (seen.has(n)) continue;
    seen.add(n);
    for (const e of edges) if (e.from_node === n) stack.push(e.to_node);
  }
  return false;
}

/**
 * Checks a connection from an output port to an input port while it is being
 * dragged: `null` when it may be made, otherwise why not. The same rules the
 * engine applies at publish (`attome_workflow::graph::validate`): the ports
 * exist, their types meet, an entry node takes no input, no edge is made
 * twice and no cycle is closed. Pure.
 */
export function checkConnection(
  doc: GraphDoc,
  kinds: readonly GraphNodeKind[],
  from: PortRef,
  to: PortRef,
): Refusal | null {
  const kindOf = (id: string) => {
    const node = doc.nodes.find(n => n.id === id);
    return node ? kinds.find(k => k.type === node.type) : undefined;
  };
  if (from.node === to.node) return { key: 'graphCanvas.refuse.self' };
  const fromKind = kindOf(from.node);
  const toKind = kindOf(to.node);
  const out = outputsOf(fromKind).find(p => p.name === from.port);
  if (!out) return { key: 'graphCanvas.refuse.noOutput', params: { port: from.port } };
  if (toKind?.isEntry) return { key: 'graphCanvas.refuse.entry' };
  const input = toKind?.inputs.find(p => p.name === to.port);
  if (!input) return { key: 'graphCanvas.refuse.noInput', params: { port: to.port } };
  if (!portsCompatible(out.portType, input.portType)) {
    return { key: 'graphCanvas.refuse.type', params: { from: out.portType, to: input.portType } };
  }
  if (doc.edges.some(e => e.from_node === from.node && e.from_port === from.port
      && e.to_node === to.node && e.to_port === to.port)) {
    return { key: 'graphCanvas.refuse.duplicate' };
  }
  if (reaches(doc.edges, to.node, from.node)) return { key: 'graphCanvas.refuse.cycle' };
  return null;
}

/** The input ports of `target` a drag from `from` may end on. Pure. */
export function droppableInputs(
  doc: GraphDoc, kinds: readonly GraphNodeKind[], from: PortRef, target: string,
): string[] {
  const node = doc.nodes.find(n => n.id === target);
  const kind = node ? kinds.find(k => k.type === node.type) : undefined;
  return (kind?.inputs ?? [])
    .filter(p => checkConnection(doc, kinds, from, { node: target, port: p.name }) === null)
    .map(p => p.name);
}

/** The command that adds an edge. Pure. */
export function connectCommand(from: PortRef, to: PortRef): EditCommand {
  return {
    op: 'add', path: '/edges/-',
    value: { from_node: from.node, from_port: from.port, to_node: to.node, to_port: to.port },
  };
}

/** The command that moves node `index` to (`x`, `y`), kept on the grid. Pure. */
export function moveNodeCommand(doc: GraphDoc, index: number, x: number, y: number, grid = 8): EditCommand {
  const snap = (v: number) => Math.max(0, Math.round(v / grid) * grid);
  const ports = { ...doc.nodes[index].ports, x: snap(x), y: snap(y) };
  return { op: 'set', path: `/nodes/${index}/ports`, value: ports };
}

/**
 * The commands that remove a node with every edge touching it, and drop it
 * from its groups; edges are removed from the last, so the indexes hold. Pure.
 */
export function removeNodeCommands(doc: GraphDoc, id: string): EditCommand[] {
  const out: EditCommand[] = [];
  doc.edges.forEach((e, i) => {
    if (e.from_node === id || e.to_node === id) out.unshift({ op: 'remove', path: `/edges/${i}` });
  });
  (doc.groups ?? []).forEach((g, gi) => {
    const at = g.nodes.indexOf(id);
    if (at >= 0) out.push({ op: 'remove', path: `/groups/${gi}/nodes/${at}` });
  });
  const index = doc.nodes.findIndex(n => n.id === id);
  if (index >= 0) out.push({ op: 'remove', path: `/nodes/${index}` });
  return out;
}

/** A new id not used by any node, group or note. Pure. */
export function freshId(doc: GraphDoc, prefix: string): string {
  const used = new Set([
    ...doc.nodes.map(n => n.id),
    ...(doc.groups ?? []).map(g => g.id),
    ...(doc.notes ?? []).map(n => n.id),
  ]);
  let i = 1;
  while (used.has(`${prefix}${i}`)) i++;
  return `${prefix}${i}`;
}

/** The commands that make sure `groups` and `notes` exist before adding to them. Pure. */
export function ensureLists(doc: GraphDoc): EditCommand[] {
  const out: EditCommand[] = [];
  if (!Array.isArray(doc.groups)) out.push({ op: 'add', path: '/groups', value: [] });
  if (!Array.isArray(doc.notes)) out.push({ op: 'add', path: '/notes', value: [] });
  return out;
}

/** Node card geometry, shared by the component's layout and its wires. */
export const CARD = { width: 200, header: 32, row: 22, pad: 8 } as const;

/** Where a port's dot sits, in canvas units. Inputs on the start edge, outputs on the end. Pure. */
export function portPoint(
  node: GraphDocNode, kind: GraphNodeKind | undefined, side: 'in' | 'out', port: string,
): { x: number; y: number } {
  const list = side === 'in' ? (kind?.inputs ?? []) : outputsOf(kind);
  const i = Math.max(0, list.findIndex(p => p.name === port));
  return {
    x: node.ports.x + (side === 'in' ? 0 : CARD.width),
    y: node.ports.y + CARD.header + CARD.pad + i * CARD.row + CARD.row / 2,
  };
}

/** A node card's height. Pure. */
export function cardHeight(kind: GraphNodeKind | undefined): number {
  const rows = Math.max(kind?.inputs.length ?? 0, outputsOf(kind).length, 1);
  return CARD.header + CARD.pad * 2 + rows * CARD.row;
}

/** A smooth wire between two points. Pure. */
export function wirePath(a: { x: number; y: number }, b: { x: number; y: number }): string {
  const dx = Math.max(40, Math.abs(b.x - a.x) / 2);
  return `M ${a.x} ${a.y} C ${a.x + dx} ${a.y}, ${b.x - dx} ${b.y}, ${b.x} ${b.y}`;
}

/** The box around a group's nodes, with a margin. `null` for an empty group. Pure. */
export function groupBox(
  doc: GraphDoc, kinds: readonly GraphNodeKind[], group: GraphDocGroup, margin = 16,
): { x: number; y: number; width: number; height: number } | null {
  const members = doc.nodes.filter(n => group.nodes.includes(n.id));
  if (!members.length) return null;
  const kindOf = (n: GraphDocNode) => kinds.find(k => k.type === n.type);
  const x0 = Math.min(...members.map(n => n.ports.x)) - margin;
  const y0 = Math.min(...members.map(n => n.ports.y)) - margin - 20;
  const x1 = Math.max(...members.map(n => n.ports.x + CARD.width)) + margin;
  const y1 = Math.max(...members.map(n => n.ports.y + cardHeight(kindOf(n)))) + margin;
  return { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
}
