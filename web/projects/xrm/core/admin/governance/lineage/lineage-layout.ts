import type {
  LineageComparison, LineageDirection, LineageEdge, LineageGraph, LineageNode,
} from '@attome/xrm/core/admin/data';

/** A node's box, and the gaps between boxes, in drawing units. */
export const NODE_W = 180;
export const NODE_H = 40;
const COL_GAP = 72;
const ROW_GAP = 16;

export interface PlacedNode {
  node: LineageNode;
  x: number;
  y: number;
  /** A definition that uses a personal attribute. */
  sensitive: boolean;
  start: boolean;
}

export interface PlacedEdge {
  key: string;
  edge: LineageEdge;
  path: string;
  /** The using end reads personal data: the path is drawn in red. */
  sensitive: boolean;
  /** In compare mode, the edge appeared between the two versions. */
  added: boolean;
}

export interface LineageLayout {
  nodes: PlacedNode[];
  edges: PlacedEdge[];
  width: number;
  height: number;
}

const edgeKey = (e: LineageEdge) => `${e.from}|${e.to}|${e.edge_kind}`;

/**
 * Lays a walk out in columns by depth, so data flows toward the end of the
 * reading direction: in a `down` walk the start node comes first and what
 * uses it after; in an `up` walk what the start uses comes first and the
 * start last. `from` uses `to`, so each edge is drawn from `to` (the
 * source) to `from`. In right to left the x axis is mirrored, so the flow
 * reads right to left. Pure.
 */
export function layoutLineage(
  graph: LineageGraph,
  direction: LineageDirection,
  rtl: boolean,
  comparison: LineageComparison | null = null,
): LineageLayout {
  const deepest = graph.nodes.reduce((m, n) => Math.max(m, n.depth), 0);
  const columns = new Map<number, LineageNode[]>();
  for (const n of graph.nodes) {
    const col = direction === 'down' ? n.depth : deepest - n.depth;
    const list = columns.get(col) ?? [];
    list.push(n);
    columns.set(col, list);
  }
  const nodes: PlacedNode[] = [];
  let tallest = 0;
  for (const [col, list] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
    list.sort((a, b) => a.label.localeCompare(b.label) || a.key.localeCompare(b.key));
    list.forEach((node, row) => {
      nodes.push({
        node,
        x: col * (NODE_W + COL_GAP),
        y: row * (NODE_H + ROW_GAP),
        sensitive: node.reads_personal,
        start: node.depth === 0,
      });
    });
    tallest = Math.max(tallest, list.length);
  }
  const width = columns.size ? (deepest + 1) * (NODE_W + COL_GAP) - COL_GAP : 0;
  const height = tallest ? tallest * (NODE_H + ROW_GAP) - ROW_GAP : 0;
  if (rtl) for (const p of nodes) p.x = width - p.x - NODE_W;

  const at = new Map(nodes.map(p => [p.node.key, p]));
  const added = new Set((comparison?.added ?? []).map(edgeKey));
  const edges: PlacedEdge[] = [];
  for (const e of graph.edges) {
    const source = at.get(e.to);
    const user = at.get(e.from);
    if (!source || !user || source === user) continue;
    edges.push({
      key: edgeKey(e),
      edge: e,
      path: edgePath(source, user),
      sensitive: user.sensitive,
      added: added.has(edgeKey(e)),
    });
  }
  return { nodes, edges, width, height };
}

/** A curve from the source box's side facing the user to the user box's facing side. */
function edgePath(source: PlacedNode, user: PlacedNode): string {
  const sy = source.y + NODE_H / 2;
  const uy = user.y + NODE_H / 2;
  if (source.x === user.x) {
    // The same column: bow out past the boxes' end side.
    const x = source.x + NODE_W;
    return `M${x},${sy} C${x + 40},${sy} ${x + 40},${uy} ${x},${uy}`;
  }
  const forward = user.x > source.x;
  const sx = forward ? source.x + NODE_W : source.x;
  const ux = forward ? user.x : user.x + NODE_W;
  const mid = (sx + ux) / 2;
  return `M${sx},${sy} C${mid},${sy} ${mid},${uy} ${ux},${uy}`;
}

/** The `{kind}/{ref}` path parts a node key names (`entity:<e>[.<a>]` or `<kind>:<id>`). Pure. */
export function walkTarget(key: string): { kind: string; ref: string } | null {
  const at = key.indexOf(':');
  if (at <= 0 || at === key.length - 1) return null;
  return { kind: key.slice(0, at), ref: key.slice(at + 1) };
}
