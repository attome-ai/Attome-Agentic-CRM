/**
 * P5-T1: a dashboard's draft (its `dashboard_page`, `dashboard_section` and
 * `dashboard_widget` records) as the one tree the shared canvas edits, and
 * the record writes that turn an edited tree back into the draft. All pure.
 *
 * Each node keeps its record id and row version; a node the designer added
 * has none and a temporary `ref` instead, so a widget added into a section
 * added in the same save is created after it, under its new id.
 */
import type { DashboardTree } from '@attome/xrm/dashboard/data';

export type DNodeType = 'dashboard' | 'page' | 'section' | 'widget';

/** One node of the canvas tree. */
export interface DNode {
  type: DNodeType;
  /** The record, when it is stored. */
  id?: string;
  rowVersion?: number;
  /** A node added in the designer, until its record is created. */
  ref?: string;
  props: Record<string, unknown>;
  children?: DNode[];
}

/** The canvas document: the tree under `/root`. */
export interface DDoc { root: DNode }

/** What the designer edits of each record. */
export const PAGE_KEYS = ['name', 'name_ar'] as const;
export const SECTION_KEYS = ['name', 'section_type', 'layout_mode'] as const;
export const WIDGET_KEYS = ['name', 'name_ar', 'widget_type', 'grid_col', 'grid_row', 'grid_col_span', 'grid_row_span'] as const;

const ENTITY: Record<Exclude<DNodeType, 'dashboard'>, string> = {
  page: 'dashboard_page', section: 'dashboard_section', widget: 'dashboard_widget',
};

function keysOf(type: DNodeType): readonly string[] {
  return type === 'page' ? PAGE_KEYS : type === 'section' ? SECTION_KEYS : type === 'widget' ? WIDGET_KEYS : [];
}

function pick(data: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (data[k] !== undefined) out[k] = data[k];
  return out;
}

function bySequence<T extends { data: Record<string, unknown> }>(a: T, b: T): number {
  return Number(a.data['sequence'] ?? 0) - Number(b.data['sequence'] ?? 0);
}

/** The canvas tree of a dashboard's draft. */
export function toDesign(tree: DashboardTree): DDoc {
  const sectionNode = (s: DashboardTree['sections'][number]): DNode => ({
    type: 'section',
    id: s.id,
    rowVersion: s.row_version,
    props: pick(s.data, SECTION_KEYS),
    children: [
      ...tree.sections.filter(c => c.data['parent_section_id'] === s.id).sort(bySequence).map(sectionNode),
      ...[...(tree.widgetsBySection.get(s.id) ?? [])].sort(bySequence).map(w => ({
        type: 'widget' as const, id: w.id, rowVersion: w.row_version, props: pick(w.data, WIDGET_KEYS),
      })),
    ],
  });
  const pages = [...tree.pages].sort(bySequence).map(p => ({
    type: 'page' as const,
    id: p.id,
    rowVersion: p.row_version,
    props: pick(p.data, PAGE_KEYS),
    children: tree.sections
      .filter(s => s.data['page_id'] === p.id && !s.data['parent_section_id'])
      .sort(bySequence)
      .map(sectionNode),
  }));
  return { root: { type: 'dashboard', id: tree.dashboard.id, props: {}, children: pages } };
}

/** Where a new record's parent is: a stored id, or the ref of one created earlier in the save. */
export interface ParentLink { id?: string; ref?: string }

/** One record write of a save, in order. */
export type SaveOp =
  | { kind: 'create'; entity: string; ref: string; data: Record<string, unknown>; links: Record<string, ParentLink> }
  | { kind: 'update'; entity: string; id: string; rowVersion: number; patch: Record<string, unknown>; links: Record<string, ParentLink> }
  | { kind: 'delete'; entity: string; id: string };

interface Placed { node: DNode; parent: DNode | null; index: number }

function walk(doc: DDoc): Placed[] {
  const out: Placed[] = [];
  const visit = (node: DNode, parent: DNode | null, index: number) => {
    out.push({ node, parent, index });
    const counters: Record<string, number> = {};
    for (const child of node.children ?? []) {
      const i = counters[child.type] ?? 0;
      counters[child.type] = i + 1;
      visit(child, node, i);
    }
  };
  visit(doc.root, null, 0);
  return out;
}

function link(node: DNode | null): ParentLink {
  return node?.id ? { id: node.id } : { ref: node?.ref ?? '' };
}

/** The parent links a node's record takes, by its place in the tree. */
function linksOf(p: Placed, pageOf: Map<DNode, DNode>): Record<string, ParentLink> | null {
  const { node, parent } = p;
  if (!parent) return null;
  if (node.type === 'page' && parent.type === 'dashboard') return { dashboard_id: link(parent) };
  if (node.type === 'section' && parent.type === 'page') return { page_id: link(parent), parent_section_id: {} };
  if (node.type === 'section' && parent.type === 'section') {
    return { page_id: link(pageOf.get(parent) ?? null), parent_section_id: link(parent) };
  }
  if (node.type === 'widget' && parent.type === 'section') return { section_id: link(parent) };
  return null;
}

/** A misplaced node (a widget outside a section, a page inside one): not saved. */
export function misplaced(doc: DDoc): number {
  const pageOf = pagesOf(doc);
  return walk(doc).filter(p => p.parent && !linksOf(p, pageOf)).length;
}

function pagesOf(doc: DDoc): Map<DNode, DNode> {
  const out = new Map<DNode, DNode>();
  const visit = (node: DNode, page: DNode | null) => {
    const here = node.type === 'page' ? node : page;
    if (here && node.type === 'section') out.set(node, here);
    for (const c of node.children ?? []) visit(c, here);
  };
  visit(doc.root, null);
  return out;
}

/**
 * The record writes that make `before` (the tree as loaded or last saved)
 * into `after`: creates and updates in tree order, parents first, then the
 * deletes, deepest first. An update carries only the edited keys, the
 * sequence when the node moved among its siblings, and the parent links
 * when it moved to another parent.
 */
export function planSave(before: DDoc, after: DDoc): { ops: SaveOp[]; misplaced: number } {
  const old = new Map<string, Placed>();
  const oldPages = pagesOf(before);
  const oldLinks = new Map<string, Record<string, ParentLink>>();
  for (const p of walk(before)) {
    if (!p.node.id) continue;
    old.set(p.node.id, p);
    const l = linksOf(p, oldPages);
    if (l) oldLinks.set(p.node.id, l);
  }
  const pages = pagesOf(after);
  const ops: SaveOp[] = [];
  let bad = 0;
  const kept = new Set<string>();
  for (const p of walk(after)) {
    if (p.node.type === 'dashboard') continue;
    const links = linksOf(p, pages);
    if (!links) { bad++; continue; }
    const entity = ENTITY[p.node.type];
    const props = pick(p.node.props, keysOf(p.node.type));
    if (!p.node.id) {
      ops.push({ kind: 'create', entity, ref: p.node.ref ?? '', data: { ...props, sequence: p.index }, links });
      continue;
    }
    kept.add(p.node.id);
    const was = old.get(p.node.id);
    const patch: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(props)) {
      if (JSON.stringify(was?.node.props[k]) !== JSON.stringify(v)) patch[k] = v;
    }
    if (!was || was.index !== p.index) patch['sequence'] = p.index;
    const before = oldLinks.get(p.node.id) ?? {};
    const moved: Record<string, ParentLink> = {};
    for (const [field, l] of Object.entries(links)) {
      const same = !l.ref && (before[field]?.id ?? null) === (l.id ?? null);
      if (!same) moved[field] = l;
    }
    if (Object.keys(patch).length || Object.keys(moved).length) {
      ops.push({ kind: 'update', entity, id: p.node.id, rowVersion: p.node.rowVersion ?? 0, patch, links: moved });
    }
  }
  const deletes = walk(before)
    .filter(p => p.node.type !== 'dashboard' && p.node.id && !kept.has(p.node.id))
    .reverse()
    .map(p => ({ kind: 'delete' as const, entity: ENTITY[p.node.type as Exclude<DNodeType, 'dashboard'>], id: p.node.id ?? '' }));
  return { ops: [...ops, ...deletes], misplaced: bad };
}

/** A save's data for one op, its parent links resolved through `created` (ref to id). */
export function resolveLinks(links: Record<string, ParentLink>, created: ReadonlyMap<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [field, l] of Object.entries(links)) {
    out[field] = l.id ?? (l.ref ? created.get(l.ref) ?? null : null);
  }
  return out;
}

/** One widget as the breakpoint preview lays it out. */
export interface PreviewBox { name: string; type: string; col: number; span: number; rowSpan: number }

/** Columns at each preview width. */
export const PREVIEW_COLUMNS = { desktop: 12, tablet: 6, phone: 1 } as const;
export type Breakpoint = keyof typeof PREVIEW_COLUMNS;

/**
 * A page's widgets in reading order, laid out for `breakpoint`: on the
 * 12-column grid as stored, on a tablet each span halved (at least one), on
 * a phone one column. Pure.
 */
export function previewBoxes(page: DNode | null, breakpoint: Breakpoint): PreviewBox[] {
  const widgets: DNode[] = [];
  const visit = (n: DNode) => {
    if (n.type === 'widget') widgets.push(n);
    (n.children ?? []).forEach(visit);
  };
  if (page) visit(page);
  const columns = PREVIEW_COLUMNS[breakpoint];
  return widgets.map(w => {
    const span = Math.min(12, Math.max(1, Number(w.props['grid_col_span'] ?? 4) || 4));
    const col = Math.max(1, Number(w.props['grid_col'] ?? 1) || 1);
    return {
      name: String(w.props['name'] ?? ''),
      type: String(w.props['widget_type'] ?? ''),
      col: breakpoint === 'desktop' ? Math.min(col, 12) : 1,
      span: breakpoint === 'desktop' ? span : breakpoint === 'tablet' ? Math.min(columns, Math.ceil(span / 2)) : 1,
      rowSpan: Math.max(1, Number(w.props['grid_row_span'] ?? 2) || 2),
    };
  });
}
