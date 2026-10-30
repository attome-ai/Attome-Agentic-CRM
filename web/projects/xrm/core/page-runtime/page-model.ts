import type { ConditionTree } from '@attome/xrm';

/** The page kind's document (`attome_model::kinds::page`, T2-T1). */
export interface PageDoc {
  id?: string;
  name?: string;
  page_type: 'app_home' | 'workspace' | 'custom' | 'record' | 'portal';
  /** D1-T2: this record page is its entity's record page. */
  default?: boolean;
  entity?: string;
  title_en?: string;
  title_ar?: string;
  description_en?: string;
  root: PageNode;
}

export type PageNodeType =
  | 'container' | 'tabs' | 'text' | 'list' | 'form' | 'chart' | 'kanban' | 'map' | 'timeline'
  | 'metric' | 'button' | 'custom';

/** D1-T2: a condition an entity binding's rows meet. */
export interface PageCondition {
  field: string;
  op: 'eq' | 'in';
  value: string | number | boolean | string[];
}

/** A binding is one of a view, a stored query, an entity, or a record. */
export interface PageBinding {
  view?: string;
  query?: string;
  /** D1-T2: an entity's records, by logical name. */
  entity?: string;
  /** D1-T2: a lookup field of the listed rows that must name the page's record. */
  related_by?: string;
  /** D1-T2: conditions on an entity binding's rows. */
  where?: PageCondition[];
  /** `current` (the page's record), or the lookup attribute of it to follow. */
  record?: string;
}

export interface PageEvent {
  on: 'load' | 'click' | 'select' | 'submit' | 'change';
  do: 'start_flow' | 'run_action' | 'navigate';
  target: string;
}

/** T2-T2: when a component shows. Every part given must hold. */
export interface PageVisibility {
  /** Shown only to holders of one of these roles (by name). */
  roles?: string[];
  /** Shown only on these screen sizes. */
  devices?: Device[];
  /** Shown only when this condition holds on the page's record (the A11 condition shape). */
  when?: ConditionTree;
}

export interface PageNode {
  id: string;
  type: PageNodeType;
  props?: Record<string, unknown> & { visible?: PageVisibility };
  binding?: PageBinding;
  events?: PageEvent[];
  children?: PageNode[];
  component?: string;
}

export type Device = 'phone' | 'tablet' | 'desktop';

/** The screen size class for a viewport width in CSS pixels. Pure. */
export function deviceOf(width: number): Device {
  if (width < 640) return 'phone';
  if (width < 1024) return 'tablet';
  return 'desktop';
}

/** What visibility is decided against. */
export interface VisibilityContext {
  roles: readonly string[];
  device: Device;
  /** Evaluates a condition on the page's record; `null` when it cannot (no record). */
  holds: (when: ConditionTree) => boolean | null;
}

/**
 * Whether `node` shows. A role list needs one of the caller's roles; a
 * device list needs the current size; a condition needs to hold on the
 * record, and a condition that cannot be decided (no record yet) hides the
 * node rather than showing something it should not. Pure.
 */
export function isVisible(node: PageNode, ctx: VisibilityContext): boolean {
  const v = node.props?.visible;
  if (!v) return true;
  if (v.roles?.length && !v.roles.some(r => ctx.roles.includes(r))) return false;
  if (v.devices?.length && !v.devices.includes(ctx.device)) return false;
  if (v.when && ctx.holds(v.when) !== true) return false;
  return true;
}

/** A localised prop (`<key>_en` / `<key>_ar`), falling back to the other language. Pure. */
export function textProp(props: Record<string, unknown> | undefined, key: string, arabic: boolean): string {
  const en = props?.[`${key}_en`];
  const ar = props?.[`${key}_ar`];
  const pick = arabic ? (ar ?? en) : (en ?? ar);
  return typeof pick === 'string' ? pick : '';
}

/** A navigate target with `{id}` filled from the selected row or the page's record. Pure. */
export function fillTarget(target: string, id: string | null): string | null {
  if (!target.startsWith('/') || target.startsWith('//') || target.includes(':')) return null;
  if (target.includes('{id}')) return id ? target.replace(/\{id\}/g, encodeURIComponent(id)) : null;
  return target;
}

/** Label and value pairs for a chart or metric from tabular rows: the first text column and the first numeric one. Pure. */
export function seriesOf(rows: readonly Record<string, unknown>[]): { label: string; value: number }[] {
  if (rows.length === 0) return [];
  const keys = Object.keys(rows[0]).filter(k => k !== 'id');
  const numeric = keys.find(k => rows.every(r => r[k] === null || r[k] === undefined || typeof r[k] === 'number' || (typeof r[k] === 'string' && r[k] !== '' && !isNaN(Number(r[k])))));
  const label = keys.find(k => k !== numeric) ?? numeric;
  if (!numeric || !label) return [];
  return rows.map(r => ({ label: String(r[label] ?? ''), value: Number(r[numeric] ?? 0) }));
}
