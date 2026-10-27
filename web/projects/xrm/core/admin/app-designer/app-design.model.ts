/**
 * A21-T3: an app's navigation (`attome_model::kinds::navigation`, A21-T1)
 * as the shared canvas edits it (Y14-T1): a root `app` node whose children
 * are the groups, each group's children its items, labels and targets under
 * `props`. Item roles ride along untouched; the landing pages and settings
 * stay beside the tree. Pure.
 */

export const ITEM_KINDS = ['view', 'form', 'dashboard', 'page', 'report', 'flow', 'url'] as const;
export type ItemKind = (typeof ITEM_KINDS)[number];

export interface NavItem {
  label: string;
  kind: ItemKind;
  target?: string;
  url?: string;
  roles?: string[];
  badge?: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export interface AppSettings {
  name?: string;
  icon?: string;
  primary_colour?: string;
  accent_colour?: string;
  languages?: ('en' | 'ar')[];
  time_zone?: string;
  /** The designer hides advanced options (roles, badges, landing pages, colours). */
  simple?: boolean;
}

export interface Navigation {
  groups: NavGroup[];
  landing?: { role: string; item: string }[];
  settings?: AppSettings;
}

export interface AppNode {
  id: string;
  type: 'app' | 'group' | 'item';
  props?: Record<string, unknown>;
  children?: AppNode[];
}

export interface AppDoc {
  root: AppNode;
}

let counter = 0;
function nextId(type: string): string {
  counter += 1;
  return `${type}_${counter}`;
}

/** A new group. */
export function groupNode(label: string): AppNode {
  return { id: nextId('group'), type: 'group', props: { label }, children: [] };
}

/** A new item opening `kind` (by `target` id, or `url`). */
export function itemNode(label: string, kind: ItemKind, target = '', url = ''): AppNode {
  const props: Record<string, unknown> = { label, kind, badge: '' };
  if (kind === 'url') props['url'] = url;
  else props['target'] = target;
  return { id: nextId('item'), type: 'item', props };
}

/** The canvas document for a navigation. Pure (but for fresh node ids). */
export function toCanvas(nav: Navigation): AppDoc {
  return {
    root: {
      id: 'app', type: 'app',
      children: (nav.groups ?? []).map(g => ({
        id: nextId('group'), type: 'group' as const, props: { label: g.label },
        children: (g.items ?? []).map(i => {
          const node = itemNode(i.label, i.kind, i.target ?? '', i.url ?? '');
          if (i.badge) (node.props as Record<string, unknown>)['badge'] = i.badge;
          if (i.roles?.length) (node.props as Record<string, unknown>)['roles'] = [...i.roles];
          return node;
        }),
      })),
    },
  };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : '';
}

function isKind(v: unknown): v is ItemKind {
  return typeof v === 'string' && (ITEM_KINDS as readonly string[]).includes(v);
}

/** The groups a canvas document describes; nodes without a label are left out. Pure. */
export function groupsOf(doc: AppDoc): NavGroup[] {
  return (doc.root.children ?? [])
    .filter(g => g.type === 'group' && str(g.props?.['label']))
    .map(g => ({
      label: str(g.props?.['label']),
      items: (g.children ?? [])
        .filter(i => i.type === 'item' && str(i.props?.['label']) && isKind(i.props?.['kind']))
        .map(i => {
          const p = i.props ?? {};
          const item: NavItem = { label: str(p['label']), kind: p['kind'] as ItemKind };
          if (item.kind === 'url') item.url = str(p['url']);
          else item.target = str(p['target']);
          if (str(p['badge'])) item.badge = str(p['badge']);
          if (Array.isArray(p['roles']) && p['roles'].length) item.roles = (p['roles'] as unknown[]).map(String);
          return item;
        }),
    }));
}

/** Every `<group>/<item>` path of the groups. Pure. */
export function itemPaths(groups: readonly NavGroup[]): Set<string> {
  return new Set(groups.flatMap(g => g.items.map(i => `${g.label}/${i.label}`)));
}

/** The settings without empty values. Pure. */
export function cleanSettings(s: AppSettings): AppSettings | undefined {
  const out: AppSettings = {};
  if (s.name?.trim()) out.name = s.name.trim();
  if (s.icon?.trim()) out.icon = s.icon.trim();
  if (s.primary_colour && /^#[0-9a-fA-F]{6}$/.test(s.primary_colour)) out.primary_colour = s.primary_colour.toLowerCase();
  if (s.accent_colour && /^#[0-9a-fA-F]{6}$/.test(s.accent_colour)) out.accent_colour = s.accent_colour.toLowerCase();
  if (s.languages?.length) out.languages = [...s.languages];
  if (s.time_zone?.trim()) out.time_zone = s.time_zone.trim();
  if (s.simple) out.simple = true;
  return Object.keys(out).length ? out : undefined;
}

/** The navigation to save: the canvas's groups, the landing pages that still name an item, the settings. Pure. */
export function navigationOf(doc: AppDoc, landing: Navigation['landing'], settings: AppSettings): Navigation {
  const groups = groupsOf(doc);
  const paths = itemPaths(groups);
  const nav: Navigation = { groups };
  const kept = (landing ?? []).filter(l => paths.has(l.item));
  if (kept.length) nav.landing = kept;
  const clean = cleanSettings(settings);
  if (clean) nav.settings = clean;
  return nav;
}

/** What the menu would be refused for, before saving: items without a target or a URL, duplicates. Pure. */
export function navProblems(groups: readonly NavGroup[]): { at: string; problem: 'noTarget' | 'badUrl' | 'duplicate' }[] {
  const out: { at: string; problem: 'noTarget' | 'badUrl' | 'duplicate' }[] = [];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  for (const g of groups) {
    const seen = new Set<string>();
    for (const i of g.items) {
      const at = `${g.label}/${i.label}`;
      if (seen.has(i.label)) out.push({ at, problem: 'duplicate' });
      seen.add(i.label);
      if (i.kind === 'url') {
        if (!/^(https?:\/\/|\/)/.test(i.url ?? '')) out.push({ at, problem: 'badUrl' });
      } else if (!uuid.test(i.target ?? '')) {
        out.push({ at, problem: 'noTarget' });
      }
    }
  }
  return out;
}

/** One draft edit as the model's command endpoint takes it. */
export type SaveCommand = { op: 'set'; path: string; value: unknown } | { op: 'remove'; path: string };

/** The edit commands that make the server's draft this navigation: each member set whole. Pure. */
export function saveCommands(nav: Navigation, before: Partial<Navigation>): SaveCommand[] {
  const out: SaveCommand[] = [{ op: 'set', path: '/groups', value: nav.groups }];
  for (const key of ['landing', 'settings'] as const) {
    if (nav[key] !== undefined) out.push({ op: 'set', path: `/${key}`, value: nav[key] });
    else if (before[key] !== undefined) out.push({ op: 'remove', path: `/${key}` });
  }
  return out;
}

/** A UUIDv7 (time-ordered) for a new app, as the model's ids are. */
export function uuidv7(now: number = Date.now()): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let ms = now;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = ms % 256;
    ms = Math.floor(ms / 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
