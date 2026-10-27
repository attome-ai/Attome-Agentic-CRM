/**
 * E2-T1: the email designer's JSON (`attome_marketing::email_render::EmailDesign`,
 * which the server renders into email-safe HTML and plain text, E2-T2) and
 * its form on the shared canvas (Y14-T1): a root `email` node whose children
 * are the blocks, each block's fields under `props`, and a `columns` block
 * holding `column` nodes. Pure.
 */

export type Direction = 'ltr' | 'rtl';

export type EmailBlock =
  | { type: 'heading'; text: string; level?: number }
  | { type: 'text'; text: string }
  | { type: 'image'; src: string; alt: string; href?: string | null; width?: number | null }
  | { type: 'button'; label: string; href: string }
  | { type: 'divider' }
  | { type: 'spacer'; height?: number }
  | { type: 'columns'; columns: EmailBlock[][] }
  | { type: 'dynamic'; [key: string]: unknown };

export interface EmailDesign {
  blocks: EmailBlock[];
  dir?: Direction;
  width?: number;
  primary_colour?: string;
}

/** The blocks the palette adds. */
export const PALETTE = ['heading', 'text', 'image', 'button', 'divider', 'spacer', 'columns'] as const;
export type PaletteType = (typeof PALETTE)[number];

/** A canvas node: id, type, the block's fields as props, children for containers. */
export interface DesignNode {
  id: string;
  type: string;
  props?: Record<string, unknown>;
  children?: DesignNode[];
}

export interface DesignDoc {
  root: DesignNode;
}

/** Widths a design may have, as the renderer accepts them. */
export const MIN_WIDTH = 320;
export const MAX_WIDTH = 800;

let counter = 0;
function nextId(type: string): string {
  counter += 1;
  return `${type}_${Date.now().toString(36)}_${counter}`;
}

/** A fresh block of `type` with empty fields. */
export function newNode(type: PaletteType): DesignNode {
  const id = nextId(type);
  switch (type) {
    case 'heading': return { id, type, props: { text: '', level: 1 } };
    case 'text': return { id, type, props: { text: '' } };
    case 'image': return { id, type, props: { src: '', alt: '', href: '', width: 0 } };
    case 'button': return { id, type, props: { label: '', href: '' } };
    case 'divider': return { id, type, props: {} };
    case 'spacer': return { id, type, props: { height: 16 } };
    case 'columns': return { id, type, children: [{ id: nextId('column'), type: 'column', children: [] }, { id: nextId('column'), type: 'column', children: [] }] };
  }
}

function toNode(block: EmailBlock): DesignNode {
  const id = nextId(block.type);
  if (block.type === 'columns') {
    return {
      id, type: 'columns',
      children: block.columns.map(col => ({ id: nextId('column'), type: 'column', children: col.map(toNode) })),
    };
  }
  if (block.type === 'dynamic') {
    // Content chosen per recipient (E25) is kept whole; the canvas only moves it.
    return { id, type: 'dynamic', props: { raw: JSON.stringify(block) } };
  }
  const { type, ...fields } = block;
  const props: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) props[k] = v ?? (k === 'width' ? 0 : '');
  return { id, type, props };
}

/** The canvas document for a design. Pure (but for fresh node ids). */
export function toCanvas(design: EmailDesign): DesignDoc {
  return { root: { id: 'email', type: 'email', children: design.blocks.map(toNode) } };
}

function text(v: unknown): string {
  return typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v);
}

function num(v: unknown): number | null {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : null;
}

function toBlock(node: DesignNode): EmailBlock | null {
  const p = node.props ?? {};
  switch (node.type) {
    case 'heading': return { type: 'heading', text: text(p['text']), level: Math.min(3, Math.max(1, num(p['level']) ?? 1)) };
    case 'text': return { type: 'text', text: text(p['text']) };
    case 'image': {
      const block: Extract<EmailBlock, { type: 'image' }> = { type: 'image', src: text(p['src']), alt: text(p['alt']) };
      const href = text(p['href']).trim();
      const width = num(p['width']);
      if (href) block.href = href;
      if (width) block.width = width;
      return block;
    }
    case 'button': return { type: 'button', label: text(p['label']), href: text(p['href']) };
    case 'divider': return { type: 'divider' };
    case 'spacer': return { type: 'spacer', height: num(p['height']) ?? 16 };
    case 'columns':
      return {
        type: 'columns',
        columns: (node.children ?? []).map(col => (col.children ?? []).map(toBlock).filter((b): b is EmailBlock => b !== null)),
      };
    case 'dynamic':
      try {
        return JSON.parse(text(p['raw'])) as EmailBlock;
      } catch {
        return null;
      }
    default:
      return null;
  }
}

/** The design a canvas document describes, with the design-wide settings. Pure. */
export function fromCanvas(doc: DesignDoc, settings: { dir: Direction; width: number; colour: string }): EmailDesign {
  const design: EmailDesign = {
    blocks: (doc.root.children ?? []).map(toBlock).filter((b): b is EmailBlock => b !== null),
    dir: settings.dir,
    width: Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, Math.round(settings.width) || 600)),
  };
  if (/^#[0-9a-fA-F]{6}$/.test(settings.colour.trim())) design.primary_colour = settings.colour.trim().toLowerCase();
  return design;
}

/** A link the renderer takes: http(s), mailto, tel or a `{{ }}` placeholder. Pure. */
export function linkOk(href: string): boolean {
  const h = href.trim();
  return /^(https?:|mailto:|tel:)/i.test(h) || /^\{\{.*\}\}$/.test(h);
}

/** What would make the server refuse the design, per block: `missingAlt`, `badLink`, `empty`. Pure. */
export function problems(design: EmailDesign): { index: string; problem: 'missingAlt' | 'badLink' | 'empty' }[] {
  const out: { index: string; problem: 'missingAlt' | 'badLink' | 'empty' }[] = [];
  const walk = (blocks: EmailBlock[], prefix: string) => blocks.forEach((b, i) => {
    const at = `${prefix}${i + 1}`;
    if (b.type === 'image') {
      if (!b.alt.trim()) out.push({ index: at, problem: 'missingAlt' });
      if (!b.src.trim()) out.push({ index: at, problem: 'empty' });
      if (b.href && !linkOk(b.href)) out.push({ index: at, problem: 'badLink' });
    } else if (b.type === 'button') {
      if (!b.label.trim()) out.push({ index: at, problem: 'empty' });
      if (!linkOk(b.href)) out.push({ index: at, problem: 'badLink' });
    } else if (b.type === 'columns') {
      b.columns.forEach((col, c) => walk(col, `${at}.${c + 1}.`));
    }
  });
  walk(design.blocks, '');
  return out;
}
