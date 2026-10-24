import {
  ChangeDetectionStrategy, Component, TemplateRef, computed, effect, input, output, signal, untracked,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { TranslatePipe } from '@attome/base';

import { CommandStack } from './command-stack';
import { EditCommand, valueAt } from './commands';

/** A node of the tree under edit: an object, with its children in `childrenKey`. */
export type CanvasNode = Record<string, unknown>;

/** One node where it sits. */
export interface PlacedNode {
  path: string;
  node: CanvasNode;
  depth: number;
  /** The array holding it (`<parent>/<childrenKey>`), `null` for the root. */
  listPath: string | null;
  index: number;
  container: boolean;
}

/** Another editor, and the node they have selected. */
export interface CanvasPresence { name: string; path: string | null; }

/** The tree in reading order, each node with its pointer. Pure. */
export function flatten(doc: unknown, rootPath: string, childrenKey: string): PlacedNode[] {
  const out: PlacedNode[] = [];
  let root: unknown;
  try {
    root = rootPath === '' ? doc : valueAt(doc, rootPath);
  } catch {
    return out;
  }
  const walk = (node: unknown, path: string, depth: number, listPath: string | null, index: number) => {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return;
    const children = (node as CanvasNode)[childrenKey];
    out.push({ path, node: node as CanvasNode, depth, listPath, index, container: Array.isArray(children) });
    if (Array.isArray(children)) {
      const list = `${path}/${childrenKey}`;
      children.forEach((child, i) => walk(child, `${list}/${i}`, depth + 1, list, i));
    }
  };
  walk(root, rootPath, 0, null, 0);
  return out;
}

/**
 * `path` as it reads once the item at `fromList/fromIndex` is removed: a
 * later sibling, or anything under one, moves up by one. Pure.
 */
export function afterRemoval(path: string, fromList: string, fromIndex: number): string {
  const prefix = `${fromList}/`;
  if (!path.startsWith(prefix)) return path;
  const rest = path.slice(prefix.length);
  const cut = rest.indexOf('/');
  const segment = cut === -1 ? rest : rest.slice(0, cut);
  const k = Number(segment);
  if (!Number.isInteger(k) || k <= fromIndex) return path;
  return `${prefix}${k - 1}${cut === -1 ? '' : rest.slice(cut)}`;
}

/**
 * The move command that puts the node at `from` into `list` at `index`
 * (before the node there), both named as the tree stands now. The server
 * reads the destination after the removal (RFC 6902), so it is rewritten
 * for that. Pure.
 */
export function moveCommand(from: string, fromList: string | null, fromIndex: number, list: string, index: number): EditCommand {
  if (fromList === null) return { op: 'move', from, to: `${list}/${index}` };
  const to = fromList === list && fromIndex < index ? index - 1 : index;
  return { op: 'move', from, to: `${afterRemoval(list, fromList, fromIndex)}/${to}` };
}

/**
 * Y14-T1 — the canvas every designer edits on. It wraps each node of a
 * document's tree with a selection handle and renders the node through the
 * designer's own template (a page designer passes the page runtime's
 * renderer; the default shows the node's type and title). Every change is
 * an edit command (`commands.ts`), so undo and redo are unlimited and what
 * changed since the last save is exactly the command list the server takes.
 *
 * - Select with a click, Ctrl or Cmd adds to the selection.
 * - Drag a node onto a container to put it inside, or onto another node to
 *   put it before that node.
 * - Keyboard: arrows move the selection; Alt and an arrow moves the node
 *   among its siblings; Delete removes it; Ctrl+Z undoes; Ctrl+Y or
 *   Ctrl+Shift+Z redoes; Escape clears the selection.
 * - The property panel edits the selected node's `props` (text, numbers,
 *   on and off).
 * - Other editors' selections show as named badges (`presence`).
 *
 * The tree is laid out in the inline direction, so it mirrors in Arabic.
 */
@Component({
  selector: 'xrm-canvas',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgTemplateOutlet, TranslatePipe],
  template: `
    <div class="cv">
      <div class="cv-toolbar" role="toolbar" [attr.aria-label]="'canvas.toolbar' | translate">
        <button type="button" data-testid="canvas-undo" [disabled]="!stack().canUndo()" (click)="undo()">{{ 'canvas.undo' | translate }}</button>
        <button type="button" data-testid="canvas-redo" [disabled]="!stack().canRedo()" (click)="redo()">{{ 'canvas.redo' | translate }}</button>
        <button type="button" data-testid="canvas-save" [disabled]="!stack().dirty()" (click)="emitSave()">{{ 'canvas.save' | translate }}</button>
      </div>
      <div class="cv-body">
        <ul class="cv-tree" role="tree" tabindex="0" [attr.aria-label]="'canvas.tree' | translate"
            [attr.aria-activedescendant]="activeId()" (keydown)="onKey($event)" data-testid="canvas-tree">
          @for (p of placed(); track p.path) {
            <li role="treeitem" class="cv-node" [id]="idOf(p.path)" [attr.aria-level]="p.depth + 1"
                [attr.aria-selected]="selected().includes(p.path)" [class.cv-node--selected]="selected().includes(p.path)"
                [class.cv-node--container]="p.container" [style.--cv-depth]="p.depth"
                [attr.data-path]="p.path" data-testid="canvas-node" draggable="true"
                tabindex="-1" (click)="select(p.path, $event)" (keydown.enter)="select(p.path)"
                (dragstart)="dragStart(p)" (dragover)="$event.preventDefault()"
                (drop)="drop($event, p)">
              <span class="cv-handle" aria-hidden="true">⠿</span>
              @if (nodeTemplate(); as tpl) {
                <ng-container [ngTemplateOutlet]="tpl" [ngTemplateOutletContext]="{ $implicit: p.node, path: p.path }" />
              } @else {
                <span class="cv-type">{{ p.node['type'] ?? '' }}</span>
                <span class="cv-label" dir="auto">{{ labelOf(p.node) }}</span>
              }
              @for (o of presenceAt(p.path); track o.name) { <span class="cv-presence" data-testid="canvas-presence">{{ o.name }}</span> }
            </li>
          }
        </ul>
        <aside class="cv-props" [attr.aria-label]="'canvas.properties' | translate" data-testid="canvas-props">
          @if (focus(); as f) {
            <h3>{{ 'canvas.properties' | translate }}</h3>
            <p class="cv-muted"><span class="cv-type">{{ f.node['type'] ?? '' }}</span> <bdi dir="ltr">{{ f.node['id'] ?? '' }}</bdi></p>
            @for (prop of propsOf(f.node); track prop.key) {
              <div class="cv-prop">
                <label [attr.for]="'cv-prop-' + prop.key">{{ prop.key }}</label>
                @if (prop.kind === 'boolean') {
                  <input type="checkbox" [id]="'cv-prop-' + prop.key" [checked]="prop.value"
                         (change)="setProp(f.path, prop.key, checked($event))" />
                } @else {
                  <input [id]="'cv-prop-' + prop.key" [type]="prop.kind === 'number' ? 'number' : 'text'" dir="auto" [value]="prop.value"
                         [attr.data-prop]="prop.key"
                         (change)="setProp(f.path, prop.key, prop.kind === 'number' ? numberOf($event) : textOf($event))" />
                }
              </div>
            } @empty {
              <p class="cv-muted">{{ 'canvas.noProps' | translate }}</p>
            }
          } @else {
            <p class="cv-muted">{{ 'canvas.pick' | translate }}</p>
          }
        </aside>
      </div>
    </div>
  `,
  styles: [`
    .cv { display: grid; gap: .5rem; }
    .cv-toolbar { display: flex; gap: .5rem; }
    .cv-body { display: grid; grid-template-columns: minmax(0, 1fr) minmax(14rem, 18rem); gap: .75rem; }
    @media (max-width: 48rem) { .cv-body { grid-template-columns: minmax(0, 1fr); } }
    .cv-tree { list-style: none; margin: 0; padding: .5rem; border: 1px solid var(--color-border, #ddd); border-radius: 8px; min-block-size: 12rem; }
    .cv-tree:focus-visible { outline: 2px solid var(--color-primary, #2b6cb0); }
    .cv-node { display: flex; align-items: center; gap: .5rem; padding-block: .25rem; padding-inline: calc(var(--cv-depth, 0) * 1.25rem + .5rem) .5rem;
               border-radius: 6px; cursor: pointer; border: 1px solid transparent; }
    .cv-node--selected { border-color: var(--color-primary, #2b6cb0); background: var(--color-bg-alt, #f4f7fb); }
    .cv-handle { cursor: grab; color: var(--color-text-secondary, #888); }
    .cv-type { font-family: ui-monospace, monospace; font-size: .75rem; color: var(--color-text-secondary, #666); }
    .cv-presence { margin-inline-start: auto; font-size: .7rem; padding-inline: .375rem; border-radius: 999px; background: var(--color-warning-bg, #fff4e0); }
    .cv-props { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; align-content: start; }
    .cv-props h3 { margin: 0; font-size: 1rem; }
    .cv-prop { display: grid; gap: .25rem; font-size: .8125rem; }
    .cv-muted { color: var(--color-text-secondary, #666); margin: 0; }
  `],
})
export class CanvasComponent {
  /** The document to edit. */
  readonly doc = input.required<unknown>();
  /** Where the tree's root is in the document (a JSON Pointer; `''` for the document itself). */
  readonly rootPath = input('/root');
  /** The member holding a node's children. */
  readonly childrenKey = input('children');
  /** The designer's rendering of one node, given `$implicit` (the node) and `path`. */
  readonly nodeTemplate = input<TemplateRef<unknown> | null>(null);
  /** Other editors and what they have selected. */
  readonly presence = input<readonly CanvasPresence[]>([]);

  /** Save: the commands since the last save, for `POST .../commands`. */
  readonly save = output<EditCommand[]>();
  /** The document after every change. */
  readonly changed = output<unknown>();
  /** The selection, by path. */
  readonly selectionChange = output<string[]>();

  readonly stack = signal(new CommandStack<unknown>(null));
  readonly selected = signal<string[]>([]);
  private dragged: PlacedNode | null = null;

  readonly placed = computed(() => flatten(this.stack().doc(), this.rootPath(), this.childrenKey()));
  readonly focus = computed(() => {
    const last = this.selected().at(-1);
    return last ? this.placed().find(p => p.path === last) ?? null : null;
  });
  readonly activeId = computed(() => {
    const f = this.focus();
    return f ? this.idOf(f.path) : null;
  });

  constructor() {
    effect(() => {
      const doc = this.doc();
      untracked(() => {
        this.stack.set(new CommandStack(structuredClone(doc)));
        this.selected.set([]);
      });
    });
  }

  idOf(path: string): string {
    return `cv${path.replace(/[^a-z0-9]/gi, '_')}`;
  }

  labelOf(node: CanvasNode): string {
    const props = node['props'] as Record<string, unknown> | undefined;
    const title = props?.['title_en'] ?? props?.['label_en'] ?? props?.['text_en'] ?? node['id'];
    return typeof title === 'string' ? title : '';
  }

  presenceAt(path: string): CanvasPresence[] {
    return this.presence().filter(p => p.path === path);
  }

  propsOf(node: CanvasNode): { key: string; value: string | number | boolean; kind: 'text' | 'number' | 'boolean' }[] {
    const props = node['props'];
    if (!props || typeof props !== 'object' || Array.isArray(props)) return [];
    return Object.entries(props as Record<string, unknown>)
      .filter(([, v]) => ['string', 'number', 'boolean'].includes(typeof v))
      .map(([key, v]) => ({
        key,
        value: v as string | number | boolean,
        kind: typeof v === 'string' ? 'text' as const : typeof v === 'number' ? 'number' as const : 'boolean' as const,
      }));
  }

  select(path: string, event?: MouseEvent): void {
    const add = !!event && (event.ctrlKey || event.metaKey);
    this.selected.update(s => (add ? (s.includes(path) ? s.filter(p => p !== path) : [...s, path]) : [path]));
    this.selectionChange.emit(this.selected());
  }

  /** Applies one command; the selection follows a moved node. */
  exec(command: EditCommand, select?: string): boolean {
    if (!this.stack().exec(command)) return false;
    if (select !== undefined) this.selected.set(select ? [select] : []);
    this.changed.emit(this.stack().doc());
    return true;
  }

  undo(): void {
    if (this.stack().undo()) this.afterHistory();
  }

  redo(): void {
    if (this.stack().redo()) this.afterHistory();
  }

  emitSave(): void {
    this.save.emit(this.stack().takeUnsaved());
  }

  setProp(path: string, key: string, value: unknown): void {
    this.exec({ op: 'set', path: `${path}/props/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`, value });
  }

  dragStart(p: PlacedNode): void {
    this.dragged = p;
  }

  drop(event: Event, target: PlacedNode): void {
    event.preventDefault();
    event.stopPropagation();
    const from = this.dragged;
    this.dragged = null;
    if (!from || !from.listPath || from.path === target.path || target.path.startsWith(`${from.path}/`)) return;
    if (target.container) {
      const list = `${target.path}/${this.childrenKey()}`;
      const length = (target.node[this.childrenKey()] as unknown[]).length;
      const command = moveCommand(from.path, from.listPath, from.index, list, length);
      this.exec(command, command.op === 'move' ? command.to : undefined);
    } else if (target.listPath) {
      const command = moveCommand(from.path, from.listPath, from.index, target.listPath, target.index);
      this.exec(command, command.op === 'move' ? command.to : undefined);
    }
  }

  onKey(event: KeyboardEvent): void {
    const mod = event.ctrlKey || event.metaKey;
    const key = event.key;
    if (mod && key.toLowerCase() === 'z' && !event.shiftKey) { event.preventDefault(); this.undo(); return; }
    if (mod && (key.toLowerCase() === 'y' || (key.toLowerCase() === 'z' && event.shiftKey))) { event.preventDefault(); this.redo(); return; }
    if (key === 'Escape') { this.selected.set([]); return; }
    const placed = this.placed();
    const focus = this.focus();
    if (key === 'ArrowDown' || key === 'ArrowUp') {
      event.preventDefault();
      if (event.altKey && focus?.listPath) {
        const step = key === 'ArrowDown' ? 1 : -1;
        const siblings = valueAt(this.stack().doc(), focus.listPath) as unknown[];
        const to = focus.index + step;
        if (to < 0 || to >= siblings.length) return;
        // Down past the next sibling: insert after it, i.e. at index + 2 before the removal.
        const command = moveCommand(focus.path, focus.listPath, focus.index, focus.listPath, step > 0 ? to + 1 : to);
        this.exec(command, command.op === 'move' ? command.to : undefined);
        return;
      }
      const at = focus ? placed.findIndex(p => p.path === focus.path) : -1;
      const next = placed[Math.min(placed.length - 1, Math.max(0, at + (key === 'ArrowDown' ? 1 : -1)))];
      if (next) this.select(next.path);
      return;
    }
    if ((key === 'Delete' || key === 'Backspace') && focus?.listPath) {
      event.preventDefault();
      this.exec({ op: 'remove', path: focus.path }, '');
    }
  }

  protected checked(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }

  protected textOf(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected numberOf(event: Event): number {
    return Number((event.target as HTMLInputElement).value);
  }

  private afterHistory(): void {
    const paths = new Set(this.placed().map(p => p.path));
    this.selected.update(s => s.filter(p => paths.has(p)));
    this.changed.emit(this.stack().doc());
  }
}
