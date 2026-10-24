import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { CanvasComponent, valueAt } from '@attome/xrm/canvas';
import type { EditCommand } from '@attome/xrm/canvas';
import { PageRuntimeComponent } from '@attome/xrm/core/page-runtime';
import type { Device, PageBinding, PageDoc, PageEvent, PageNode, PageNodeType } from '@attome/xrm/core/page-runtime';
import { ModelService } from '@attome/xrm/model';
import type { ModelCommand } from '@attome/xrm/model';

/** The component palette (`attome_model::kinds::page::NODE_TYPES`). */
export const PALETTE: readonly PageNodeType[] = [
  'container', 'tabs', 'text', 'list', 'form', 'chart', 'kanban', 'map', 'timeline', 'metric', 'button', 'custom',
];

/** Above this many reads, the page is flagged as likely slow. */
export const QUERY_BUDGET = 15;

const ROW_TYPES: readonly PageNodeType[] = ['list', 'chart', 'metric', 'kanban', 'map', 'timeline'];

/** One read the page makes when it opens. */
export interface ExpectedQuery { node: string; what: string; }

/**
 * The reads a page makes when it opens: one per component bound to a view
 * or stored query, one per record binding, and the page's own record on a
 * record page. Pure.
 */
export function expectedQueries(doc: PageDoc | null): ExpectedQuery[] {
  if (!doc?.root) return [];
  const out: ExpectedQuery[] = [];
  if (doc.page_type === 'record') out.push({ node: '(page)', what: 'record' });
  const walk = (n: PageNode) => {
    const b = n.binding;
    if (b?.view && ROW_TYPES.includes(n.type)) out.push({ node: n.id, what: `view ${b.view}` });
    else if (b?.query && ROW_TYPES.includes(n.type)) out.push({ node: n.id, what: `query ${b.query}` });
    else if (b?.record && b.record !== 'current') out.push({ node: n.id, what: `record ${b.record}` });
    (n.children ?? []).forEach(walk);
  };
  walk(doc.root);
  return out;
}

/** A node id not yet on the page. Pure. */
export function freshId(doc: PageDoc | null, type: string): string {
  const used = new Set<string>();
  const walk = (n: PageNode) => { used.add(n.id); (n.children ?? []).forEach(walk); };
  if (doc?.root) walk(doc.root);
  for (let i = 1; ; i++) {
    const id = `${type}_${i}`;
    if (!used.has(id)) return id;
  }
}

type BindingKind = '' | 'view' | 'query' | 'record';

/**
 * T2-T3 — the page designer, at `/xrm/admin/pages/:id/design`: the page's
 * draft on the shared canvas (Y14-T1), a palette to add components into the
 * selected container, the selected component's binding and events, the
 * reads the page will make when it opens (flagged above 15), and a live
 * preview through the page runtime (T2-T2) as a chosen role, screen size
 * and language. Saving sends the canvas's edit commands against the
 * draft's content hash; publishing makes the draft the page people see.
 */
@Component({
  selector: 'xrm-page-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, CanvasComponent, PageRuntimeComponent],
  template: `
    <section class="pd" data-testid="page-designer">
      <header class="pd-head">
        <h2>{{ 'pageDesigner.title' | translate }} <bdi>{{ name() }}</bdi></h2>
        <div class="pd-actions">
          @if (saved(); as v) { <span class="pd-muted" role="status">{{ 'pageDesigner.saved' | translate: { version: v } }}</span> }
          <button type="button" data-testid="pd-publish" [disabled]="busy() || !hash()" (click)="publish()">{{ 'pageDesigner.publish' | translate }}</button>
        </div>
      </header>
      @if (error(); as e) { <p class="pd-error" role="alert">{{ e }}</p> }

      @if (initial(); as doc) {
        <div class="pd-layout">
          <nav class="pd-palette" [attr.aria-label]="'pageDesigner.palette' | translate">
            <h3>{{ 'pageDesigner.palette' | translate }}</h3>
            @for (t of palette; track t) {
              <button type="button" class="pd-tool" [attr.data-add]="t" (click)="add(t)">{{ 'pageDesigner.types.' + t | translate }}</button>
            }
          </nav>

          <div class="pd-main">
            <xrm-canvas [doc]="doc" rootPath="/root" (changed)="onChanged($event)" (save)="save($event)"
                        (selectionChange)="onSelect($event)" />

            @if (selectedNode(); as n) {
              <section class="pd-panel" data-testid="pd-binding">
                <h3>{{ 'pageDesigner.binding' | translate }}</h3>
                <label>{{ 'pageDesigner.bindTo' | translate }}
                  <select [ngModel]="bindingKind(n)" (ngModelChange)="setBinding($event, bindingValue(n))">
                    <option value="">{{ 'pageDesigner.none' | translate }}</option>
                    <option value="view">{{ 'pageDesigner.view' | translate }}</option>
                    <option value="query">{{ 'pageDesigner.query' | translate }}</option>
                    <option value="record">{{ 'pageDesigner.record' | translate }}</option>
                  </select>
                </label>
                @if (bindingKind(n)) {
                  <label>{{ 'pageDesigner.bindingValue' | translate }}
                    <input dir="ltr" data-testid="pd-binding-value" [ngModel]="bindingValue(n)"
                           (change)="setBinding(bindingKind(n), value($event))" />
                  </label>
                }
                <h3>{{ 'pageDesigner.events' | translate }}</h3>
                <ul class="pd-events">
                  @for (e of n.events ?? []; track $index; let i = $index) {
                    <li><span dir="ltr">{{ e.on }} → {{ e.do }} {{ e.target }}</span>
                      <button type="button" (click)="removeEvent(i)">{{ 'pageDesigner.remove' | translate }}</button></li>
                  }
                </ul>
                <div class="pd-event-form">
                  <select [ngModel]="newOn()" (ngModelChange)="newOn.set($event)" [attr.aria-label]="'pageDesigner.on' | translate">
                    @for (o of triggers; track o) { <option [value]="o">{{ o }}</option> }
                  </select>
                  <select [ngModel]="newDo()" (ngModelChange)="newDo.set($event)" [attr.aria-label]="'pageDesigner.do' | translate">
                    @for (d of actions; track d) { <option [value]="d">{{ 'pageDesigner.actions.' + d | translate }}</option> }
                  </select>
                  <input dir="ltr" [attr.aria-label]="'pageDesigner.target' | translate" [ngModel]="newTarget()" (ngModelChange)="newTarget.set($event)" />
                  <button type="button" data-testid="pd-add-event" [disabled]="!newTarget().trim()" (click)="addEvent()">{{ 'pageDesigner.addEvent' | translate }}</button>
                </div>
              </section>
            }
          </div>

          <aside class="pd-side">
            <section class="pd-panel" data-testid="pd-queries">
              <h3>{{ 'pageDesigner.queries' | translate: { count: queries().length } }}</h3>
              @if (queries().length > budget) {
                <p class="pd-warn" role="alert" data-testid="pd-query-warning">{{ 'pageDesigner.tooMany' | translate: { budget: budget } }}</p>
              }
              <ul>@for (q of queries(); track $index) { <li dir="ltr">{{ q.node }}: {{ q.what }}</li> }</ul>
            </section>
            <section class="pd-panel">
              <h3>{{ 'pageDesigner.preview' | translate }}</h3>
              <label>{{ 'pageDesigner.asRoles' | translate }}
                <input [ngModel]="rolesText()" (ngModelChange)="rolesText.set($event)" />
              </label>
              <label>{{ 'pageDesigner.size' | translate }}
                <select [ngModel]="device()" (ngModelChange)="device.set($event)">
                  <option value="desktop">{{ 'pageDesigner.desktop' | translate }}</option>
                  <option value="tablet">{{ 'pageDesigner.tablet' | translate }}</option>
                  <option value="phone">{{ 'pageDesigner.phone' | translate }}</option>
                </select>
              </label>
              <label>{{ 'pageDesigner.language' | translate }}
                <select [ngModel]="language()" (ngModelChange)="language.set($event)">
                  <option value="en">English</option>
                  <option value="ar">العربية</option>
                </select>
              </label>
              <div class="pd-preview" [class]="'pd-preview pd-preview--' + device()" data-testid="pd-preview">
                <xrm-page-runtime [page]="current()" [previewRoles]="previewRoles()" [previewDevice]="device()"
                                  [previewArabic]="language() === 'ar'" />
              </div>
            </section>
          </aside>
        </div>
      } @else if (!error()) {
        <p class="pd-muted">{{ 'pageDesigner.loading' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .pd { display: grid; gap: .75rem; }
    .pd-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: .5rem; }
    .pd-head h2 { margin: 0; }
    .pd-actions { display: flex; gap: .5rem; align-items: center; }
    .pd-layout { display: grid; grid-template-columns: 10rem minmax(0, 1fr) minmax(16rem, 24rem); gap: .75rem; align-items: start; }
    @media (max-width: 64rem) { .pd-layout { grid-template-columns: minmax(0, 1fr); } }
    .pd-palette { display: grid; gap: .25rem; }
    .pd-palette h3, .pd-panel h3 { margin: 0; font-size: .875rem; }
    .pd-tool { text-align: start; }
    .pd-main, .pd-side { display: grid; gap: .75rem; min-inline-size: 0; }
    .pd-panel { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; }
    .pd-panel label { display: grid; gap: .25rem; font-size: .8125rem; }
    .pd-events { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .pd-event-form { display: flex; flex-wrap: wrap; gap: .25rem; }
    .pd-warn { color: var(--color-warning, #8a5a00); margin: 0; }
    .pd-error { color: var(--color-danger, #c53030); }
    .pd-muted { color: var(--color-text-secondary, #666); }
    .pd-preview { border: 1px dashed var(--color-border, #ccc); border-radius: 8px; overflow: auto; max-block-size: 40rem; }
    .pd-preview--phone { max-inline-size: 375px; }
    .pd-preview--tablet { max-inline-size: 768px; }
  `],
})
export class PageDesignerComponent {
  private readonly model = inject(ModelService);
  private readonly lang = inject(LangService);
  private readonly canvas = viewChild(CanvasComponent);

  /** The page object (route parameter). */
  readonly id = input.required<string>();

  readonly palette = PALETTE;
  readonly budget = QUERY_BUDGET;
  readonly triggers: PageEvent['on'][] = ['load', 'click', 'select', 'submit', 'change'];
  readonly actions: PageEvent['do'][] = ['navigate', 'start_flow', 'run_action'];

  readonly initial = signal<PageDoc | null>(null);
  readonly current = signal<PageDoc | null>(null);
  readonly name = signal('');
  readonly hash = signal('');
  readonly saved = signal<number | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly selectedPath = signal<string | null>(null);
  readonly rolesText = signal('');
  readonly device = signal<Device>('desktop');
  readonly language = signal<'en' | 'ar'>('en');
  readonly newOn = signal<PageEvent['on']>('click');
  readonly newDo = signal<PageEvent['do']>('navigate');
  readonly newTarget = signal('');

  readonly queries = computed(() => expectedQueries(this.current()));
  readonly previewRoles = computed(() => {
    const roles = this.rolesText().split(',').map(r => r.trim()).filter(Boolean);
    return roles.length ? roles : null;
  });
  readonly selectedNode = computed(() => {
    const path = this.selectedPath();
    const doc = this.current();
    if (!path || !doc) return null;
    try {
      return valueAt(doc, path) as PageNode;
    } catch {
      return null;
    }
  });

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
  }

  onChanged(doc: unknown): void {
    this.current.set(doc as PageDoc);
  }

  onSelect(paths: string[]): void {
    this.selectedPath.set(paths.at(-1) ?? null);
  }

  /** Adds a component into the selected container (or the selected component's container, or the page). */
  add(type: PageNodeType): void {
    const doc = this.current();
    if (!doc) return;
    const id = freshId(doc, type);
    const node: PageNode = type === 'container' || type === 'tabs'
      ? { id, type, children: [] }
      : { id, type, props: type === 'text' ? { text_en: '', text_ar: '' } : { title_en: '', title_ar: '' } };
    const list = this.targetList();
    const length = (valueAt(doc, list) as unknown[]).length;
    this.exec({ op: 'add', path: `${list}/-`, value: node }, `${list}/${length}`);
  }

  bindingKind(n: PageNode): BindingKind {
    const b = n.binding;
    return b?.view !== undefined ? 'view' : b?.query !== undefined ? 'query' : b?.record !== undefined ? 'record' : '';
  }

  bindingValue(n: PageNode): string {
    const b = n.binding;
    return b?.view ?? b?.query ?? b?.record ?? '';
  }

  setBinding(kind: BindingKind, value: string): void {
    const path = this.selectedPath();
    const node = this.selectedNode();
    if (!path || !node) return;
    if (!kind) {
      if (node.binding) this.exec({ op: 'remove', path: `${path}/binding` });
      return;
    }
    const binding: PageBinding = { [kind]: value.trim() || (kind === 'record' ? 'current' : '') };
    this.exec({ op: 'set', path: `${path}/binding`, value: binding });
  }

  addEvent(): void {
    const path = this.selectedPath();
    const node = this.selectedNode();
    const target = this.newTarget().trim();
    if (!path || !node || !target) return;
    const event: PageEvent = { on: this.newOn(), do: this.newDo(), target };
    this.exec({ op: 'set', path: `${path}/events`, value: [...(node.events ?? []), event] });
    this.newTarget.set('');
  }

  removeEvent(index: number): void {
    const path = this.selectedPath();
    const node = this.selectedNode();
    if (!path || !node?.events) return;
    this.exec({ op: 'set', path: `${path}/events`, value: node.events.filter((_, i) => i !== index) });
  }

  save(commands: EditCommand[]): void {
    if (!commands.length) return;
    this.busy.set(true);
    this.error.set(null);
    // A new page starts from an empty document on the server: its base members go first.
    const isNew = !this.hash();
    const base: EditCommand[] = isNew
      ? Object.entries(this.initial() ?? {}).map(([k, v]) => ({ op: 'set' as const, path: `/${k}`, value: v }))
      : [];
    this.model.saveDraft('page', this.id(), this.hash(), isNew ? this.name() || 'page' : null, [...base, ...commands] as ModelCommand[]).subscribe({
      next: saved => {
        this.busy.set(false);
        this.hash.set(saved.content_hash);
        this.saved.set(saved.version_no);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 409 ? this.lang.translate('pageDesigner.conflict') : this.lang.errorText(e));
      },
    });
  }

  publish(): void {
    this.busy.set(true);
    this.model.publish('page', this.id()).subscribe({
      next: () => this.busy.set(false),
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  private exec(command: EditCommand, select?: string): void {
    this.canvas()?.exec(command, select);
  }

  /** The children list a new component goes into. */
  private targetList(): string {
    const path = this.selectedPath();
    const node = this.selectedNode();
    if (path && node && Array.isArray(node.children)) return `${path}/children`;
    if (path && path !== '/root') {
      const parent = path.slice(0, path.lastIndexOf('/'));
      if (parent.endsWith('/children')) return parent;
    }
    return '/root/children';
  }

  private load(id: string): void {
    this.error.set(null);
    this.model.object('page', id).subscribe({
      next: v => {
        const doc = v.doc as PageDoc;
        this.name.set(v.name);
        this.hash.set(v.content_hash);
        this.initial.set(doc);
        this.current.set(doc);
      },
      error: (e: ApiError) => {
        if (e.status === 404) {
          // A new page: start from an empty custom page; the first save creates it.
          const doc: PageDoc = { page_type: 'custom', title_en: '', title_ar: '', root: { id: 'main', type: 'container', children: [] } };
          this.hash.set('');
          this.initial.set(doc);
          this.current.set(doc);
        } else {
          this.error.set(this.lang.errorText(e));
        }
      },
    });
  }
}
