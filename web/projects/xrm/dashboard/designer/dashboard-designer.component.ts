import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { CanvasComponent, valueAt } from '@attome/xrm/canvas';
import type { EditCommand } from '@attome/xrm/canvas';
import { EntityService } from '@attome/xrm/core/entity';
import { DashboardService } from '@attome/xrm/dashboard/data';
import type { WidgetDescriptor } from '@attome/xrm/dashboard/data';
import { Observable, concatMap, from, lastValueFrom, map, toArray } from 'rxjs';

import {
  Breakpoint, DDoc, DNode, PREVIEW_COLUMNS, misplaced, planSave, previewBoxes, resolveLinks, toDesign,
} from './dashboard-doc';
import type { SaveOp } from './dashboard-doc';

/**
 * P5-T1 — the dashboard designer, at `/xrm/dashboard/:id/design`: the
 * dashboard's draft (its pages, sections and widgets) on the shared canvas
 * (Y14-T1). Add a page, a section, or a widget from the registry into what
 * is selected; drag to reorder or move a widget between sections; the
 * property panel edits names, the section's type and layout, and a widget's
 * place and size on the 12-column grid. Beside it a breakpoint preview lays
 * out the selected page at desktop, tablet and phone widths. Saving writes
 * the records that changed (creates, then updates with `If-Match`, then
 * deletes) and reloads the draft; what viewers see changes when the draft is
 * published, as before.
 */
@Component({
  selector: 'xrm-dashboard-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, CanvasComponent],
  template: `
    <section class="dd" data-testid="dashboard-designer">
      <header class="dd-head">
        <h2>{{ 'dashboardDesigner.title' | translate }} <bdi>{{ name() }}</bdi></h2>
        @if (saving()) { <span class="dd-muted" role="status">{{ 'dashboardDesigner.saving' | translate }}</span> }
        @else if (savedAt()) { <span class="dd-muted" role="status">{{ 'dashboardDesigner.saved' | translate }}</span> }
      </header>
      <p class="dd-muted" data-testid="dd-visibility">
        {{ (personal() ? 'dashboardDesigner.personal' : 'dashboardDesigner.shared') | translate }}
      </p>
      @if (error(); as e) { <p class="dd-error" role="alert">{{ e }}</p> }
      @if (misplacedCount()) {
        <p class="dd-error" role="alert" data-testid="dd-misplaced">{{ 'dashboardDesigner.misplaced' | translate: { count: misplacedCount() } }}</p>
      }

      @if (initial(); as doc) {
        <div class="dd-layout">
          <nav class="dd-palette" [attr.aria-label]="'dashboardDesigner.palette' | translate">
            <h3>{{ 'dashboardDesigner.layout' | translate }}</h3>
            <button type="button" class="dd-tool" data-add="page" (click)="addPage()">{{ 'dashboardDesigner.addPage' | translate }}</button>
            <button type="button" class="dd-tool" data-add="section" (click)="addSection()">{{ 'dashboardDesigner.addSection' | translate }}</button>
            <h3>{{ 'dashboardDesigner.widgets' | translate }}</h3>
            @for (w of widgetTypes(); track w.type_id) {
              <button type="button" class="dd-tool" [attr.data-widget]="w.type_id" (click)="addWidget(w)">{{ w.display_name }}</button>
            }
          </nav>

          <div class="dd-main">
            <ng-template #node let-n>
              <span class="dd-type">{{ 'dashboardDesigner.types.' + n.type | translate }}</span>
              <span dir="auto">{{ n.props?.name ?? '' }}</span>
              @if (n.type === 'widget') { <span class="dd-type" dir="ltr">{{ n.props?.widget_type }}</span> }
            </ng-template>
            <xrm-canvas [doc]="doc" rootPath="/root" [nodeTemplate]="node" (changed)="onChanged($event)"
                        (save)="save()" (selectionChange)="onSelect($event)" />
          </div>

          <aside class="dd-panel" data-testid="dd-preview">
            <h3>{{ 'dashboardDesigner.preview' | translate }}</h3>
            <label>{{ 'dashboardDesigner.breakpoint' | translate }}
              <select [ngModel]="breakpoint()" (ngModelChange)="breakpoint.set($event)">
                <option value="desktop">{{ 'dashboardDesigner.desktop' | translate }}</option>
                <option value="tablet">{{ 'dashboardDesigner.tablet' | translate }}</option>
                <option value="phone">{{ 'dashboardDesigner.phone' | translate }}</option>
              </select>
            </label>
            <div [class]="'dd-grid dd-grid--' + breakpoint()" [style.--dd-cols]="columns()">
              @for (b of boxes(); track $index) {
                <div class="dd-box" data-testid="dd-box" [style.grid-column]="b.col + ' / span ' + b.span"
                     [style.grid-row]="'span ' + b.rowSpan">
                  <strong dir="auto">{{ b.name }}</strong>
                  <span class="dd-type" dir="ltr">{{ b.type }}</span>
                </div>
              } @empty {
                <p class="dd-muted">{{ 'dashboardDesigner.emptyPage' | translate }}</p>
              }
            </div>
          </aside>
        </div>
      } @else if (!error()) {
        <p class="dd-muted">{{ 'dashboardDesigner.loading' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .dd { display: grid; gap: .75rem; }
    .dd-head { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; }
    .dd-head h2 { margin: 0; }
    .dd-layout { display: grid; grid-template-columns: 12rem minmax(0, 1fr) minmax(16rem, 28rem); gap: .75rem; align-items: start; }
    @media (max-width: 64rem) { .dd-layout { grid-template-columns: minmax(0, 1fr); } }
    .dd-palette { display: grid; gap: .25rem; max-block-size: 40rem; overflow: auto; }
    .dd-palette h3, .dd-panel h3 { margin: 0; font-size: .875rem; }
    .dd-tool { text-align: start; }
    .dd-main { min-inline-size: 0; }
    .dd-type { font-family: ui-monospace, monospace; font-size: .75rem; color: var(--color-text-secondary, #666); }
    .dd-panel { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; }
    .dd-panel label { display: grid; gap: .25rem; font-size: .8125rem; }
    .dd-grid { display: grid; grid-template-columns: repeat(var(--dd-cols, 12), minmax(0, 1fr)); grid-auto-rows: 2rem; gap: .25rem; }
    .dd-grid--tablet { max-inline-size: 768px; }
    .dd-grid--phone { max-inline-size: 375px; }
    .dd-box { border: 1px solid var(--color-border, #ccc); border-radius: 6px; padding: .25rem .375rem; display: grid; align-content: start; overflow: hidden; font-size: .75rem; }
    .dd-error { color: var(--color-danger, #c53030); margin: 0; }
    .dd-muted { color: var(--color-text-secondary, #666); margin: 0; }
  `],
})
export class DashboardDesignerComponent {
  private readonly dashboards = inject(DashboardService);
  private readonly records = inject(EntityService);
  private readonly lang = inject(LangService);
  private readonly canvas = viewChild(CanvasComponent);

  /** The dashboard (route parameter). */
  readonly id = input.required<string>();

  readonly initial = signal<DDoc | null>(null);
  readonly current = signal<DDoc | null>(null);
  /** The tree as last loaded or saved: what a save is planned against. */
  readonly saved = signal<DDoc | null>(null);
  readonly name = signal('');
  readonly personal = signal(false);
  readonly widgetTypes = signal<readonly WidgetDescriptor[]>([]);
  readonly error = signal<string | null>(null);
  readonly saving = signal(false);
  readonly savedAt = signal<number | null>(null);
  readonly selectedPath = signal<string | null>(null);
  readonly breakpoint = signal<Breakpoint>('desktop');
  private refs = 0;

  readonly misplacedCount = computed(() => {
    const doc = this.current();
    return doc ? misplaced(doc) : 0;
  });
  readonly columns = computed(() => PREVIEW_COLUMNS[this.breakpoint()]);

  /** The page the preview shows: the one holding the selection, else the first. */
  readonly previewPage = computed<DNode | null>(() => {
    const doc = this.current();
    if (!doc) return null;
    const match = this.selectedPath()?.match(/^\/root\/children\/(\d+)/);
    const pages = doc.root.children ?? [];
    return pages[match ? Number(match[1]) : 0] ?? null;
  });
  readonly boxes = computed(() => previewBoxes(this.previewPage(), this.breakpoint()));

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
    this.dashboards.widgetTypes().subscribe({
      next: types => this.widgetTypes.set(types),
      error: () => this.widgetTypes.set([]),
    });
  }

  onChanged(doc: unknown): void {
    this.current.set(doc as DDoc);
  }

  onSelect(paths: string[]): void {
    this.selectedPath.set(paths.at(-1) ?? null);
  }

  addPage(): void {
    const doc = this.current();
    if (!doc) return;
    const length = (doc.root.children ?? []).length;
    const page: DNode = { type: 'page', ref: this.ref(), props: { name: this.lang.translate('dashboardDesigner.newPage') }, children: [] };
    this.exec({ op: 'add', path: '/root/children/-', value: page }, `/root/children/${length}`);
  }

  addSection(): void {
    const doc = this.current();
    if (!doc) return;
    const parent = this.containerPath(doc, ['section', 'page']) ?? this.lastPage(doc);
    if (!parent) {
      this.error.set(this.lang.translate('dashboardDesigner.needPage'));
      return;
    }
    const section: DNode = {
      type: 'section', ref: this.ref(),
      props: { name: this.lang.translate('dashboardDesigner.newSection'), section_type: 'container', layout_mode: 'grid' },
      children: [],
    };
    this.addInto(doc, parent, section);
  }

  addWidget(w: WidgetDescriptor): void {
    const doc = this.current();
    if (!doc) return;
    const parent = this.containerPath(doc, ['section']) ?? this.firstSection(doc);
    if (!parent) {
      this.error.set(this.lang.translate('dashboardDesigner.needSection'));
      return;
    }
    const widget: DNode = {
      type: 'widget', ref: this.ref(),
      props: { name: w.display_name, widget_type: w.type_id, grid_col: 1, grid_row: 1, grid_col_span: 4, grid_row_span: 2 },
    };
    this.addInto(doc, parent, widget);
  }

  /**
   * Writes the records the tree changed, one after another (creates first,
   * so a new widget's new section exists), then reloads the draft.
   */
  async save(): Promise<void> {
    const before = this.saved();
    const after = this.current();
    if (!before || !after || this.saving()) return;
    const plan = planSave(before, after);
    if (!plan.ops.length) return;
    this.saving.set(true);
    this.error.set(null);
    const created = new Map<string, string>();
    try {
      await lastValueFrom(from(plan.ops).pipe(concatMap(op => this.run(op, created)), toArray()));
      this.savedAt.set(Date.now());
      this.load(this.id());
    } catch (e) {
      const err = e as ApiError;
      this.error.set(err?.status === 409 || err?.status === 412
        ? this.lang.translate('dashboardDesigner.conflict')
        : this.lang.errorText(err));
    } finally {
      this.saving.set(false);
    }
  }

  private run(op: SaveOp, created: Map<string, string>): Observable<unknown> {
    switch (op.kind) {
      case 'create':
        return this.records.create(op.entity, { ...op.data, ...resolveLinks(op.links, created) }).pipe(
          map(rec => { created.set(op.ref, rec.id); return rec; }));
      case 'update':
        return this.records.update(op.entity, op.id, { ...op.patch, ...resolveLinks(op.links, created) }, op.rowVersion);
      case 'delete':
        return this.records.delete(op.entity, op.id);
    }
  }

  private ref(): string {
    this.refs += 1;
    return `new-${this.refs}`;
  }

  private exec(command: EditCommand, select?: string): void {
    this.canvas()?.exec(command, select);
  }

  private addInto(doc: DDoc, parent: string, node: DNode): void {
    const list = `${parent}/children`;
    const length = (valueAt(doc, list) as unknown[] | undefined)?.length ?? 0;
    this.exec({ op: 'add', path: `${list}/-`, value: node }, `${list}/${length}`);
  }

  /** The selected node, or its nearest ancestor, of one of `types`. */
  private containerPath(doc: DDoc, types: DNode['type'][]): string | null {
    let path = this.selectedPath();
    while (path && path.startsWith('/root/children/')) {
      const node = this.nodeAt(doc, path);
      if (node && types.includes(node.type)) return path;
      const cut = path.lastIndexOf('/children/');
      path = cut > 0 ? path.slice(0, cut) : null;
    }
    return null;
  }

  private lastPage(doc: DDoc): string | null {
    const n = (doc.root.children ?? []).length;
    return n ? `/root/children/${n - 1}` : null;
  }

  private firstSection(doc: DDoc): string | null {
    const pages = doc.root.children ?? [];
    for (let p = 0; p < pages.length; p++) {
      const sections = pages[p].children ?? [];
      const s = sections.findIndex(c => c.type === 'section');
      if (s >= 0) return `/root/children/${p}/children/${s}`;
    }
    return null;
  }

  private nodeAt(doc: DDoc, path: string): DNode | null {
    try {
      return valueAt(doc, path) as DNode;
    } catch {
      return null;
    }
  }

  private load(id: string): void {
    this.dashboards.loadTree(id).subscribe({
      next: tree => {
        const design = toDesign(tree);
        this.name.set(String(tree.dashboard.data['name'] ?? ''));
        this.personal.set(tree.dashboard.data['visibility'] === 'private');
        this.initial.set(design);
        this.current.set(design);
        this.saved.set(design);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
