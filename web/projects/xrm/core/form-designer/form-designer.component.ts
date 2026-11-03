import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { CanvasComponent, valueAt } from '@attome/xrm/canvas';
import type { EditCommand } from '@attome/xrm/canvas';
import { AdminService } from '@attome/xrm/core/admin/data';
import type { AttributeMeta } from '@attome/xrm/core/admin/data';
import { FormRendererComponent, ModelService } from '@attome/xrm/model';
import type { FormPlan, ModelCommand } from '@attome/xrm/model';

import {
  DesignDoc, DesignNode, FormCheck, FormDoc, allSections, checkForm, fromDesign, previewFieldType, toDesign,
} from './form-doc';

type Device = 'desktop' | 'phone';

/**
 * A12-T3 — the form designer, at `/xrm/admin/forms/:id/design`: a form's
 * draft on the shared canvas (Y14-T1) as tabs, sections, fields and related
 * lists. Add a tab, a section, one of the entity's fields or a related list
 * into what is selected; drag to reorder or move between sections; the
 * property panel edits labels and columns. Beside it, the checks (every tab
 * and section labelled, every field still the entity's, nothing twice;
 * above 150 fields or 8 related lists, slow) and a preview through the form
 * renderer at a desktop or phone width, left to right or right to left.
 * Saving writes the draft (`POST /api/v1/admin/model/form/{id}/commands`)
 * against its content hash; publishing makes it the form people see.
 * `?entity=<id>` starts a new form for that entity.
 */
@Component({
  selector: 'xrm-form-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, CanvasComponent, FormRendererComponent],
  template: `
    <section class="fd" data-testid="form-designer">
      <header class="fd-head">
        <h2>{{ 'formDesigner.title' | translate }} <bdi>{{ name() }}</bdi></h2>
        <div class="fd-actions">
          @if (saved(); as v) { <span class="fd-muted" role="status">{{ 'formDesigner.saved' | translate: { version: v } }}</span> }
          <button type="button" data-testid="fd-publish" [disabled]="busy() || !hash()" (click)="publish()">{{ 'formDesigner.publish' | translate }}</button>
        </div>
      </header>
      @if (error(); as e) { <p class="fd-error" role="alert">{{ e }}</p> }

      @if (initial(); as doc) {
        <div class="fd-layout">
          <nav class="fd-palette" [attr.aria-label]="'formDesigner.palette' | translate">
            <h3>{{ 'formDesigner.layout' | translate }}</h3>
            <button type="button" class="fd-tool" data-add="tab" (click)="addTab()">{{ 'formDesigner.addTab' | translate }}</button>
            <button type="button" class="fd-tool" data-add="section" (click)="addSection()">{{ 'formDesigner.addSection' | translate }}</button>
            <h3>{{ 'formDesigner.fields' | translate }}</h3>
            @for (a of available(); track a.id) {
              <button type="button" class="fd-tool" [attr.data-field]="a.logicalname" (click)="addField(a)">{{ a.name }}</button>
            } @empty {
              <p class="fd-muted">{{ 'formDesigner.allPlaced' | translate }}</p>
            }
            <h3>{{ 'formDesigner.related' | translate }}</h3>
            <input dir="ltr" [attr.aria-label]="'formDesigner.relatedEntity' | translate" [ngModel]="relatedEntity()"
                   (ngModelChange)="relatedEntity.set($event)" data-testid="fd-related-entity" />
            <button type="button" class="fd-tool" data-add="related" [disabled]="!relatedEntity().trim()" (click)="addRelated()">
              {{ 'formDesigner.addRelated' | translate }}
            </button>
          </nav>

          <div class="fd-main">
            <ng-template #node let-n let-path="path">
              <span class="fd-type">{{ 'formDesigner.types.' + n.type | translate }}</span>
              <span dir="auto">{{ nodeLabel(n) }}</span>
            </ng-template>
            <xrm-canvas [doc]="doc" rootPath="/root" [nodeTemplate]="node" (changed)="onChanged($event)"
                        (save)="save()" (selectionChange)="onSelect($event)" />
          </div>

          <aside class="fd-side">
            <section class="fd-panel" data-testid="fd-checks">
              <h3>{{ 'formDesigner.checks' | translate }}</h3>
              @for (c of checks(); track $index) {
                <p [class]="'fd-check fd-check--' + c.kind" [attr.data-check]="c.key">{{ 'formDesigner.check.' + c.key | translate: c.args ?? {} }}</p>
              } @empty {
                <p class="fd-muted">{{ 'formDesigner.allGood' | translate }}</p>
              }
            </section>
            <section class="fd-panel">
              <h3>{{ 'formDesigner.preview' | translate }}</h3>
              <label>{{ 'formDesigner.size' | translate }}
                <select [ngModel]="device()" (ngModelChange)="device.set($event)">
                  <option value="desktop">{{ 'formDesigner.desktop' | translate }}</option>
                  <option value="phone">{{ 'formDesigner.phone' | translate }}</option>
                </select>
              </label>
              <label>{{ 'formDesigner.language' | translate }}
                <select [ngModel]="language()" (ngModelChange)="language.set($event)">
                  <option value="en">English</option>
                  <option value="ar">العربية</option>
                </select>
              </label>
              @if (previewPlan(); as plan) {
                <div [class]="'fd-preview fd-preview--' + device()" [attr.dir]="language() === 'ar' ? 'rtl' : 'ltr'"
                     [attr.lang]="language()" data-testid="fd-preview">
                  <xrm-form-renderer [previewPlan]="plan" />
                </div>
              }
            </section>
          </aside>
        </div>
      } @else if (!error()) {
        <p class="fd-muted">{{ 'formDesigner.loading' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .fd { display: grid; gap: .75rem; }
    .fd-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: .5rem; }
    .fd-head h2 { margin: 0; }
    .fd-actions { display: flex; gap: .5rem; align-items: center; }
    .fd-layout { display: grid; grid-template-columns: 12rem minmax(0, 1fr) minmax(16rem, 26rem); gap: .75rem; align-items: start; }
    @media (max-width: 64rem) { .fd-layout { grid-template-columns: minmax(0, 1fr); } }
    .fd-palette { display: grid; gap: .25rem; max-block-size: 40rem; overflow: auto; }
    .fd-palette h3, .fd-panel h3 { margin: 0; font-size: .875rem; }
    .fd-tool { text-align: start; }
    .fd-main, .fd-side { display: grid; gap: .75rem; min-inline-size: 0; }
    .fd-type { font-family: ui-monospace, monospace; font-size: .75rem; color: var(--color-text-secondary, #666); }
    .fd-panel { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; }
    .fd-panel label { display: grid; gap: .25rem; font-size: .8125rem; }
    .fd-check { margin: 0; font-size: .8125rem; }
    .fd-check--performance { color: var(--color-warning, #8a5a00); }
    .fd-check--accessibility, .fd-check--layout { color: var(--color-danger, #c53030); }
    .fd-error { color: var(--color-danger, #c53030); }
    .fd-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .fd-preview { border: 1px dashed var(--color-border, #ccc); border-radius: 8px; overflow: auto; max-block-size: 40rem; padding: .5rem; }
    .fd-preview--phone { max-inline-size: 375px; }
  `],
})
export class FormDesignerComponent {
  private readonly model = inject(ModelService);
  private readonly admin = inject(AdminService);
  private readonly lang = inject(LangService);
  private readonly canvas = viewChild(CanvasComponent);

  /** The form object (route parameter). */
  readonly id = input.required<string>();
  /** A new form's entity id (`?entity=`). */
  readonly entity = input<string | null>(null);

  readonly initial = signal<DesignDoc | null>(null);
  readonly current = signal<DesignDoc | null>(null);
  /** The stored document, for what the tree does not carry (entity, kind, targeting). */
  readonly base = signal<FormDoc | null>(null);
  readonly attributes = signal<readonly AttributeMeta[]>([]);
  readonly entityName = signal('');
  readonly name = signal('');
  readonly hash = signal('');
  readonly saved = signal<number | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly selectedPath = signal<string | null>(null);
  readonly relatedEntity = signal('');
  readonly device = signal<Device>('desktop');
  readonly language = signal<'en' | 'ar'>('en');

  private readonly attributeNames = computed(
    () => new Map(this.attributes().map(a => [a.id, a.name || a.logicalname] as const)));

  /** The form as the tree stands, and how many nodes are misplaced. */
  readonly draft = computed(() => {
    const design = this.current();
    const base = this.base();
    return design && base ? fromDesign(design, base) : null;
  });

  readonly checks = computed<FormCheck[]>(() => {
    const draft = this.draft();
    return draft ? checkForm(draft.doc, this.attributeNames(), draft.misplaced) : [];
  });

  /** The entity's fields not yet on the form. */
  readonly available = computed(() => {
    const placed = new Set(allSections(this.draft()?.doc ?? { entity: '' }).flatMap(s => s.fields ?? []));
    return this.attributes().filter(a => a.is_active !== false && !placed.has(a.id));
  });

  /** The draft as the form renderer draws it. */
  readonly previewPlan = computed<FormPlan | null>(() => {
    const draft = this.draft();
    const entity = this.entityName();
    if (!draft || !entity) return null;
    const byId = new Map(this.attributes().map(a => [a.id, a] as const));
    const section = (s: { label: string; columns?: number; fields?: string[] }) => ({
      label: s.label,
      columns: s.columns ?? 1,
      fields: (s.fields ?? []).flatMap(id => {
        const a = byId.get(id);
        return a ? [{
          attribute: a.logicalname, label: a.name || a.logicalname,
          field_type: previewFieldType(a.field_type), required: a.is_required,
        }] : [];
      }),
    });
    const doc = draft.doc;
    return {
      id: this.id(), name: this.name(), entity, form_kind: doc.form_kind ?? 'main',
      sections: allSections(doc).map(section),
      tabs: doc.tabs?.map(t => ({ label: t.label, sections: t.sections.length })),
    };
  });

  constructor() {
    effect(() => {
      const id = this.id();
      const entity = this.entity();
      untracked(() => this.load(id, entity));
    });
  }

  onChanged(doc: unknown): void {
    this.current.set(doc as DesignDoc);
  }

  onSelect(paths: string[]): void {
    this.selectedPath.set(paths.at(-1) ?? null);
  }

  nodeLabel(n: DesignNode): string {
    if (n.type === 'field') return this.attributeNames().get(n.attribute ?? '') ?? n.attribute ?? '';
    if (n.type === 'related') return `${String(n.props?.['label'] ?? '')} (${n.entity ?? ''})`;
    return String(n.props?.['label'] ?? '');
  }

  addTab(): void {
    const doc = this.current();
    if (!doc) return;
    const roots = doc.root.children ?? [];
    const label = this.lang.translate('formDesigner.newTab');
    if (roots.length && !roots.some(n => n.type === 'tab')) {
      // A form with sections becomes a tabbed one: its sections go into the first tab.
      this.exec({ op: 'set', path: '/root/children', value: [
        { type: 'tab', props: { label }, children: roots },
      ] }, '/root/children/0');
      return;
    }
    this.exec({ op: 'add', path: '/root/children/-', value: { type: 'tab', props: { label }, children: [] } },
      `/root/children/${roots.length}`);
  }

  addSection(): void {
    const doc = this.current();
    if (!doc) return;
    const list = this.sectionList();
    const length = (valueAt(doc, list) as unknown[]).length;
    const section: DesignNode = { type: 'section', props: { label: this.lang.translate('formDesigner.newSection'), columns: 1 }, children: [] };
    this.exec({ op: 'add', path: `${list}/-`, value: section }, `${list}/${length}`);
  }

  addField(a: AttributeMeta): void {
    this.addLeaf({ type: 'field', attribute: a.id });
  }

  addRelated(): void {
    const entity = this.relatedEntity().trim();
    if (!entity) return;
    this.addLeaf({ type: 'related', entity, props: { label: '' } });
    this.relatedEntity.set('');
  }

  /** Saves the draft: the tree written back as the form's tabs or sections. */
  save(): void {
    const draft = this.draft();
    const base = this.base();
    if (!draft || !base) return;
    this.busy.set(true);
    this.error.set(null);
    const isNew = !this.hash();
    const doc = draft.doc;
    const commands: ModelCommand[] = isNew
      ? Object.entries(doc).map(([k, v]) => ({ op: 'set' as const, path: `/${k}`, value: v }))
      : [
        ...(doc.tabs
          ? [{ op: 'set' as const, path: '/tabs', value: doc.tabs }]
          : [{ op: 'set' as const, path: '/sections', value: doc.sections ?? [] }]),
        ...(doc.tabs && base.sections ? [{ op: 'remove' as const, path: '/sections' }] : []),
        ...(!doc.tabs && base.tabs ? [{ op: 'remove' as const, path: '/tabs' }] : []),
      ];
    this.model.saveDraft('form', this.id(), this.hash(), isNew ? this.name() || 'form' : null, commands).subscribe({
      next: saved => {
        this.busy.set(false);
        this.hash.set(saved.content_hash);
        this.saved.set(saved.version_no);
        this.base.set(doc);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 409 ? this.lang.translate('formDesigner.conflict') : this.lang.errorText(e));
      },
    });
  }

  publish(): void {
    this.busy.set(true);
    this.error.set(null);
    this.model.publish('form', this.id()).subscribe({
      next: () => this.busy.set(false),
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  private exec(command: EditCommand, select?: string): void {
    this.canvas()?.exec(command, select);
  }

  /** Adds a field or related list into the selected section (or the one holding the selection, or the last). */
  private addLeaf(node: DesignNode): void {
    const doc = this.current();
    if (!doc) return;
    const section = this.sectionPath(doc);
    if (!section) {
      this.error.set(this.lang.translate('formDesigner.needSection'));
      return;
    }
    const list = `${section}/children`;
    const length = (valueAt(doc, list) as unknown[]).length;
    this.exec({ op: 'add', path: `${list}/-`, value: node }, `${list}/${length}`);
  }

  /** The section a new field goes into. */
  private sectionPath(doc: DesignDoc): string | null {
    let path = this.selectedPath();
    while (path && path !== '/root') {
      const node = this.nodeAt(doc, path);
      if (node?.type === 'section') return path;
      path = path.slice(0, path.lastIndexOf('/children/'));
    }
    const last = (nodes: DesignNode[] | undefined, at: string): string | null => {
      const list = nodes ?? [];
      for (let i = list.length - 1; i >= 0; i--) {
        const n = list[i];
        const here = `${at}/${i}`;
        if (n.type === 'section') return here;
        if (n.type === 'tab') {
          const inner = last(n.children, `${here}/children`);
          if (inner) return inner;
        }
      }
      return null;
    };
    return last(doc.root.children, '/root/children');
  }

  /** The list a new section goes into: the selected tab, the tab holding the selection, the last tab, or the form. */
  private sectionList(): string {
    const doc = this.current();
    const roots = doc?.root.children ?? [];
    if (!roots.some(n => n.type === 'tab')) return '/root/children';
    const selected = this.selectedPath();
    const match = selected?.match(/^\/root\/children\/(\d+)/);
    const index = match ? Number(match[1]) : roots.length - 1;
    return `/root/children/${index}/children`;
  }

  private nodeAt(doc: DesignDoc, path: string): DesignNode | null {
    try {
      return valueAt(doc, path) as DesignNode;
    } catch {
      return null;
    }
  }

  private load(id: string, entity: string | null): void {
    this.error.set(null);
    this.model.object('form', id).subscribe({
      next: v => {
        const doc = v.doc as FormDoc;
        this.name.set(v.name);
        this.hash.set(v.content_hash);
        this.start(doc);
      },
      error: (e: ApiError) => {
        if (e.status === 404 && entity) {
          // A new form for `entity`: one empty section; the first save creates it.
          this.hash.set('');
          this.start({ entity, form_kind: 'main', sections: [{ label: this.lang.translate('formDesigner.newSection'), fields: [] }] });
        } else {
          this.error.set(e.status === 404 ? this.lang.translate('formDesigner.noEntity') : this.lang.errorText(e));
        }
      },
    });
  }

  private start(doc: FormDoc): void {
    const design = toDesign(doc);
    this.base.set(doc);
    this.initial.set(design);
    this.current.set(design);
    this.admin.getEntity(doc.entity).subscribe({
      next: detail => {
        this.attributes.set(detail.attributes ?? []);
        this.entityName.set(detail.logicalname);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
