import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

import { newId } from '../agent-designer/agent-designer.component';
import { ModelService, ObjectSummary } from '../model.service';

/** A dependency document (`attome_model::kinds::dependency`). */
export interface DependencyDoc {
  entity: string;
  controlling: string;
  dependent: string;
  matrix: Record<string, string[]>;
  default?: string[];
}

/** What the impact route answers. */
export interface DependencyImpact {
  count: number;
  sample_ids: string[];
}

interface SchemaField { name: string; field_type: string; options?: { choices?: string[] } | null }

/** Whether `dependent` is allowed for `controlling` in `matrix`. Pure. */
export function isAllowed(matrix: Record<string, string[]>, controlling: string, dependent: string): boolean {
  return (matrix[controlling] ?? []).includes(dependent);
}

/** `matrix` with one cell turned on or off; an emptied row is dropped. Pure. */
export function toggleCell(
  matrix: Record<string, string[]>, controlling: string, dependent: string,
): Record<string, string[]> {
  const row = matrix[controlling] ?? [];
  const next = row.includes(dependent) ? row.filter(v => v !== dependent) : [...row, dependent];
  const out = { ...matrix };
  if (next.length) out[controlling] = next; else delete out[controlling];
  return out;
}

/**
 * A6-T4: the dependency editor. Pick an entity and its controlling and
 * dependent choice attributes, then tick which dependent values each
 * controlling value allows, in a grid or as a tree. Before publishing,
 * "Check records" counts the live records the draft would no longer allow.
 */
@Component({
  selector: 'xrm-dependency-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="dp">
      <aside class="dp-list">
        <h2>{{ 'dependencies.title' | translate }}</h2>
        <button type="button" class="btn btn-secondary" (click)="startNew()">{{ 'dependencies.new' | translate }}</button>
        <ul>
          @for (d of items(); track d.id) {
            <li><button type="button" class="btn btn-text" [class.dp-on]="d.id === id()" (click)="open(d)">{{ d.name }}</button></li>
          }
        </ul>
      </aside>
      @if (id()) {
        <div class="dp-main" data-testid="dependency-editor">
          <div class="dp-row">
            <label><span>{{ 'dependencies.name' | translate }}</span>
              <input dir="ltr" [ngModel]="name()" (ngModelChange)="name.set($event)" [disabled]="!isNew()" /></label>
            <label><span>{{ 'dependencies.entity' | translate }}</span>
              <input dir="ltr" [ngModel]="entity()" (ngModelChange)="entity.set($event)" (blur)="loadSchema()" /></label>
            <label><span>{{ 'dependencies.controlling' | translate }}</span>
              <select [ngModel]="controlling()" (ngModelChange)="controlling.set($event)">
                <option value=""></option>
                @for (f of choiceFields(); track f.name) { <option [value]="f.name">{{ f.name }}</option> }
              </select></label>
            <label><span>{{ 'dependencies.dependent' | translate }}</span>
              <select [ngModel]="dependent()" (ngModelChange)="dependent.set($event)">
                <option value=""></option>
                @for (f of choiceFields(); track f.name) { <option [value]="f.name">{{ f.name }}</option> }
              </select></label>
          </div>
          <div class="dp-row" role="tablist">
            <button type="button" role="tab" class="btn btn-text" [attr.aria-selected]="view() === 'matrix'" (click)="view.set('matrix')">{{ 'dependencies.matrix' | translate }}</button>
            <button type="button" role="tab" class="btn btn-text" [attr.aria-selected]="view() === 'tree'" (click)="view.set('tree')">{{ 'dependencies.tree' | translate }}</button>
          </div>
          @if (view() === 'matrix') {
            <table class="dp-grid" data-testid="dependency-matrix">
              <thead>
                <tr><th scope="col"></th>
                  @for (dv of dependentValues(); track dv) { <th scope="col">{{ dv }}</th> }
                </tr>
              </thead>
              <tbody>
                @for (cv of controllingValues(); track cv) {
                  <tr>
                    <th scope="row">{{ cv }}</th>
                    @for (dv of dependentValues(); track dv) {
                      <td><input type="checkbox" [checked]="allowed(cv, dv)" (change)="toggle(cv, dv)"
                                 [attr.aria-label]="cv + ' → ' + dv" [attr.data-cell]="cv + ':' + dv" /></td>
                    }
                  </tr>
                }
              </tbody>
            </table>
          } @else {
            <ul class="dp-tree" data-testid="dependency-tree">
              @for (cv of controllingValues(); track cv) {
                <li><strong>{{ cv }}</strong>
                  <ul>
                    @for (dv of matrix()[cv] ?? []; track dv) { <li>{{ dv }}</li> }
                    @if (!(matrix()[cv] ?? []).length) { <li class="dp-muted">{{ 'dependencies.anyValue' | translate }}</li> }
                  </ul>
                </li>
              }
            </ul>
          }
          <div class="dp-actions">
            <button type="button" class="btn btn-secondary" [disabled]="busy() || !ready()" (click)="save()">{{ 'dependencies.saveDraft' | translate }}</button>
            <button type="button" class="btn btn-text" [disabled]="busy() || !hash()" (click)="checkImpact()">{{ 'dependencies.checkRecords' | translate }}</button>
            <button type="button" class="btn btn-primary" [disabled]="busy() || !hash()" (click)="publish()">{{ 'dependencies.publish' | translate }}</button>
            @if (notice(); as n) { <span role="status">{{ n | translate }}</span> }
          </div>
          @if (impact(); as i) {
            <p class="dp-impact" role="status" data-testid="dependency-impact">
              {{ 'dependencies.impact' | translate: { count: i.count } }}
            </p>
          }
          @for (issue of issues(); track issue) { <p class="dp-error" role="alert">{{ issue }}</p> }
        </div>
      }
    </section>
  `,
  styles: [`
    .dp { display: flex; gap: 1.5rem; align-items: flex-start; }
    .dp-list { min-inline-size: 12rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .dp-list h2 { margin-block: 0; font-size: 1.25rem; }
    .dp-list ul { list-style: none; margin: 0; padding: 0; }
    .dp-on { font-weight: 600; }
    .dp-main { flex: 1; display: flex; flex-direction: column; gap: 0.75rem; overflow-x: auto; }
    .dp-row { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: end; }
    .dp-row label { display: grid; gap: 0.25rem; }
    .dp-grid { border-collapse: collapse; font-size: 0.875rem; }
    .dp-grid th, .dp-grid td { padding-block: 0.25rem; padding-inline: 0.375rem; text-align: center;
      border-block-end: 1px solid var(--color-border); }
    .dp-grid th[scope='row'] { text-align: start; }
    .dp-tree { margin: 0; padding-inline-start: 1rem; }
    .dp-muted { color: var(--color-text-secondary); }
    .dp-actions { display: flex; align-items: center; gap: 0.5rem; }
    .dp-impact { margin: 0; }
    .dp-error { color: var(--color-danger); margin: 0; }
  `],
})
export class DependencyEditorComponent implements OnInit {
  private readonly model = inject(ModelService);
  private readonly api = inject(ApiService);

  readonly items = signal<ObjectSummary[]>([]);
  readonly id = signal<string | null>(null);
  readonly isNew = signal(false);
  readonly name = signal('');
  readonly entity = signal('');
  readonly controlling = signal('');
  readonly dependent = signal('');
  readonly matrix = signal<Record<string, string[]>>({});
  readonly fields = signal<SchemaField[]>([]);
  readonly view = signal<'matrix' | 'tree'>('matrix');
  readonly hash = signal('');
  readonly busy = signal(false);
  readonly notice = signal<string | null>(null);
  readonly issues = signal<string[]>([]);
  readonly impact = signal<DependencyImpact | null>(null);

  readonly choiceFields = computed(() => this.fields().filter(f => f.field_type === 'choice'));
  private choicesOf(name: string): string[] {
    return this.fields().find(f => f.name === name)?.options?.choices ?? [];
  }
  readonly controllingValues = computed(() => {
    const listed = this.choicesOf(this.controlling());
    const extra = Object.keys(this.matrix()).filter(k => !listed.includes(k));
    return [...listed, ...extra];
  });
  readonly dependentValues = computed(() => this.choicesOf(this.dependent()));
  readonly ready = computed(() =>
    !!this.entity() && !!this.controlling() && !!this.dependent() && Object.keys(this.matrix()).length > 0);

  ngOnInit(): void {
    this.loadList();
  }

  private loadList(): void {
    this.model.objects('dependency', 1).subscribe({
      next: page => this.items.set(page.items),
      error: () => this.items.set([]),
    });
  }

  startNew(): void {
    this.id.set(newId());
    this.isNew.set(true);
    this.name.set('');
    this.entity.set('');
    this.controlling.set('');
    this.dependent.set('');
    this.matrix.set({});
    this.fields.set([]);
    this.hash.set('');
    this.issues.set([]);
    this.notice.set(null);
    this.impact.set(null);
  }

  open(item: ObjectSummary): void {
    this.model.object('dependency', item.id).subscribe({
      next: object => {
        const doc = (object.doc ?? {}) as Partial<DependencyDoc>;
        this.id.set(object.id);
        this.isNew.set(false);
        this.name.set(object.name);
        this.entity.set(doc.entity ?? '');
        this.controlling.set(doc.controlling ?? '');
        this.dependent.set(doc.dependent ?? '');
        this.matrix.set(doc.matrix ?? {});
        this.hash.set(object.content_hash);
        this.issues.set([]);
        this.notice.set(null);
        this.impact.set(null);
        this.loadSchema();
      },
      error: (e: ApiError) => this.issues.set([e.message]),
    });
  }

  loadSchema(): void {
    const entity = this.entity().trim();
    if (!entity) return;
    this.api.get<{ fields: SchemaField[] }>(`/api/v1/schema/${encodeURIComponent(entity)}`).subscribe({
      next: schema => this.fields.set(schema.fields ?? []),
      error: (e: ApiError) => { this.fields.set([]); this.issues.set([e.message]); },
    });
  }

  allowed(controlling: string, dependent: string): boolean {
    return isAllowed(this.matrix(), controlling, dependent);
  }

  toggle(controlling: string, dependent: string): void {
    this.matrix.update(m => toggleCell(m, controlling, dependent));
    this.impact.set(null);
  }

  save(): void {
    const id = this.id();
    if (!id || !this.ready()) return;
    this.busy.set(true);
    const commands = [
      { op: 'set' as const, path: '/entity', value: this.entity().trim() },
      { op: 'set' as const, path: '/controlling', value: this.controlling() },
      { op: 'set' as const, path: '/dependent', value: this.dependent() },
      { op: 'set' as const, path: '/matrix', value: this.matrix() },
    ];
    this.model.saveDraft('dependency', id, this.isNew() ? '' : this.hash(), this.isNew() ? this.name().trim() : null, commands)
      .subscribe({
        next: saved => {
          this.busy.set(false);
          this.isNew.set(false);
          this.hash.set(saved.content_hash);
          this.issues.set(saved.issues.map(i => `${i.path}: ${i.message}`));
          this.notice.set('dependencies.saved');
          this.loadList();
        },
        error: (e: ApiError) => { this.busy.set(false); this.issues.set([e.message]); },
      });
  }

  checkImpact(): void {
    const id = this.id();
    if (!id) return;
    this.api.get<DependencyImpact>(`/api/v1/admin/model/dependency/${encodeURIComponent(id)}/impact`).subscribe({
      next: impact => this.impact.set(impact),
      error: (e: ApiError) => this.issues.set([e.message]),
    });
  }

  publish(): void {
    const id = this.id();
    if (!id) return;
    this.busy.set(true);
    this.model.publish('dependency', id).subscribe({
      next: () => { this.busy.set(false); this.notice.set('dependencies.published'); },
      error: (e: ApiError) => { this.busy.set(false); this.issues.set([e.message]); },
    });
  }
}
