import { ChangeDetectionStrategy, Component, OnInit, inject, input, output, signal } from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { AdminService, type EntityMeta } from '@attome/xrm/core/admin/data';

import {
  type CustomerTest, ERROR_KINDS, type ExpectRow, type GivenRow, STEP_OPS, type TestDraft,
  type ValueRow, type WhenRow, fromTest, toDefinition,
} from './customer-test.model';

/**
 * The customer test editor (roadmap Z15-T15): a name, the role the steps
 * run as, and three lists of rows — Given (records to start from), When
 * (writes under test) and Expect (an attribute's value afterwards, or an
 * error a step met). Entity and attribute pickers read the metadata API.
 * Saving creates the test, or changes it under `If-Match`.
 */
@Component({
  selector: 'xrm-customer-test-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, NgTemplateOutlet, TranslatePipe],
  template: `
    <form class="cte" (ngSubmit)="save()">
      @if (error(); as message) { <p class="cte-error" role="alert">{{ message }}</p> }
      <div class="cte-head">
        <label>{{ 'customerTestsPage.name' | translate }}
          <input name="name" [(ngModel)]="draft.name" required maxlength="200" />
        </label>
        <label>{{ 'customerTestsPage.asRole' | translate }}
          <input name="asRole" [(ngModel)]="draft.asRole" />
        </label>
        <label class="cte-check">
          <input type="checkbox" name="blocking" [(ngModel)]="draft.blocking" />
          {{ 'customerTestsPage.blocking' | translate }}
        </label>
        <label class="cte-wide">{{ 'customerTestsPage.description' | translate }}
          <input name="description" [(ngModel)]="draft.description" />
        </label>
      </div>

      <fieldset class="cte-section">
        <legend>{{ 'customerTestsPage.given' | translate }}</legend>
        @for (row of draft.given; track $index; let i = $index) {
          <div class="cte-row" data-section="given">
            <select [name]="'given-entity-' + i" [(ngModel)]="row.entity" (ngModelChange)="loadAttributes($event)"
                    [attr.aria-label]="'customerTestsPage.entity' | translate">
              <option value="">{{ 'customerTestsPage.pickEntity' | translate }}</option>
              @for (e of entities(); track e.id) { <option [value]="e.logicalname">{{ e.name }}</option> }
            </select>
            <input [name]="'given-ref-' + i" [(ngModel)]="row.ref" dir="ltr"
                   [attr.aria-label]="'customerTestsPage.ref' | translate"
                   [placeholder]="'customerTestsPage.ref' | translate" />
            <ng-container *ngTemplateOutlet="values; context: { $implicit: row.values, entity: row.entity, key: 'given-' + i }" />
            <button type="button" (click)="draft.given.splice(i, 1)">{{ 'customerTestsPage.remove' | translate }}</button>
          </div>
        }
        <button type="button" class="cte-add" (click)="addGiven()">{{ 'customerTestsPage.addGiven' | translate }}</button>
      </fieldset>

      <fieldset class="cte-section">
        <legend>{{ 'customerTestsPage.when' | translate }}</legend>
        @for (row of draft.when; track $index; let i = $index) {
          <div class="cte-row" data-section="when">
            <select [name]="'when-op-' + i" [(ngModel)]="row.op" [attr.aria-label]="'customerTestsPage.op' | translate">
              @for (op of ops; track op) { <option [value]="op">{{ 'customerTestsPage.ops.' + op | translate }}</option> }
            </select>
            <select [name]="'when-entity-' + i" [(ngModel)]="row.entity" (ngModelChange)="loadAttributes($event)"
                    [attr.aria-label]="'customerTestsPage.entity' | translate">
              <option value="">{{ 'customerTestsPage.pickEntity' | translate }}</option>
              @for (e of entities(); track e.id) { <option [value]="e.logicalname">{{ e.name }}</option> }
            </select>
            <input [name]="'when-ref-' + i" [(ngModel)]="row.ref" dir="ltr"
                   [attr.aria-label]="'customerTestsPage.ref' | translate"
                   [placeholder]="'customerTestsPage.ref' | translate" />
            @if (row.op !== 'delete') {
              <ng-container *ngTemplateOutlet="values; context: { $implicit: row.values, entity: row.entity, key: 'when-' + i }" />
            }
            <button type="button" (click)="draft.when.splice(i, 1)">{{ 'customerTestsPage.remove' | translate }}</button>
          </div>
        }
        <button type="button" class="cte-add" (click)="addWhen()">{{ 'customerTestsPage.addWhen' | translate }}</button>
      </fieldset>

      <fieldset class="cte-section">
        <legend>{{ 'customerTestsPage.expect' | translate }}</legend>
        @for (row of draft.expect; track $index; let i = $index) {
          <div class="cte-row" data-section="expect">
            <select [name]="'expect-kind-' + i" [(ngModel)]="row.kind" [attr.aria-label]="'customerTestsPage.kind' | translate">
              <option value="value">{{ 'customerTestsPage.kinds.value' | translate }}</option>
              <option value="error">{{ 'customerTestsPage.kinds.error' | translate }}</option>
            </select>
            @if (row.kind === 'error') {
              <select [name]="'expect-error-' + i" [(ngModel)]="row.error" [attr.aria-label]="'customerTestsPage.kinds.error' | translate">
                @for (k of errorKinds; track k) { <option [value]="k">{{ 'customerTestsPage.errors.' + k | translate }}</option> }
              </select>
            } @else {
              <select [name]="'expect-entity-' + i" [(ngModel)]="row.entity" (ngModelChange)="loadAttributes($event)"
                      [attr.aria-label]="'customerTestsPage.entity' | translate">
                <option value="">{{ 'customerTestsPage.pickEntity' | translate }}</option>
                @for (e of entities(); track e.id) { <option [value]="e.logicalname">{{ e.name }}</option> }
              </select>
              <input [name]="'expect-ref-' + i" [(ngModel)]="row.ref" dir="ltr"
                     [attr.aria-label]="'customerTestsPage.ref' | translate"
                     [placeholder]="'customerTestsPage.ref' | translate" />
              <select [name]="'expect-attribute-' + i" [(ngModel)]="row.attribute"
                      [attr.aria-label]="'customerTestsPage.attribute' | translate">
                <option value="">{{ 'customerTestsPage.pickAttribute' | translate }}</option>
                @for (a of attributesOf(row.entity); track a) { <option [value]="a">{{ a }}</option> }
              </select>
              <input [name]="'expect-equals-' + i" [(ngModel)]="row.equals" dir="auto"
                     [attr.aria-label]="'customerTestsPage.equals' | translate"
                     [placeholder]="'customerTestsPage.equals' | translate" />
            }
            <button type="button" (click)="draft.expect.splice(i, 1)">{{ 'customerTestsPage.remove' | translate }}</button>
          </div>
        }
        <button type="button" class="cte-add" (click)="addExpect()">{{ 'customerTestsPage.addExpect' | translate }}</button>
      </fieldset>

      <ng-template #values let-rows let-entity="entity" let-key="key">
        <div class="cte-values">
          @for (v of asValues(rows); track $index; let j = $index) {
            <span class="cte-value">
              <select [name]="key + '-attr-' + j" [(ngModel)]="v.attribute"
                      [attr.aria-label]="'customerTestsPage.attribute' | translate">
                <option value="">{{ 'customerTestsPage.pickAttribute' | translate }}</option>
                @for (a of attributesOf(entity); track a) { <option [value]="a">{{ a }}</option> }
              </select>
              <input [name]="key + '-value-' + j" [(ngModel)]="v.value" dir="auto"
                     [attr.aria-label]="'customerTestsPage.value' | translate"
                     [placeholder]="'customerTestsPage.value' | translate" />
              <button type="button" (click)="asValues(rows).splice(j, 1)"
                      [attr.aria-label]="'customerTestsPage.remove' | translate"><i class="la la-times" aria-hidden="true"></i></button>
            </span>
          }
          <button type="button" (click)="asValues(rows).push({ attribute: '', value: '' })">
            {{ 'customerTestsPage.addValue' | translate }}
          </button>
        </div>
      </ng-template>

      <div class="cte-actions">
        <button type="submit" [disabled]="busy() || !draft.name.trim()">{{ 'customerTestsPage.save' | translate }}</button>
        <button type="button" (click)="cancelled.emit()">{{ 'customerTestsPage.cancel' | translate }}</button>
      </div>
    </form>
  `,
  styles: [`
    :host { display: block; }
    .cte { display: flex; flex-direction: column; gap: 0.75rem; }
    .cte-head { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; align-items: end; }
    .cte-head label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; }
    .cte-head .cte-check { flex-direction: row; align-items: center; }
    .cte-wide { flex: 1 1 100%; }
    .cte-section { border: 1px solid var(--color-border); border-radius: 4px; padding-block: 0.5rem; padding-inline: 0.75rem; }
    .cte-section legend { font-weight: 600; padding-inline: 0.25rem; }
    .cte-row { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: start; padding-block: 0.375rem;
      border-block-end: 1px dashed var(--color-border); }
    .cte-values { display: flex; flex-wrap: wrap; gap: 0.25rem; align-items: center; }
    .cte-value { display: inline-flex; gap: 0.125rem; }
    .cte-add { margin-block-start: 0.375rem; }
    .cte-actions { display: flex; gap: 0.5rem; }
    .cte-error { color: var(--color-danger); }
  `],
})
export class CustomerTestEditorComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly admin = inject(AdminService);

  /** The test to change, or none to write a new one. */
  readonly test = input<CustomerTest | null>(null);
  readonly saved = output<CustomerTest>();
  readonly cancelled = output<void>();

  readonly entities = signal<EntityMeta[]>([]);
  readonly attributes = signal<Record<string, string[]>>({});
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly ops = STEP_OPS;
  readonly errorKinds = ERROR_KINDS;
  draft: TestDraft = fromTest(null);

  ngOnInit(): void {
    this.draft = fromTest(this.test());
    this.admin.listEntities().subscribe({
      next: entities => {
        this.entities.set(entities);
        const used = [...this.draft.given, ...this.draft.when, ...this.draft.expect].map(r => r.entity);
        for (const name of new Set(used)) this.loadAttributes(name);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** The template's value rows (typed for the shared `values` template). */
  asValues(rows: unknown): ValueRow[] {
    return rows as ValueRow[];
  }

  attributesOf(entity: string): string[] {
    return this.attributes()[entity] ?? [];
  }

  loadAttributes(logicalname: string): void {
    if (!logicalname || this.attributes()[logicalname]) return;
    const entity = this.entities().find(e => e.logicalname === logicalname);
    if (!entity) return;
    this.admin.getEntity(entity.id).subscribe({
      next: detail => this.attributes.update(all => ({
        ...all,
        [logicalname]: detail.attributes.map(a => a.logicalname).sort(),
      })),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  addGiven(): void {
    const row: GivenRow = { entity: '', ref: `r${this.draft.given.length + 1}`, values: [] };
    this.draft.given.push(row);
  }

  addWhen(): void {
    const row: WhenRow = { op: 'update', entity: '', ref: '', values: [] };
    this.draft.when.push(row);
  }

  addExpect(): void {
    const row: ExpectRow = { kind: 'value', entity: '', ref: '', attribute: '', equals: '', error: 'validation' };
    this.draft.expect.push(row);
  }

  save(): void {
    const existing = this.test();
    const body = {
      name: this.draft.name.trim(),
      description: this.draft.description.trim() || null,
      blocking: this.draft.blocking,
      definition: toDefinition(this.draft),
    };
    this.busy.set(true);
    this.error.set(null);
    const request = existing
      ? this.api.patch<CustomerTest>(`/api/v1/admin/customer-tests/${existing.id}`, body, existing.row_version)
      : this.api.post<CustomerTest>('/api/v1/admin/customer-tests', body);
    request.subscribe({
      next: test => { this.busy.set(false); this.saved.emit(test); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
