import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, ApiService, LangService, Page, TranslatePipe } from '@attome/base';
import type { PageDoc } from '@attome/xrm/core/page-runtime';

import { PortalSiteService } from './portal-site.service';

/** What a page offers to create (`root.props.create`): an entity and the fields asked for. */
export interface CreateTarget {
  entity: string;
  fields: string[];
}

/** One field as the portal describes it (`GET /{keyword}/api/v1/metadata/{entity}`). */
export interface PortalField {
  name: string;
  label: string | null;
  field_type: string;
  required: boolean;
  writable: boolean;
  lookup_entity: string | null;
  options: { choices?: string[] } | null;
}

interface PortalEntityView {
  entity: string;
  can_create: boolean;
  fields: PortalField[];
}

const NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** The create target a page's root asks for (`props.create`), if well formed. Pure. */
export function createOf(doc: PageDoc | null): CreateTarget | null {
  const create = doc?.root?.props?.['create'] as Partial<CreateTarget> | undefined;
  if (!create || typeof create !== 'object' || typeof create.entity !== 'string' || !NAME.test(create.entity)) return null;
  const fields = Array.isArray(create.fields) ? create.fields.filter((f): f is string => typeof f === 'string' && NAME.test(f)) : [];
  return fields.length ? { entity: create.entity, fields } : null;
}

/** The fields of `view` to ask for, in `wanted` order: writable ones only. Pure. */
export function formFields(view: PortalEntityView | null, wanted: readonly string[]): PortalField[] {
  if (!view?.can_create) return [];
  return wanted
    .map(name => view.fields.find(f => f.name === name))
    .filter((f): f is PortalField => !!f && f.writable);
}

/** A form value as the record API takes it: numbers as numbers, empty as absent. Pure. */
export function valueFor(field: PortalField, raw: string): unknown {
  const text = raw.trim();
  if (!text) return undefined;
  if (['number', 'decimal', 'currency', 'integer'].includes(field.field_type)) {
    const n = Number(text);
    return Number.isFinite(n) ? n : text;
  }
  if (field.field_type === 'bool' || field.field_type === 'boolean') return text === 'true';
  return text;
}

/**
 * AC11-T2 — a portal page's create form: the page's root
 * names an entity and the fields to ask for (`props.create`), and the form
 * shows those the portal user's plan lets them write, as the portal's own
 * metadata describes them (choices as a list, a lookup as the records of its
 * target the user can read). It creates the record through the portal's
 * record API, which checks every value against the plan.
 */
@Component({
  selector: 'xrm-portal-create-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (fields().length) {
      <form class="pcf" (submit)="$event.preventDefault(); save()" data-testid="portal-create">
        <h2>{{ 'portalSite.create' | translate }}</h2>
        @for (f of fields(); track f.name) {
          <label [for]="'pcf-' + f.name">{{ f.label || f.name }}@if (f.required) { * }</label>
          @if (f.options?.choices?.length) {
            <select [id]="'pcf-' + f.name" (change)="set(f.name, $any($event.target).value)">
              <option value=""></option>
              @for (c of f.options!.choices!; track c) { <option [value]="c">{{ c }}</option> }
            </select>
          } @else if (f.lookup_entity) {
            <select [id]="'pcf-' + f.name" (change)="set(f.name, $any($event.target).value)">
              <option value=""></option>
              @for (o of choices()[f.name] ?? []; track o.id) { <option [value]="o.id">{{ o.label }}</option> }
            </select>
          } @else {
            <input [id]="'pcf-' + f.name" dir="auto" [attr.type]="inputType(f)"
                   [value]="values()[f.name] ?? ''" (input)="set(f.name, $any($event.target).value)" />
          }
        }
        <button type="submit" [disabled]="busy() || !ready()" data-create>{{ 'portalSite.submit' | translate }}</button>
        @if (done()) { <p role="status">{{ 'portalSite.created' | translate }}</p> }
        @if (error(); as message) { <p role="alert" class="pcf-error">{{ message }}</p> }
      </form>
    }
  `,
  styles: [`
    .pcf { display: grid; gap: .5rem; max-inline-size: 36rem; margin-block-start: 1rem; }
    .pcf button { justify-self: start; }
    .pcf-error { color: var(--color-danger, #c53030); }
  `],
})
export class PortalCreateFormComponent {
  private readonly api = inject(ApiService);
  private readonly site = inject(PortalSiteService);
  private readonly lang = inject(LangService);

  readonly target = input.required<CreateTarget>();
  /** After a record is created, so the page can show it. */
  readonly created = output<void>();

  readonly view = signal<PortalEntityView | null>(null);
  readonly fields = computed(() => formFields(this.view(), this.target().fields));
  readonly values = signal<Record<string, string>>({});
  readonly choices = signal<Record<string, { id: string; label: string }[]>>({});
  readonly ready = computed(() => this.fields().every(f => !f.required || (this.values()[f.name] ?? '').trim() !== ''));
  readonly busy = signal(false);
  readonly done = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const target = this.target();
      const keyword = this.site.keyword();
      untracked(() => {
        if (keyword) this.load(keyword, target.entity);
      });
    });
  }

  private base(keyword: string): string {
    return `/${encodeURIComponent(keyword)}/api/v1`;
  }

  private load(keyword: string, entity: string): void {
    this.api.get<PortalEntityView>(`${this.base(keyword)}/metadata/${encodeURIComponent(entity)}`).subscribe({
      next: view => {
        this.view.set(view);
        for (const f of formFields(view, this.target().fields)) {
          if (f.lookup_entity) this.loadChoices(keyword, f);
        }
      },
      // Not the user's to create here: the form stays away.
      error: () => this.view.set(null),
    });
  }

  private loadChoices(keyword: string, field: PortalField): void {
    this.api
      .get<Page<{ id: string; data: Record<string, unknown> }>>(
        `${this.base(keyword)}/records/${encodeURIComponent(field.lookup_entity ?? '')}`, { page: '1', page_size: '50' })
      .subscribe({
        next: page => this.choices.update(c => ({
          ...c,
          [field.name]: page.items.map(r => ({
            id: r.id,
            label: String(r.data['name'] ?? r.data['full_name'] ?? r.data['title'] ?? r.id),
          })),
        })),
        error: () => undefined,
      });
  }

  inputType(field: PortalField): string {
    if (['number', 'decimal', 'currency', 'integer'].includes(field.field_type)) return 'number';
    if (field.field_type === 'date' || field.field_type === 'date_time') return 'date';
    return 'text';
  }

  set(name: string, value: string): void {
    this.values.update(v => ({ ...v, [name]: value }));
    this.done.set(false);
  }

  save(): void {
    const keyword = this.site.keyword();
    if (!keyword || !this.ready()) return;
    const body: Record<string, unknown> = {};
    for (const f of this.fields()) {
      const value = valueFor(f, this.values()[f.name] ?? '');
      if (value !== undefined) body[f.name] = value;
    }
    this.busy.set(true);
    this.error.set(null);
    this.site.create(keyword, this.target().entity, body).subscribe({
      next: () => {
        this.busy.set(false);
        this.done.set(true);
        this.values.set({});
        this.created.emit();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
