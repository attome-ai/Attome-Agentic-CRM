import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_api::env_variable_admin::EnvVariable`. */
export interface EnvVariable {
  name: string;
  type: 'text' | 'number' | 'boolean' | 'url' | 'secret';
  required: boolean;
  default: unknown;
  description_en: string | null;
  description_ar: string | null;
  /** Always null for a secret. */
  value: unknown;
  is_set: boolean;
  updated_at: string | null;
  updated_by: string | null;
  row_version: number | null;
}

/** `attome_api::env_variable_admin::EnvVariableChange`. */
export interface EnvVariableChange {
  id: string;
  change: 'set' | 'cleared';
  value: unknown;
  is_secret: boolean;
  changed_by: string;
  changed_at: string;
}

/** A required variable with neither a value here nor a default. */
export function isMissing(v: EnvVariable): boolean {
  return v.required && !v.is_set && (v.default === null || v.default === undefined);
}

/** The value a draft holds, typed for the variable, or `undefined` when it does not parse. */
export function parseDraft(type: EnvVariable['type'], draft: string): unknown {
  switch (type) {
    case 'number': {
      const n = Number(draft);
      return draft.trim() !== '' && Number.isFinite(n) ? n : undefined;
    }
    case 'boolean':
      return draft === 'true' ? true : draft === 'false' ? false : undefined;
    case 'url':
      return /^https?:\/\//.test(draft.trim()) ? draft.trim() : undefined;
    default:
      return draft;
  }
}

/** How a value reads in the list. */
export function shown(v: EnvVariable): string {
  if (v.type === 'secret') return '';
  const value = v.is_set ? v.value : v.default;
  return value === null || value === undefined ? '' : String(value);
}

/**
 * Environment variables (roadmap A30-T3): the variables this deployment's
 * published metadata defines, with this deployment's own values. Set or
 * clear a value, see its history. A secret is write-only: the page shows
 * only whether it is set. Logical CSS only.
 */
@Component({
  selector: 'xrm-env-variables',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <section class="ev">
      <h3>{{ 'envVariablesPage.title' | translate }}</h3>
      <p class="ev-muted">{{ 'envVariablesPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="ev-error" role="alert">{{ message }}</p> }
      @if (variables().length === 0) {
        <p class="ev-muted">{{ 'envVariablesPage.none' | translate }}</p>
      } @else {
        <table class="ev-table">
          <thead>
            <tr>
              <th scope="col">{{ 'envVariablesPage.name' | translate }}</th>
              <th scope="col">{{ 'envVariablesPage.type' | translate }}</th>
              <th scope="col">{{ 'envVariablesPage.value' | translate }}</th>
              <th scope="col">{{ 'envVariablesPage.updated' | translate }}</th>
              <th scope="col"><span class="ev-sr">{{ 'envVariablesPage.actions' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (v of variables(); track v.name) {
              <tr [class.ev-missing]="missing(v)" [attr.data-variable]="v.name">
                <td dir="ltr">
                  <code>{{ v.name }}</code>
                  @if (v.required) { <span class="ev-badge">{{ 'envVariablesPage.required' | translate }}</span> }
                </td>
                <td>{{ 'envVariablesPage.types.' + v.type | translate }}</td>
                <td>
                  @if (editing() === v.name) {
                    @if (v.type === 'boolean') {
                      <select [(ngModel)]="draft" [attr.aria-label]="v.name">
                        <option value="true">{{ 'envVariablesPage.yes' | translate }}</option>
                        <option value="false">{{ 'envVariablesPage.no' | translate }}</option>
                      </select>
                    } @else {
                      <input [type]="v.type === 'secret' ? 'password' : 'text'" [(ngModel)]="draft"
                             [attr.aria-label]="v.name" autocomplete="off" dir="ltr" />
                    }
                  } @else if (v.type === 'secret') {
                    {{ (v.is_set ? 'envVariablesPage.secretSet' : 'envVariablesPage.notSet') | translate }}
                  } @else {
                    <span dir="ltr">{{ shown(v) }}</span>
                    @if (!v.is_set && v.default !== null) {
                      <span class="ev-muted">({{ 'envVariablesPage.default' | translate }})</span>
                    }
                  }
                  @if (missing(v)) {
                    <span class="ev-warn">{{ 'envVariablesPage.missing' | translate }}</span>
                  }
                </td>
                <td>{{ v.updated_at ? (v.updated_at | localDate) : '' }}</td>
                <td class="ev-actions">
                  @if (editing() === v.name) {
                    <button type="button" (click)="save(v)" [disabled]="busy()">{{ 'envVariablesPage.save' | translate }}</button>
                    <button type="button" (click)="editing.set(null)">{{ 'envVariablesPage.cancel' | translate }}</button>
                  } @else {
                    <button type="button" (click)="edit(v)">
                      {{ (v.type === 'secret' && v.is_set ? 'envVariablesPage.replace' : 'envVariablesPage.set') | translate }}
                    </button>
                    @if (v.is_set) {
                      <button type="button" (click)="clear(v)" [disabled]="busy()">{{ 'envVariablesPage.clear' | translate }}</button>
                    }
                    <button type="button" (click)="toggleHistory(v)">{{ 'envVariablesPage.history' | translate }}</button>
                  }
                </td>
              </tr>
              @if (historyOf() === v.name) {
                <tr class="ev-history"><td colspan="5">
                  @for (h of history(); track h.id) {
                    <div>
                      {{ h.changed_at | localDate }} ·
                      {{ 'envVariablesPage.changes.' + h.change | translate }}
                      @if (!h.is_secret && h.value !== null) { <code dir="ltr">{{ h.value }}</code> }
                    </div>
                  } @empty {
                    <div class="ev-muted">{{ 'envVariablesPage.noHistory' | translate }}</div>
                  }
                </td></tr>
              }
            }
          </tbody>
        </table>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .ev { display: flex; flex-direction: column; gap: 0.5rem; }
    .ev h3 { margin-block: 0; font-size: 1rem; }
    .ev-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .ev-table th, .ev-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .ev-missing td { background: color-mix(in srgb, var(--color-danger) 10%, transparent); }
    .ev-badge { margin-inline-start: 0.375rem; font-size: 0.75rem; color: var(--color-text-secondary); }
    .ev-warn { display: block; color: var(--color-danger); font-size: 0.75rem; }
    .ev-actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .ev-history td { background: var(--color-bg-alt); font-size: 0.8125rem; }
    .ev-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .ev-error { color: var(--color-danger); }
    .ev-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class EnvVariablesComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly variables = signal<EnvVariable[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly editing = signal<string | null>(null);
  readonly historyOf = signal<string | null>(null);
  readonly history = signal<EnvVariableChange[]>([]);
  draft = '';

  readonly missing = isMissing;
  readonly shown = shown;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: EnvVariable[] }>('/api/v1/admin/env-variables').subscribe({
      next: page => this.variables.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  edit(v: EnvVariable): void {
    this.error.set(null);
    this.draft = v.type === 'secret' ? '' : shown(v);
    this.editing.set(v.name);
  }

  save(v: EnvVariable): void {
    const value = parseDraft(v.type, this.draft);
    if (value === undefined) {
      this.error.set(`${v.name}: ${v.type}`);
      return;
    }
    this.busy.set(true);
    this.api.put<void>(`/api/v1/admin/env-variables/${encodeURIComponent(v.name)}`, {
      value, row_version: v.row_version,
    }).subscribe({
      next: () => { this.busy.set(false); this.editing.set(null); this.draft = ''; this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  clear(v: EnvVariable): void {
    this.busy.set(true);
    this.api.delete(`/api/v1/admin/env-variables/${encodeURIComponent(v.name)}`).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  toggleHistory(v: EnvVariable): void {
    if (this.historyOf() === v.name) {
      this.historyOf.set(null);
      return;
    }
    this.historyOf.set(v.name);
    this.history.set([]);
    this.api.get<{ items: EnvVariableChange[] }>(
      `/api/v1/admin/env-variables/${encodeURIComponent(v.name)}/history`,
    ).subscribe({
      next: page => this.history.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
