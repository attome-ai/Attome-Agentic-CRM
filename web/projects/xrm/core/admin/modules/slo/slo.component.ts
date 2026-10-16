import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

/** `attome_api::slo_admin::SloTargets`. */
export interface SloTargets {
  p50_ms: number | null;
  p95_ms: number | null;
  p99_ms: number | null;
}

/** `attome_api::slo_admin::SloOverride`. */
export interface SloOverride {
  p95_ms: number;
  p99_ms: number;
  row_version: number;
  updated_by: string;
  updated_at: string;
}

/** `attome_api::slo_admin::SloClassStatus`. */
export interface SloClass {
  id: string;
  name_en: string;
  name_ar: string;
  kind: string;
  status: 'ok' | 'at_risk' | 'exhausted' | 'unmeasured';
  target: SloTargets | null;
  override: SloOverride | null;
  budget_remaining: number | null;
  error_ratio_30d: number | null;
}

/** The budget left as a whole percentage, clamped at zero, or null. */
export function budgetPercent(c: SloClass): number | null {
  if (c.budget_remaining === null) return null;
  return Math.max(0, Math.round(c.budget_remaining * 100));
}

/** The targets in force: the deployment's own, else the reference. */
export function effectiveTargets(c: SloClass): { p95: number | null; p99: number | null } {
  if (c.override) return { p95: c.override.p95_ms, p99: c.override.p99_ms };
  return { p95: c.target?.p95_ms ?? null, p99: c.target?.p99_ms ?? null };
}

/**
 * Service levels (roadmap AA13-T11): each class with its status label, the
 * share of its 30-day error budget left and its latency targets; an
 * administrator sets the deployment's own targets (within half to three
 * times the reference) or goes back to the reference. Readable on a phone:
 * one card per class. Logical CSS only.
 */
@Component({
  selector: 'xrm-slo',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="slo">
      <h3>{{ 'sloPage.title' | translate }}</h3>
      <p class="slo-muted">{{ 'sloPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="slo-error" role="alert">{{ message }}</p> }
      <div class="slo-grid">
        @for (c of classes(); track c.id) {
          <article class="slo-card" [attr.data-class]="c.id" [attr.data-status]="c.status">
            <header>
              <strong>{{ name(c) }}</strong>
              <span class="slo-status slo-status--{{ c.status }}">{{ 'sloPage.status.' + c.status | translate }}</span>
            </header>
            @let left = budget(c);
            @if (left !== null) {
              <div class="slo-bar" role="meter" [attr.aria-valuenow]="left" aria-valuemin="0" aria-valuemax="100"
                   [attr.aria-label]="'sloPage.budget' | translate">
                <span [style.inline-size.%]="left"></span>
              </div>
              <small>{{ 'sloPage.budgetLeft' | translate: { percent: left } }}</small>
            }
            @if (targets(c); as t) {
              @if (t.p95 !== null) {
                <small dir="ltr">p95 {{ t.p95 }} ms · p99 {{ t.p99 ?? '—' }} ms</small>
              }
            }
            @if (c.target && c.target.p95_ms !== null) {
              @if (editing() === c.id) {
                <div class="slo-edit">
                  <label>p95 <input type="number" min="1" [(ngModel)]="p95" dir="ltr" /></label>
                  <label>p99 <input type="number" min="1" [(ngModel)]="p99" dir="ltr" /></label>
                  <button type="button" (click)="save(c)" [disabled]="busy()">{{ 'sloPage.save' | translate }}</button>
                  <button type="button" (click)="editing.set(null)">{{ 'sloPage.cancel' | translate }}</button>
                </div>
              } @else {
                <div class="slo-actions">
                  <button type="button" (click)="edit(c)">{{ 'sloPage.setTarget' | translate }}</button>
                  @if (c.override) {
                    <button type="button" (click)="reset(c)" [disabled]="busy()">{{ 'sloPage.useReference' | translate }}</button>
                  }
                </div>
              }
            }
          </article>
        }
      </div>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .slo { display: flex; flex-direction: column; gap: 0.75rem; }
    .slo h3 { margin-block: 0; font-size: 1rem; }
    .slo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); gap: 0.75rem; }
    .slo-card { display: flex; flex-direction: column; gap: 0.375rem; padding: 0.75rem;
      border: 1px solid var(--color-border); border-radius: 6px; background: var(--color-surface); }
    .slo-card header { display: flex; justify-content: space-between; gap: 0.5rem; align-items: baseline; }
    .slo-status { font-size: 0.75rem; padding-inline: 0.375rem; border-radius: 999px; background: var(--color-bg-alt); }
    .slo-status--at_risk { color: var(--color-warning); }
    .slo-status--exhausted { color: var(--color-danger); }
    .slo-bar { block-size: 0.375rem; background: var(--color-bg-alt); border-radius: 999px; overflow: hidden; }
    .slo-bar span { display: block; block-size: 100%; background: var(--color-accent); }
    .slo-edit, .slo-actions { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: center; }
    .slo-edit input { inline-size: 5rem; }
    .slo-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .slo-error { color: var(--color-danger); }
  `],
})
export class SloComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly classes = signal<SloClass[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly editing = signal<string | null>(null);
  p95: number | null = null;
  p99: number | null = null;

  readonly budget = budgetPercent;
  readonly targets = effectiveTargets;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ classes: SloClass[] }>('/api/v1/admin/slo').subscribe({
      next: body => this.classes.set(body.classes),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  name(c: SloClass): string {
    return this.lang.current() === 'ar' ? c.name_ar : c.name_en;
  }

  edit(c: SloClass): void {
    const t = effectiveTargets(c);
    this.p95 = t.p95;
    this.p99 = t.p99;
    this.error.set(null);
    this.editing.set(c.id);
  }

  save(c: SloClass): void {
    this.busy.set(true);
    this.api.put<SloOverride>(`/api/v1/admin/slo/targets/${encodeURIComponent(c.id)}`, {
      p95_ms: this.p95, p99_ms: this.p99, row_version: c.override?.row_version ?? null,
    }).subscribe({
      next: () => { this.busy.set(false); this.editing.set(null); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  reset(c: SloClass): void {
    this.busy.set(true);
    this.api.delete(`/api/v1/admin/slo/targets/${encodeURIComponent(c.id)}`).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
