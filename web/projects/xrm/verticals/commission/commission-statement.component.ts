import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';

/** One explanation step: a catalogue key under `commission.` and its values. */
export interface StatementStep {
  key: string;
  values: Record<string, string>;
}

/** `attome_commission::statement::CommissionStatementRow`. */
export interface StatementRow {
  id: string;
  /** `line`, `adjustment` or `clawback`. */
  kind: string;
  participant_id: string | null;
  run_id: string | null;
  component_id: string | null;
  credit_id: string | null;
  /** Absent when the reader may not see pay amounts. */
  amount: string | null;
  /** A line's steps; an adjustment's reason. */
  explanation: StatementStep[] | string | null;
}

interface Period {
  id: string;
  name: string;
  startsOn: string;
  endsOn: string;
}

/**
 * My commission statement (roadmap F10-T15): pick a period and see each
 * statement line, adjustment and clawback with how it was worked out. A
 * line's explanation is the engine's own steps (rate, tier, gate, cap),
 * shown from the catalogue so it reads in Arabic too; the server decides
 * which rows and amounts the reader sees. Periods show in the reader's
 * calendar (Gregorian, Hijri or both) and the page runs right to left in
 * Arabic.
 */
@Component({
  selector: 'xrm-commission-statement',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, LocalNumberPipe, TranslatePipe],
  template: `
    <section class="cs" [attr.dir]="dir()" aria-labelledby="cs-title">
      <h2 id="cs-title">{{ 'commission.statement.title' | translate }}</h2>
      @if (periods().length) {
        <label class="cs-period">
          <span>{{ 'commission.statement.period' | translate }}</span>
          <select [value]="periodId() ?? ''" (change)="choose($any($event.target).value)">
            @for (p of periods(); track p.id) {
              <option [value]="p.id" [attr.data-period]="p.id">
                {{ p.name }} · {{ p.startsOn | localDate: { dateStyle: 'medium' } }} – {{ p.endsOn | localDate: { dateStyle: 'medium' } }}
              </option>
            }
          </select>
        </label>
      } @else {
        <p class="cs-muted">{{ 'commission.statement.noPeriods' | translate }}</p>
      }
      @if (error(); as message) { <p class="cs-error" role="alert">{{ message }}</p> }
      @if (rows().length) {
        <ul class="cs-rows">
          @for (r of rows(); track r.id) {
            <li class="cs-row" [attr.data-row]="r.id">
              <div class="cs-head">
                <span class="cs-kind">{{ 'commission.statement.kind.' + r.kind | translate }}</span>
                <strong>
                  @if (r.amount !== null) { {{ +r.amount | localNumber }} } @else { {{ 'commission.statement.hidden' | translate }} }
                </strong>
              </div>
              @if (steps(r); as list) {
                @if (list.length) {
                  <details>
                    <summary>{{ 'commission.statement.how' | translate }}</summary>
                    <ol>
                      @for (s of list; track $index) {
                        <li data-step>{{ s.key | translate: s.values }}</li>
                      }
                    </ol>
                  </details>
                }
              }
              @if (note(r); as text) { <p class="cs-note">{{ text }}</p> }
            </li>
          }
        </ul>
      } @else if (periodId() && !loading()) {
        <p class="cs-muted">{{ 'commission.statement.empty' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .cs { display: flex; flex-direction: column; gap: 0.75rem; padding-block: 1rem; padding-inline: 1rem; }
    .cs h2 { margin-block: 0; font-size: 1.125rem; }
    .cs-period { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .cs-rows { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .cs-row { padding-block: 0.5rem; padding-inline: 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .cs-head { display: flex; justify-content: space-between; gap: 0.5rem; }
    .cs-kind { color: var(--color-text-secondary); }
    .cs-row ol { margin-block: 0.375rem 0; padding-inline-start: 1.25rem; }
    .cs-note { margin-block: 0.25rem 0; color: var(--color-text-secondary); }
    .cs-muted { color: var(--color-text-secondary); margin: 0; }
    .cs-error { color: var(--color-danger); margin: 0; }
  `],
})
export class CommissionStatementComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly periods = signal<Period[]>([]);
  readonly periodId = signal<string | null>(null);
  readonly rows = signal<StatementRow[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));

  constructor() {
    this.entities.list('comp_period', {
      sorts: [{ field: 'starts_on', dir: 'desc' }],
      limit: 24,
    }).subscribe({
      next: page => {
        const periods = page.data.map(r => ({
          id: r.id,
          name: String(r.data['fiscal_period'] ?? ''),
          startsOn: String(r.data['starts_on'] ?? ''),
          endsOn: String(r.data['ends_on'] ?? ''),
        }));
        this.periods.set(periods);
        const today = new Date().toISOString().slice(0, 10);
        const current = periods.find(p => p.startsOn <= today && today <= p.endsOn) ?? periods[0];
        if (current) this.choose(current.id);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  choose(id: string): void {
    this.periodId.set(id);
    this.rows.set([]);
    this.error.set(null);
    this.loading.set(true);
    this.api.get<{ items: StatementRow[] }>('/api/v1/commission/statements/me', { period_id: id, page_size: '200' })
      .subscribe({
        next: page => { this.loading.set(false); if (this.periodId() === id) this.rows.set(page.items); },
        error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
      });
  }

  /** A line's explanation steps. */
  steps(row: StatementRow): StatementStep[] | null {
    return Array.isArray(row.explanation) ? row.explanation : null;
  }

  /** An adjustment's reason. */
  note(row: StatementRow): string | null {
    return typeof row.explanation === 'string' ? row.explanation : null;
  }
}
