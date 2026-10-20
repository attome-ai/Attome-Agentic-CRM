import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { catchError, forkJoin, of } from 'rxjs';

/** A campaign as the calendar shows it (`campaign`, marketing pack). */
export interface CalendarCampaign {
  id: string;
  name: string;
  type: string | null;
  status: string | null;
  start: string | null;
  end: string | null;
  budget: number | null;
}

/** A marketing event (`marketing_event`). */
export interface CalendarEvent {
  id: string;
  name: string;
  nameAr: string | null;
  start: string | null;
  campaignId: string | null;
}

/** A budget line (`budget_line`, finance pack) as far as the calendar needs it. */
export interface CampaignBudgetLine {
  campaignCode: string | null;
  amount: number;
  actual: number;
}

/** One entry on one day of the calendar. */
export interface CalendarEntry {
  kind: 'campaign_start' | 'campaign_end' | 'event';
  id: string;
  label: string;
  day: string;
}

/** Budget against actual for one campaign. */
export interface BudgetRow {
  campaignId: string;
  name: string;
  budget: number | null;
  planned: number;
  actual: number;
  /** Budget (else planned lines) less actual; positive is left to spend. */
  remaining: number | null;
}

const num = (v: unknown): number => (v == null || v === '' ? 0 : Number(v) || 0);
const day = (iso: string | null): string | null => (iso && iso.length >= 10 ? iso.slice(0, 10) : null);

/** The first and last day (`YYYY-MM-DD`) of `month` (1-12) in `year`. Pure. */
export function monthRange(year: number, month: number): { first: string; last: string } {
  const pad = (n: number) => String(n).padStart(2, '0');
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  return { first: `${year}-${pad(month)}-01`, last: `${year}-${pad(month)}-${pad(lastDay)}` };
}

/**
 * The entries in [first, last]: each campaign's start and end and each
 * event's start that fall in the month, sorted by day then label. Pure.
 */
export function entriesForMonth(
  campaigns: readonly CalendarCampaign[],
  events: readonly CalendarEvent[],
  first: string,
  last: string,
  eventLabel: (e: CalendarEvent) => string = e => e.name,
): CalendarEntry[] {
  const inMonth = (d: string | null): d is string => !!d && d >= first && d <= last;
  const out: CalendarEntry[] = [];
  for (const c of campaigns) {
    const start = day(c.start);
    const end = day(c.end);
    if (inMonth(start)) out.push({ kind: 'campaign_start', id: c.id, label: c.name, day: start });
    if (inMonth(end) && end !== start) out.push({ kind: 'campaign_end', id: c.id, label: c.name, day: end });
  }
  for (const e of events) {
    const start = day(e.start);
    if (inMonth(start)) out.push({ kind: 'event', id: e.id, label: eventLabel(e), day: start });
  }
  return out.sort((a, b) => a.day.localeCompare(b.day) || a.label.localeCompare(b.label));
}

/**
 * Budget against actual per campaign: the campaign's own budget, the budget
 * lines that name it (by id or by name in `campaign_code`) as planned and
 * actual, and what is left. Pure.
 */
export function budgetRows(
  campaigns: readonly CalendarCampaign[],
  lines: readonly CampaignBudgetLine[],
): BudgetRow[] {
  return campaigns.map(c => {
    const keys = new Set([c.id.toLowerCase(), c.name.trim().toLowerCase()]);
    const mine = lines.filter(l => l.campaignCode && keys.has(l.campaignCode.trim().toLowerCase()));
    const planned = mine.reduce((sum, l) => sum + l.amount, 0);
    const actual = mine.reduce((sum, l) => sum + l.actual, 0);
    const base = c.budget ?? (mine.length ? planned : null);
    return {
      campaignId: c.id,
      name: c.name,
      budget: c.budget,
      planned,
      actual,
      remaining: base === null ? null : base - actual,
    };
  });
}

/**
 * The marketing calendar (roadmap E29-T1): a month of campaign starts and
 * ends and marketing events, day by day, and each campaign's budget against
 * what it has spent — its own budget, the finance budget lines that name it
 * (`campaign_code`, the campaign's id or name) as planned, and their
 * actuals. A deployment without the finance pack shows the campaign budgets
 * alone. Records show as the reader may read them. Arabic mirrors the
 * layout.
 */
@Component({
  selector: 'xrm-marketing-calendar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  template: `
    <section class="mc" aria-labelledby="mc-title">
      <header class="mc-head">
        <h2 id="mc-title">{{ 'marketingCalendar.title' | translate }}</h2>
        <nav class="mc-nav" [attr.aria-label]="'marketingCalendar.month' | translate">
          <button type="button" data-testid="mc-prev" (click)="shift(-1)">{{ 'marketingCalendar.previous' | translate }}</button>
          <strong data-testid="mc-month">{{ monthLabel() }}</strong>
          <button type="button" data-testid="mc-next" (click)="shift(1)">{{ 'marketingCalendar.next' | translate }}</button>
        </nav>
      </header>
      @if (error(); as message) { <p class="mc-error" role="alert">{{ message }}</p> }

      <ol class="mc-days">
        @for (group of days(); track group.day) {
          <li class="mc-day">
            <h3>{{ dayLabel(group.day) }}</h3>
            <ul>
              @for (e of group.entries; track e.kind + e.id) {
                <li class="mc-entry" [attr.data-kind]="e.kind" data-testid="mc-entry">
                  <span class="mc-kind">{{ 'marketingCalendar.' + e.kind | translate }}</span>
                  {{ e.label }}
                </li>
              }
            </ul>
          </li>
        } @empty {
          <li class="mc-muted">{{ 'marketingCalendar.nothing' | translate }}</li>
        }
      </ol>

      <h3>{{ 'marketingCalendar.budgetVsActual' | translate }}</h3>
      @if (budget().length) {
        <div class="mc-scroll">
          <table class="mc-budget">
            <thead>
              <tr>
                <th scope="col">{{ 'marketingCalendar.campaign' | translate }}</th>
                <th scope="col">{{ 'marketingCalendar.budget' | translate }}</th>
                <th scope="col">{{ 'marketingCalendar.planned' | translate }}</th>
                <th scope="col">{{ 'marketingCalendar.actual' | translate }}</th>
                <th scope="col">{{ 'marketingCalendar.remaining' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (r of budget(); track r.campaignId) {
                <tr [attr.data-campaign]="r.campaignId">
                  <th scope="row">{{ r.name }}</th>
                  <td>@if (r.budget !== null) { {{ r.budget | localNumber }} }</td>
                  <td>{{ r.planned | localNumber }}</td>
                  <td data-actual>{{ r.actual | localNumber }}</td>
                  <td data-remaining [class.mc-over]="r.remaining !== null && r.remaining < 0">
                    @if (r.remaining !== null) { {{ r.remaining | localNumber }} }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      } @else {
        <p class="mc-muted">{{ 'marketingCalendar.noCampaigns' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .mc { display: flex; flex-direction: column; gap: var(--space-3, 12px); }
    .mc-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--space-2, 8px); }
    .mc-nav { display: flex; align-items: center; gap: var(--space-2, 8px); }
    .mc-days { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2, 8px); }
    .mc-day h3 { margin-block: 0 var(--space-1, 4px); font-size: 1rem; }
    .mc-day ul { list-style: none; margin: 0; padding-inline-start: var(--space-3, 12px); }
    .mc-kind { color: var(--color-text-secondary); margin-inline-end: var(--space-1, 4px); }
    .mc-scroll { overflow-x: auto; }
    .mc-budget { border-collapse: collapse; inline-size: 100%; }
    .mc-budget th, .mc-budget td { padding: var(--space-1, 4px) var(--space-2, 8px); text-align: start; }
    .mc-over { color: var(--color-danger); }
    .mc-muted { color: var(--color-text-secondary); margin: 0; }
    .mc-error { color: var(--color-danger); margin: 0; }
  `],
})
export class MarketingCalendarComponent {
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly year = signal(new Date().getUTCFullYear());
  readonly month = signal(new Date().getUTCMonth() + 1);
  readonly campaigns = signal<CalendarCampaign[]>([]);
  readonly events = signal<CalendarEvent[]>([]);
  readonly lines = signal<CampaignBudgetLine[]>([]);
  readonly error = signal<string | null>(null);

  private readonly range = computed(() => monthRange(this.year(), this.month()));

  readonly days = computed(() => {
    const { first, last } = this.range();
    const ar = this.lang.current() === 'ar';
    const entries = entriesForMonth(this.campaigns(), this.events(), first, last,
      e => (ar && e.nameAr) ? e.nameAr : e.name);
    const groups: { day: string; entries: CalendarEntry[] }[] = [];
    for (const e of entries) {
      const group = groups.find(g => g.day === e.day);
      if (group) group.entries.push(e); else groups.push({ day: e.day, entries: [e] });
    }
    return groups;
  });

  /** Budget against actual for the campaigns running in the month. */
  readonly budget = computed(() => {
    const { first, last } = this.range();
    const running = this.campaigns().filter(c => {
      const start = day(c.start) ?? first;
      const end = day(c.end) ?? start;
      return start <= last && end >= first;
    });
    return budgetRows(running, this.lines());
  });

  readonly monthLabel = computed(() => new Intl.DateTimeFormat(this.locale(), { year: 'numeric', month: 'long', timeZone: 'UTC' })
    .format(new Date(Date.UTC(this.year(), this.month() - 1, 1))));

  constructor() {
    this.load();
  }

  shift(by: number): void {
    const index = this.year() * 12 + (this.month() - 1) + by;
    this.year.set(Math.floor(index / 12));
    this.month.set((index % 12) + 1);
    this.load();
  }

  dayLabel(iso: string): string {
    const [y, m, d] = iso.split('-').map(Number);
    return new Intl.DateTimeFormat(this.locale(), { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' })
      .format(new Date(Date.UTC(y, m - 1, d)));
  }

  private locale(): string {
    return this.lang.intlLocale();
  }

  private load(): void {
    const { first, last } = this.range();
    this.error.set(null);
    forkJoin({
      campaigns: this.entities.list('campaign', {
        filters: [{ field: 'start_date', op: 'lte', value: last }],
        sorts: [{ field: 'start_date', dir: 'asc' }],
        limit: 200,
      }),
      events: this.entities.list('marketing_event', {
        filters: [
          { field: 'starts_at', op: 'gte', value: first },
          { field: 'starts_at', op: 'lte', value: `${last}T23:59:59Z` },
        ],
        sorts: [{ field: 'starts_at', dir: 'asc' }],
        limit: 200,
      }).pipe(catchError(() => of(null))),
      // The finance pack's budget lines; a deployment without it has none.
      lines: this.entities.list('budget_line', {
        filters: [{ field: 'campaign_code', op: 'notnull' }],
        limit: 500,
      }).pipe(catchError(() => of(null))),
    }).subscribe({
      next: ({ campaigns, events, lines }) => {
        this.campaigns.set(campaigns.data.map(c => ({
          id: c.id,
          name: String(c.data['name'] ?? ''),
          type: (c.data['campaign_type'] as string | null) ?? null,
          status: (c.data['status'] as string | null) ?? null,
          start: (c.data['start_date'] as string | null) ?? null,
          end: (c.data['end_date'] as string | null) ?? null,
          budget: c.data['budget'] == null || c.data['budget'] === '' ? null : num(c.data['budget']),
        })));
        this.events.set((events?.data ?? []).map(e => ({
          id: e.id,
          name: String(e.data['name'] ?? ''),
          nameAr: (e.data['name_ar'] as string | null) ?? null,
          start: (e.data['starts_at'] as string | null) ?? null,
          campaignId: (e.data['campaign_ref'] as string | null) ?? null,
        })));
        this.lines.set((lines?.data ?? []).map(l => ({
          campaignCode: (l.data['campaign_code'] as string | null) ?? null,
          amount: num(l.data['amount']),
          actual: num(l.data['actual']),
        })));
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
