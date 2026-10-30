import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { QueryExecResponse } from '@attome/xrm/core/query/data';

import { logicalToUrlPath } from '../services/entity-url.utils';

/** A query filter: `in` takes a list, the rest one value. */
export interface Customer360Filter {
  field: string;
  op: 'eq' | 'in';
  value: string | string[];
}

/** One section of the 360 view: the records of `entity` linked to the customer. */
export interface Customer360Section {
  key: string;
  entity: string;
  /** The column naming the customer (a lookup), or the polymorphic pair for activities. */
  filters: Customer360Filter[];
  /** The column shown for each row. */
  labelField: string;
}

/**
 * The sections for a customer, open work first. Each names records that
 * point at the customer through a lookup (or, for activities, the
 * entity/record pair) and are still open. Pure.
 */
export function sectionsFor(entity: string, id: string): Customer360Section[] {
  const openTasks: Customer360Section = {
    key: 'tasks', entity: 'activity', labelField: 'subject',
    filters: [
      { field: 'entity_name', op: 'eq', value: entity },
      { field: 'record_id', op: 'eq', value: id },
      { field: 'status', op: 'eq', value: 'open' },
    ],
  };
  if (entity === 'contact') {
    return [
      openTasks,
      {
        key: 'assets', entity: 'asset', labelField: 'name',
        filters: [{ field: 'contact_ref', op: 'eq', value: id }],
      },
    ];
  }
  return [
    {
      key: 'deals', entity: 'opportunity', labelField: 'name',
      filters: [
        { field: 'account_ref', op: 'eq', value: id },
        { field: 'stage', op: 'in', value: ['prospecting', 'qualification', 'proposal', 'negotiation'] },
      ],
    },
    openTasks,
    {
      key: 'invoices', entity: 'invoice', labelField: 'invoice_number',
      filters: [
        { field: 'account_ref', op: 'eq', value: id },
        { field: 'payment_status', op: 'in', value: ['open', 'partly_paid', 'overdue'] },
      ],
    },
    {
      key: 'entitlements', entity: 'entitlement', labelField: 'name',
      filters: [
        { field: 'account_ref', op: 'eq', value: id },
        { field: 'status', op: 'eq', value: 'active' },
      ],
    },
    {
      key: 'assets', entity: 'asset', labelField: 'name',
      filters: [
        { field: 'account_ref', op: 'eq', value: id },
        { field: 'lifecycle_status', op: 'in', value: ['ordered', 'in_service', 'under_maintenance'] },
      ],
    },
    {
      key: 'contacts', entity: 'contact', labelField: 'full_name',
      filters: [{ field: 'account_ref', op: 'eq', value: id }],
    },
  ];
}

/** What one section shows once loaded. */
interface SectionState {
  status: 'idle' | 'loading' | 'ready' | 'hidden';
  total: number;
  rows: { id: string; label: string }[];
}

interface TimelineItem {
  kind: string;
  occurred_at: string;
  summary: string;
}

/** Rows a section shows. */
export const SECTION_ROWS = 5;

/**
 * G15-T1: a customer's 360 view — the account's (or contact's) open deals,
 * open tasks, unpaid invoices, active entitlements, assets and people, its
 * recent timeline and an AI summary on request. Each section loads the
 * first time it is opened (its count comes with the first page, read
 * through the same permission-checked query every list uses), and a section
 * whose entity is not installed on this deployment hides itself. Used on
 * the record pages and in the agent workspace; logical CSS only.
 */
@Component({
  selector: 'xrm-customer-360',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  template: `
    <section class="c360">
      <header class="c360-head">
        <h3>{{ 'customer360.title' | translate }}</h3>
        @if (recordPage(); as pageId) {
          <a class="c360-page" data-record-page [routerLink]="['/xrm/pages', pageId]"
             [queryParams]="{ entity: entity(), record: recordId() }">{{ 'customer360.openPage' | translate }}</a>
        }
        <button type="button" (click)="summarise()" [disabled]="summarising()">
          {{ (summarising() ? 'customer360.summarising' : 'customer360.summarise') | translate }}
        </button>
      </header>
      @if (summary(); as text) { <p class="c360-summary" dir="auto" data-summary>{{ text }}</p> }
      @if (error(); as message) { <p class="c360-error" role="alert">{{ message }}</p> }

      @for (s of sections(); track s.key) {
        @if (state(s.key).status !== 'hidden') {
          <details class="c360-section" [attr.data-section]="s.key" (toggle)="opened(s, $event)">
            <summary>
              {{ 'customer360.sections.' + s.key | translate }}
              @if (state(s.key).status === 'ready') { <span class="c360-count">{{ state(s.key).total }}</span> }
            </summary>
            @if (state(s.key).status === 'loading') { <p class="c360-muted">{{ 'customer360.loading' | translate }}</p> }
            @if (state(s.key).status === 'ready') {
              <ul>
                @for (r of state(s.key).rows; track r.id) {
                  <li><a [routerLink]="formPath(s.entity)" [queryParams]="{ id: r.id }" dir="auto">{{ r.label || r.id }}</a></li>
                } @empty {
                  <li class="c360-muted">{{ 'customer360.none' | translate }}</li>
                }
              </ul>
            }
          </details>
        }
      }

      <details class="c360-section" data-section="timeline" (toggle)="openedTimeline($event)">
        <summary>{{ 'customer360.sections.timeline' | translate }}</summary>
        <ul>
          @for (t of timeline(); track $index) {
            <li><small class="c360-muted">{{ t.occurred_at | localDate }}</small> <span dir="auto">{{ t.summary }}</span></li>
          } @empty {
            <li class="c360-muted">{{ 'customer360.none' | translate }}</li>
          }
        </ul>
      </details>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .c360 { display: flex; flex-direction: column; gap: 0.5rem; }
    .c360-head { display: flex; align-items: center; gap: 0.75rem; }
    .c360-head h3 { margin-block: 0; font-size: 1rem; flex: 1 1 auto; }
    .c360-summary { white-space: pre-wrap; margin-block: 0; text-align: start; }
    .c360-section { border-block-end: 1px solid var(--color-border); padding-block: 0.375rem; }
    .c360-section summary { cursor: pointer; font-weight: 600; display: flex; gap: 0.5rem; align-items: center; }
    .c360-section ul { list-style: none; margin-block: 0.375rem 0; padding: 0; display: flex; flex-direction: column; gap: 0.25rem; }
    .c360-count { color: var(--color-text-secondary); font-weight: 400; }
    .c360-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .c360-error { color: var(--color-danger); }
  `],
})
export class Customer360Component {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  /** `account` or `contact`. */
  readonly entity = input.required<string>();
  /** The customer's id. */
  readonly recordId = input.required<string>();

  private readonly states = signal<Record<string, SectionState>>({});
  readonly timeline = signal<TimelineItem[]>([]);
  readonly summary = signal<string | null>(null);
  readonly summarising = signal(false);
  readonly error = signal<string | null>(null);
  /** D1-T2: the entity's record page, when it has one. */
  readonly recordPage = signal<string | null>(null);
  private timelineLoaded = false;

  constructor() {
    effect(() => {
      const entity = this.entity();
      untracked(() => {
        this.recordPage.set(null);
        // No record page (a 404) leaves the link out.
        this.api.get<{ id: string }>(`/api/v1/model/entities/${encodeURIComponent(entity)}/record-page`)
          .subscribe({ next: ref => this.recordPage.set(ref.id), error: () => this.recordPage.set(null) });
      });
    });
  }

  sections(): Customer360Section[] {
    return sectionsFor(this.entity(), this.recordId());
  }

  state(key: string): SectionState {
    return this.states()[key] ?? { status: 'idle', total: 0, rows: [] };
  }

  formPath(entity: string): string {
    return `/${logicalToUrlPath(entity)}/form`;
  }

  private setState(key: string, value: SectionState): void {
    this.states.update(s => ({ ...s, [key]: value }));
  }

  /** Loads a section the first time it opens. */
  opened(section: Customer360Section, event: Event): void {
    const open = (event.target as HTMLDetailsElement | null)?.open ?? false;
    if (!open || this.state(section.key).status !== 'idle') return;
    this.load(section);
  }

  load(section: Customer360Section): void {
    this.setState(section.key, { status: 'loading', total: 0, rows: [] });
    // The same permission-checked query every entity list runs.
    this.api.post<QueryExecResponse>('/api/v1/query/execute', {
      entity: section.entity,
      page: 1,
      page_size: SECTION_ROWS,
      search: '',
      order_by: '',
      order_dir: 'desc',
      filters: section.filters,
      include_total: true,
    }).subscribe({
      next: res => this.setState(section.key, {
        status: 'ready',
        total: Number(res.data.total ?? 0),
        rows: res.data.records.map(r => ({
          id: String(r['id'] ?? ''),
          label: String(r[section.labelField] ?? ''),
        })),
      }),
      // Not installed here, or not the caller's to read: the section hides.
      error: () => this.setState(section.key, { status: 'hidden', total: 0, rows: [] }),
    });
  }

  openedTimeline(event: Event): void {
    const open = (event.target as HTMLDetailsElement | null)?.open ?? false;
    if (!open || this.timelineLoaded) return;
    this.timelineLoaded = true;
    this.api.get<{ items: TimelineItem[] }>(
      `/api/v1/${encodeURIComponent(this.entity())}/${encodeURIComponent(this.recordId())}/timeline`,
      { page_size: '10' },
    ).subscribe({
      next: page => this.timeline.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  /** The AI summary of the customer (`record.summarize`), on request. */
  summarise(): void {
    this.summarising.set(true);
    this.api.post<{ status: string; result?: { summary?: string } }>(
      '/api/v1/actions/record.summarize/invoke',
      { args: { entity: this.entity(), record_id: this.recordId() } },
    ).subscribe({
      next: outcome => {
        this.summarising.set(false);
        this.summary.set(outcome.status === 'completed' ? (outcome.result?.summary ?? null) : null);
      },
      error: (e: ApiError) => { this.summarising.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
