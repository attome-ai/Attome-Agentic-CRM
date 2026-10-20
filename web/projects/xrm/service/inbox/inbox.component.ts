import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, AuthService, LangService, TranslatePipe } from '@attome/base';
import { EntityService, NotesPanelComponent } from '@attome/xrm/core/entity';
import { PresenceComponent } from '@attome/xrm/service/workspace';
import { catchError, forkJoin, map, of } from 'rxjs';

/** One shared mailbox (`GET /api/v1/service/inbox/mailboxes`). */
export interface InboxMailbox {
  id: string;
  name: string;
}

/** One routed conversation (`GET /api/v1/service/inbox`). */
export interface InboxConversation {
  entity_name: string;
  record_id: string;
  messages: number;
  last_message_at: string;
}

interface Page<T> {
  items: T[];
  total: number;
}

/** A conversation with its record, as the inbox shows it. */
export interface InboxRow {
  entity: string;
  id: string;
  title: string;
  status: string | null;
  assignee: string | null;
  messages: number;
  last: string;
  rowVersion: number;
}

/** The ticket statuses an agent sets from the inbox. */
export const TICKET_STATUSES = ['new', 'open', 'in_progress', 'waiting_on_customer', 'resolved', 'closed'] as const;
const DONE = new Set(['resolved', 'closed']);

export type InboxFilter = 'open' | 'mine' | 'all';

/** The rows `filter` keeps for `me`. Pure. */
export function filterRows(rows: readonly InboxRow[], filter: InboxFilter, me: string | null): InboxRow[] {
  switch (filter) {
    case 'open': return rows.filter(r => r.entity !== 'service_ticket' || !DONE.has(r.status ?? ''));
    case 'mine': return rows.filter(r => !!me && r.assignee === me);
    default: return [...rows];
  }
}

/** A row from a conversation and its record's data. Pure. */
export function toRow(c: InboxConversation, data: Record<string, unknown>, rowVersion: number): InboxRow {
  const text = (k: string) => (typeof data[k] === 'string' && data[k] ? data[k] as string : null);
  return {
    entity: c.entity_name,
    id: c.record_id,
    title: text('title') ?? text('name') ?? text('full_name') ?? text('email') ?? c.record_id,
    status: text('status'),
    assignee: text('assignee_id'),
    messages: c.messages,
    last: c.last_message_at,
    rowVersion,
  };
}

/**
 * The shared inbox (roadmap C8-T1): a mailbox's conversations (the tickets,
 * leads and contact logs its mail was routed to), latest first, with open,
 * mine and all filters. For the one in hand: who else is viewing it (G5-T3
 * presence, the collision warning), the ticket's status and assignee, the
 * record's internal notes, and turning a lead or contact conversation into
 * a ticket. Records the agent may not read are left out.
 */
@Component({
  selector: 'xrm-service-inbox',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, PresenceComponent, NotesPanelComponent],
  template: `
    <section class="ib" aria-labelledby="ib-title">
      <header class="ib-head">
        <h2 id="ib-title">{{ 'serviceInbox.title' | translate }}</h2>
        <label>{{ 'serviceInbox.mailbox' | translate }}
          <select data-testid="ib-mailbox" [value]="mailbox() ?? ''" (change)="selectMailbox(value($event))">
            @for (m of mailboxes(); track m.id) { <option [value]="m.id">{{ m.name }}</option> }
          </select>
        </label>
        <div class="ib-filters" role="group" [attr.aria-label]="'serviceInbox.filter' | translate">
          @for (f of filters; track f) {
            <button type="button" [attr.aria-pressed]="filter() === f" [attr.data-filter]="f" (click)="filter.set(f)">
              {{ 'serviceInbox.filters.' + f | translate }}</button>
          }
        </div>
      </header>
      @if (error(); as message) { <p class="ib-error" role="alert">{{ message }}</p> }
      @if (!mailboxes().length && loaded()) { <p class="ib-muted">{{ 'serviceInbox.noMailboxes' | translate }}</p> }

      <div class="ib-body">
        <ul class="ib-list" [attr.aria-label]="'serviceInbox.conversations' | translate">
          @for (r of shown(); track r.entity + r.id) {
            <li>
              <button type="button" class="ib-item" data-testid="ib-row" [class.ib-active]="selected()?.id === r.id" (click)="select(r)">
                <strong>{{ r.title }}</strong>
                <span class="ib-meta">
                  {{ 'serviceInbox.entity.' + r.entity | translate }}
                  @if (r.status) { · {{ 'serviceInbox.status.' + r.status | translate }} }
                  · {{ r.messages }} {{ 'serviceInbox.messages' | translate }}
                </span>
              </button>
            </li>
          } @empty {
            <li class="ib-muted">{{ 'serviceInbox.empty' | translate }}</li>
          }
        </ul>

        @if (selected(); as s) {
          <article class="ib-detail" data-testid="ib-detail">
            <h3>{{ s.title }}</h3>
            <xrm-service-presence [entity]="s.entity" [recordId]="s.id" />
            @if (s.entity === 'service_ticket') {
              <div class="ib-actions">
                <label>{{ 'serviceInbox.statusLabel' | translate }}
                  <select data-testid="ib-status" [value]="s.status ?? ''" [disabled]="busy()" (change)="setStatus(s, value($event))">
                    @for (st of statuses; track st) { <option [value]="st">{{ 'serviceInbox.status.' + st | translate }}</option> }
                  </select>
                </label>
                <button type="button" data-testid="ib-assign" [disabled]="busy() || s.assignee === me()" (click)="assignToMe(s)">
                  {{ 'serviceInbox.assignToMe' | translate }}</button>
              </div>
            } @else {
              <button type="button" data-testid="ib-convert" [disabled]="busy()" (click)="convert(s)">
                {{ 'serviceInbox.convert' | translate }}</button>
            }
            @if (notice(); as n) { <p role="status">{{ n | translate }}</p> }
            <xrm-notes-panel [entityName]="s.entity" [recordId]="s.id" />
          </article>
        }
      </div>
    </section>
  `,
  styles: [`
    .ib { display: flex; flex-direction: column; gap: var(--space-3, 12px); }
    .ib-head { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-3, 12px); }
    .ib-filters { display: flex; gap: var(--space-1, 4px); }
    .ib-filters [aria-pressed="true"] { font-weight: 600; }
    .ib-body { display: grid; grid-template-columns: minmax(16rem, 1fr) 2fr; gap: var(--space-3, 12px); }
    .ib-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-1, 4px); }
    .ib-item { inline-size: 100%; text-align: start; display: flex; flex-direction: column; background: none; border: 1px solid var(--color-border); padding: var(--space-2, 8px); cursor: pointer; }
    .ib-active { border-color: var(--color-primary); }
    .ib-meta, .ib-muted { color: var(--color-text-secondary); }
    .ib-detail { display: flex; flex-direction: column; gap: var(--space-2, 8px); }
    .ib-actions { display: flex; flex-wrap: wrap; align-items: end; gap: var(--space-2, 8px); }
    .ib-error { color: var(--color-danger); margin: 0; }
    @media (max-width: 48rem) { .ib-body { grid-template-columns: 1fr; } }
  `],
})
export class InboxComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  private readonly auth = inject(AuthService);
  private readonly lang = inject(LangService);

  readonly filters: readonly InboxFilter[] = ['open', 'mine', 'all'];
  readonly statuses = TICKET_STATUSES;
  readonly mailboxes = signal<InboxMailbox[]>([]);
  readonly mailbox = signal<string | null>(null);
  readonly rows = signal<InboxRow[]>([]);
  readonly filter = signal<InboxFilter>('open');
  readonly selected = signal<InboxRow | null>(null);
  readonly busy = signal(false);
  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly me = computed(() => this.auth.userId());
  readonly shown = computed(() => filterRows(this.rows(), this.filter(), this.me()));

  constructor() {
    this.api.get<Page<InboxMailbox>>('/api/v1/service/inbox/mailboxes').subscribe({
      next: page => {
        this.mailboxes.set(page.items);
        this.loaded.set(true);
        if (page.items.length) this.selectMailbox(page.items[0].id);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  value(event: Event): string {
    return (event.target as HTMLSelectElement).value;
  }

  selectMailbox(id: string): void {
    this.mailbox.set(id);
    this.selected.set(null);
    this.load();
  }

  select(row: InboxRow): void {
    this.selected.set(row);
    this.notice.set(null);
  }

  setStatus(row: InboxRow, status: string): void {
    this.save(row, { status });
  }

  assignToMe(row: InboxRow): void {
    const me = this.me();
    if (me) this.save(row, { assignee_id: me });
  }

  /** A lead or contact conversation becomes a ticket the agent requests. */
  convert(row: InboxRow): void {
    const me = this.me();
    if (!me) return;
    this.busy.set(true);
    this.entities.create('service_ticket', {
      title: row.title,
      channel: 'email',
      status: 'new',
      requester_id: me,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set('serviceInbox.converted');
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private save(row: InboxRow, patch: Record<string, unknown>): void {
    this.busy.set(true);
    this.error.set(null);
    this.entities.update(row.entity, row.id, patch, row.rowVersion).subscribe({
      next: r => {
        const next = toRow(
          { entity_name: row.entity, record_id: row.id, messages: row.messages, last_message_at: row.last },
          r.data as Record<string, unknown>,
          r.row_version,
        );
        this.rows.update(rows => rows.map(x => (x.entity === row.entity && x.id === row.id ? next : x)));
        this.selected.set(next);
        this.busy.set(false);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private load(): void {
    const mailbox = this.mailbox();
    if (!mailbox) return;
    this.error.set(null);
    this.api.get<Page<InboxConversation>>('/api/v1/service/inbox', { mailbox, page_size: '50' }).subscribe({
      next: page => {
        if (!page.items.length) {
          this.rows.set([]);
          return;
        }
        // Each record through the generic API: one the agent may not read
        // is left out.
        forkJoin(page.items.map(c => this.entities.get(c.entity_name, c.record_id).pipe(
          map(r => toRow(c, r.data as Record<string, unknown>, r.row_version)),
          catchError(() => of(null)),
        ))).subscribe(rows => this.rows.set(rows.filter((r): r is InboxRow => r !== null)));
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e));
  }
}
