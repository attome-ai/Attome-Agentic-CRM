import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_api::dead_letter_inbox::DeadLetterGroup`. */
export interface DeadLetterGroup {
  cause_group: string;
  source: string;
  step: string | null;
  error_kind: string;
  count: number;
  first_seen: string;
  last_seen: string;
  sample_message: string | null;
}

/** `attome_core::dead_letter::DeadLetter`. */
export interface DeadLetterItem {
  source: string;
  id: string;
  step: string | null;
  error_kind: string;
  cause_group: string;
  message: string | null;
  first_seen: string;
  attempts: number;
  payload_ref: string | null;
}

/** `attome_api::dead_letter_inbox::GroupReplayStarted`. */
export interface GroupReplayStarted {
  preview: { outcome: string; reason: string | null };
  job_id: string | null;
  queued: number;
  rate_per_minute: number;
}

interface Page<T> { items: T[]; total: number; warnings?: string[] }

/** How a group is moving: `new` (first failed in the last day), `active`
 *  (failed again in the last hour) or `quiet`. */
export function trend(group: DeadLetterGroup, now: number = Date.now()): 'new' | 'active' | 'quiet' {
  const hour = 3_600_000;
  if (now - Date.parse(group.first_seen) < 24 * hour) return 'new';
  if (now - Date.parse(group.last_seen) < hour) return 'active';
  return 'quiet';
}

/** A rate the API accepts (1–600 a minute), or `null`. */
export function validRate(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 600 ? value : null;
}

const BASE = '/api/v1/admin/dead-letters';

/**
 * The dead-letter inbox (roadmap M5-T3): everything that failed for good —
 * background jobs, flow triggers, flow runs, webhook deliveries — grouped
 * by cause. A group is replayed at a chosen pace after its oldest item went
 * through as a preview; one item is replayed or discarded with a reason.
 * Extends the failed-jobs screen. Logical CSS only.
 */
@Component({
  selector: 'xrm-dead-letter-inbox',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <section class="dl">
      <div class="dl-head">
        <h3>{{ 'deadLetterInbox.title' | translate }}</h3>
        <button type="button" (click)="load()" [disabled]="busy()">{{ 'deadLetterInbox.refresh' | translate }}</button>
      </div>
      <p class="dl-muted">{{ 'deadLetterInbox.intro' | translate }}</p>
      @if (error(); as message) { <p class="dl-error" role="alert">{{ message }}</p> }
      @if (notice(); as message) { <p class="dl-notice" role="status">{{ message }}</p> }
      @for (w of warnings(); track w) { <p class="dl-muted">{{ w }}</p> }
      @if (groups().length === 0) {
        <p class="dl-muted">{{ 'deadLetterInbox.none' | translate }}</p>
      } @else {
        <table class="dl-table">
          <thead>
            <tr>
              <th scope="col">{{ 'deadLetterInbox.source' | translate }}</th>
              <th scope="col">{{ 'deadLetterInbox.step' | translate }}</th>
              <th scope="col">{{ 'deadLetterInbox.errorKind' | translate }}</th>
              <th scope="col">{{ 'deadLetterInbox.count' | translate }}</th>
              <th scope="col">{{ 'deadLetterInbox.lastSeen' | translate }}</th>
              <th scope="col"><span class="dl-sr">{{ 'deadLetterInbox.actions' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (g of groups(); track g.cause_group) {
              <tr [attr.data-group]="g.cause_group">
                <td>{{ 'deadLetterInbox.sources.' + g.source | translate }}</td>
                <td dir="ltr"><code>{{ g.step ?? '—' }}</code></td>
                <td>
                  {{ g.error_kind }}
                  @if (g.sample_message) { <span class="dl-sample" dir="auto">{{ g.sample_message }}</span> }
                </td>
                <td>
                  {{ g.count }}
                  @if (trendOf(g) !== 'quiet') {
                    <span class="dl-trend" [attr.data-trend]="trendOf(g)">{{ 'deadLetterInbox.trend.' + trendOf(g) | translate }}</span>
                  }
                </td>
                <td>{{ g.last_seen | localDate }}</td>
                <td class="dl-actions">
                  <label>
                    <span class="dl-sr">{{ 'deadLetterInbox.rate' | translate }}</span>
                    <input type="number" min="1" max="600" [(ngModel)]="rate" [attr.aria-label]="'deadLetterInbox.rate' | translate" />
                  </label>
                  <button type="button" (click)="replayGroup(g)" [disabled]="busy()">{{ 'deadLetterInbox.replayGroup' | translate }}</button>
                  <button type="button" (click)="toggle(g)">{{ (open() === g.cause_group ? 'deadLetterInbox.hide' : 'deadLetterInbox.items') | translate }}</button>
                </td>
              </tr>
              @if (open() === g.cause_group) {
                <tr class="dl-items"><td colspan="6">
                  @for (i of items(); track i.id) {
                    <div class="dl-item" [attr.data-item]="i.id">
                      <span>{{ i.first_seen | localDate }} · {{ 'deadLetterInbox.attempts' | translate }} {{ i.attempts }}</span>
                      <code dir="ltr">{{ i.id }}</code>
                      @if (i.message) { <span class="dl-sample" dir="auto">{{ i.message }}</span> }
                      <button type="button" (click)="replay(i)" [disabled]="busy()">{{ 'deadLetterInbox.replay' | translate }}</button>
                      @if (discarding() === i.id) {
                        <input type="text" [(ngModel)]="reason" maxlength="500"
                               [attr.aria-label]="'deadLetterInbox.reason' | translate"
                               [placeholder]="'deadLetterInbox.reason' | translate" />
                        <button type="button" (click)="discard(i)" [disabled]="busy() || !reason.trim()">{{ 'deadLetterInbox.confirmDiscard' | translate }}</button>
                        <button type="button" (click)="discarding.set(null)">{{ 'deadLetterInbox.cancel' | translate }}</button>
                      } @else {
                        <button type="button" (click)="startDiscard(i)">{{ 'deadLetterInbox.discard' | translate }}</button>
                      }
                    </div>
                  } @empty {
                    <div class="dl-muted">{{ 'deadLetterInbox.noItems' | translate }}</div>
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
    .dl { display: flex; flex-direction: column; gap: 0.5rem; }
    .dl-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .dl h3 { margin-block: 0; font-size: 1rem; }
    .dl-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .dl-table th, .dl-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .dl-sample { display: block; color: var(--color-text-secondary); font-size: 0.75rem; overflow-wrap: anywhere; }
    .dl-trend { margin-inline-start: 0.375rem; font-size: 0.75rem; color: var(--color-danger); }
    .dl-actions { display: flex; flex-wrap: wrap; gap: 0.25rem; align-items: center; }
    .dl-actions input { inline-size: 4.5rem; }
    .dl-items td { background: var(--color-bg-alt); }
    .dl-item { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: center; padding-block: 0.25rem; font-size: 0.8125rem; }
    .dl-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .dl-error { color: var(--color-danger); }
    .dl-notice { color: var(--color-text-secondary); }
    .dl-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class DeadLetterInboxComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly groups = signal<DeadLetterGroup[]>([]);
  readonly warnings = signal<string[]>([]);
  readonly items = signal<DeadLetterItem[]>([]);
  readonly open = signal<string | null>(null);
  readonly discarding = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);
  rate = 60;
  reason = '';

  trendOf(group: DeadLetterGroup): 'new' | 'active' | 'quiet' {
    return trend(group);
  }

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.api.get<Page<DeadLetterGroup>>(`${BASE}/groups`, { page_size: '200' }).subscribe({
      next: page => { this.groups.set(page.items); this.warnings.set(page.warnings ?? []); },
      error: (e: ApiError) => this.error.set(e.message),
    });
    const open = this.open();
    if (open) this.loadItems(open);
  }

  toggle(group: DeadLetterGroup): void {
    if (this.open() === group.cause_group) {
      this.open.set(null);
      return;
    }
    this.open.set(group.cause_group);
    this.loadItems(group.cause_group);
  }

  private loadItems(causeGroup: string): void {
    this.items.set([]);
    this.api.get<Page<DeadLetterItem>>(BASE, { group: causeGroup, page_size: '200' }).subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  replayGroup(group: DeadLetterGroup): void {
    const rate = validRate(this.rate);
    if (rate === null) {
      this.error.set('rate_per_minute: 1–600');
      return;
    }
    this.busy.set(true);
    this.notice.set(null);
    this.api.post<GroupReplayStarted>(`${BASE}/groups/replay`, {
      cause_group: group.cause_group, rate_per_minute: rate,
    }).subscribe({
      next: started => {
        this.busy.set(false);
        this.notice.set(started.job_id
          ? `${started.preview.outcome}; ${started.queued} → ${started.rate_per_minute}/min (${started.job_id})`
          : started.preview.outcome);
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  replay(item: DeadLetterItem): void {
    this.busy.set(true);
    this.api.post<unknown>(`${BASE}/${encodeURIComponent(item.source)}/${encodeURIComponent(item.id)}/replay`, {})
      .subscribe({
        next: () => { this.busy.set(false); this.load(); },
        error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
      });
  }

  startDiscard(item: DeadLetterItem): void {
    this.reason = '';
    this.discarding.set(item.id);
  }

  discard(item: DeadLetterItem): void {
    const reason = this.reason.trim();
    if (!reason) return;
    this.busy.set(true);
    this.api.post<void>(
      `${BASE}/${encodeURIComponent(item.source)}/${encodeURIComponent(item.id)}/discard`, { reason },
    ).subscribe({
      next: () => { this.busy.set(false); this.discarding.set(null); this.reason = ''; this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
