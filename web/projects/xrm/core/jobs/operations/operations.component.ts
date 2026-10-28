import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { ageLabel } from '../lanes/job-lanes.component';

/** `attome_api::jobs_admin::OperationSummary`. */
export interface OperationSummary {
  id: string;
  /** `mass`, `bulk`, `bulk_transform`, `staged_import`, `import` or `index_build`. */
  kind: string;
  action?: string | null;
  entity: string;
  status: string;
  rows_done?: number | null;
  estimated_rows?: number | null;
  started_by?: string | null;
  reason?: string | null;
  created_at: string;
  finished_at?: string | null;
  /** A mass operation's row version, sent as `If-Match` by its controls. */
  row_version?: number | null;
  seconds_left?: number | null;
}

interface OperationsPage {
  items: OperationSummary[];
  next_cursor?: string | null;
}

/** A control on a mass operation (`POST /api/v1/mass/{id}/{control}`). */
export type MassControl = 'pause' | 'resume' | 'cancel' | 'undo';

/** How often the screen refreshes while anything is working. */
export const OPERATIONS_POLL_MS = 5000;

/** Status words that mean the operation is still working, whatever its kind. */
const WORKING = new Set(['queued', 'pending', 'running', 'processing', 'undoing', 'staged']);

export function isWorking(op: OperationSummary): boolean {
  return WORKING.has(op.status);
}

/**
 * The controls a mass operation offers in its status, mirroring
 * `attome_records::mass::next_status`: pause while queued or running,
 * resume while paused, cancel until it finishes, undo once done (or
 * cancelled, which undoes the part that ran). Other kinds have their own
 * screens and no controls here. Pure.
 */
export function controlsFor(op: OperationSummary): MassControl[] {
  if (op.kind !== 'mass' || op.row_version === null || op.row_version === undefined) return [];
  switch (op.status) {
    case 'queued':
    case 'running':   return ['pause', 'cancel'];
    case 'paused':    return ['resume', 'cancel'];
    case 'done':
    case 'cancelled': return ['undo'];
    default:          return [];
  }
}

/** Percent done, or `null` when the total is unknown. Pure. */
export function progressPercent(op: OperationSummary): number | null {
  const total = op.estimated_rows;
  if (!total || total <= 0) return null;
  return Math.min(100, Math.round(((op.rows_done ?? 0) / total) * 100));
}

/**
 * Every long-running operation in one list (roadmap AA10-T8): mass
 * operations, bulk edits and transforms, imports and, for administrators,
 * the indexes being built now — with progress, time left, who started it
 * and why. Refreshes every 5 s while any row is working. A mass operation
 * can be paused, resumed, cancelled and undone here; each control sends the
 * row version the screen last saw, so a stale screen gets a conflict
 * instead of acting on a state it never showed. Logical CSS only.
 */
@Component({
  selector: 'xrm-operations',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, TranslatePipe],
  template: `
    <section class="ops">
      <div class="ops-head">
        <h2>{{ 'operations.title' | translate }}</h2>
        <button type="button" (click)="load()" [disabled]="busy()">{{ 'operations.refresh' | translate }}</button>
      </div>
      @if (error(); as message) { <p class="ops-error" role="alert">{{ message }}</p> }
      @if (!items().length && !busy()) {
        <p class="ops-empty">{{ 'operations.empty' | translate }}</p>
      } @else {
      <table class="ops-table">
        <thead>
          <tr>
            <th scope="col">{{ 'operations.what' | translate }}</th>
            <th scope="col">{{ 'operations.status' | translate }}</th>
            <th scope="col">{{ 'operations.progress' | translate }}</th>
            <th scope="col">{{ 'operations.timeLeft' | translate }}</th>
            <th scope="col">{{ 'operations.startedBy' | translate }}</th>
            <th scope="col">{{ 'operations.reason' | translate }}</th>
            <th scope="col">{{ 'operations.started' | translate }}</th>
            <th scope="col"><span class="ops-sr">{{ 'operations.actions' | translate }}</span></th>
          </tr>
        </thead>
        <tbody>
          @for (op of items(); track op.id) {
            <tr [attr.data-op]="op.id" [attr.data-status]="op.status">
              <th scope="row">
                {{ ('operations.kind.' + op.kind) | translate }}
                @if (op.action) { <span class="ops-muted">{{ op.action }}</span> }
                <div class="ops-entity">{{ op.entity }}</div>
              </th>
              <td>{{ op.status }}</td>
              <td>
                @let p = percent(op);
                @if (p !== null) {
                  <progress max="100" [value]="p" [attr.aria-label]="'operations.progress' | translate"></progress>
                  <span class="ops-muted">{{ op.rows_done ?? 0 }} / {{ op.estimated_rows }}</span>
                } @else if (op.rows_done !== null && op.rows_done !== undefined) {
                  {{ op.rows_done }}
                } @else { — }
              </td>
              <td>{{ op.seconds_left === null || op.seconds_left === undefined ? '—' : age(op.seconds_left) }}</td>
              <td class="ops-muted">{{ op.started_by ?? '—' }}</td>
              <td>{{ op.reason ?? '—' }}</td>
              <td>{{ op.created_at | date: 'short' }}</td>
              <td class="ops-actions">
                @for (control of controls(op); track control) {
                  <button type="button" [attr.data-control]="control" [disabled]="acting() === op.id"
                    (click)="act(op, control)">{{ ('operations.control.' + control) | translate }}</button>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
      @if (nextCursor()) {
        <button type="button" class="ops-more" (click)="more()" [disabled]="busy()">{{ 'operations.more' | translate }}</button>
      }
      }
    </section>
  `,
  styles: [`
    .ops-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    .ops-table { inline-size: 100%; border-collapse: collapse; }
    .ops-table th, .ops-table td { padding-block: 0.4rem; padding-inline: 0.6rem; text-align: start; border-block-end: 1px solid var(--border, #e5e7eb); vertical-align: top; }
    .ops-table progress { inline-size: 8rem; margin-inline-end: 0.5rem; }
    .ops-entity, .ops-muted { color: var(--text-muted, #6b7280); font-weight: 400; font-size: 0.85rem; }
    .ops-muted { margin-inline-start: 0.4rem; }
    .ops-actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
    .ops-error { color: var(--danger, #b91c1c); }
    .ops-more { margin-block-start: 0.75rem; }
    .ops-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class OperationsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly items = signal<OperationSummary[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  /** The operation a control is being sent for. */
  readonly acting = signal<string | null>(null);
  readonly anyWorking = computed(() => this.items().some(isWorking));

  readonly age = ageLabel;
  readonly controls = controlsFor;
  readonly percent = progressPercent;

  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stopPolling());
  }

  ngOnInit(): void {
    this.load();
  }

  /** The first page again; schedules the next refresh while anything works. */
  load(): void {
    this.stopPolling();
    this.busy.set(true);
    this.error.set(null);
    this.api.get<OperationsPage>('/api/v1/admin/operations').subscribe({
      next: page => {
        this.items.set(page.items);
        this.nextCursor.set(page.next_cursor ?? null);
        this.busy.set(false);
        this.schedule();
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.busy.set(false);
      },
    });
  }

  more(): void {
    const cursor = this.nextCursor();
    if (!cursor) return;
    this.busy.set(true);
    this.api.get<OperationsPage>('/api/v1/admin/operations', { cursor }).subscribe({
      next: page => {
        this.items.update(items => [...items, ...page.items]);
        this.nextCursor.set(page.next_cursor ?? null);
        this.busy.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.busy.set(false);
      },
    });
  }

  act(op: OperationSummary, control: MassControl): void {
    if (op.row_version === null || op.row_version === undefined) return;
    this.acting.set(op.id);
    this.error.set(null);
    this.api.post(`/api/v1/mass/${encodeURIComponent(op.id)}/${control}`, {}, { ifMatch: op.row_version }).subscribe({
      next: () => {
        this.acting.set(null);
        this.load();
      },
      error: (e: ApiError) => {
        // A 409 means the operation moved on since this screen loaded:
        // show why and reload what it is now.
        this.acting.set(null);
        this.error.set(e.message);
        this.load();
      },
    });
  }

  private schedule(): void {
    if (!this.anyWorking()) return;
    this.timer = setTimeout(() => this.load(), OPERATIONS_POLL_MS);
  }

  private stopPolling(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
