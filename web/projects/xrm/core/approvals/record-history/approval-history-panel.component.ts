import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_api::approval_process::ApprovalHistoryItem`. */
export interface ApprovalHistoryItem {
  id: string;
  action_type: string;
  title: string | null;
  status: string;
  requested_by: string;
  requested_by_name: string | null;
  requested_at: string;
  executed_at: string | null;
  changed_attributes: string[];
}

interface Page<T> { items: T[]; total: number }

/** Requests the panel shows. */
export const APPROVAL_HISTORY_PAGE_SIZE = 20;

/**
 * A record's approval history (roadmap M9-T4), the record form's Approvals
 * tab: every request about the record, newest first, each linking to its
 * request page. Reads `GET /api/v1/approvals/regarding/{entity}/{id}`.
 */
@Component({
  selector: 'xrm-approval-history-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  template: `
    <section class="ah">
      @if (error(); as message) { <p class="ah-error" role="alert">{{ message }}</p> }
      @for (r of items(); track r.id) {
        <a class="ah-item" [routerLink]="['/approvals/requests', r.id]" [attr.data-request]="r.id">
          <span class="ah-title">{{ r.title ?? r.action_type }}</span>
          <span class="ah-status" [attr.data-status]="r.status">{{ 'approvalRequest.status.' + r.status | translate }}</span>
          <span class="ah-meta">{{ r.requested_by_name ?? r.requested_by }} · {{ r.requested_at | localDate }}</span>
          @if (r.changed_attributes.length > 0) {
            <span class="ah-meta" dir="ltr">{{ r.changed_attributes.join(', ') }}</span>
          }
        </a>
      } @empty {
        @if (!error()) { <p class="ah-muted">{{ 'approvalHistory.none' | translate }}</p> }
      }
      @if (total() > items().length) {
        <p class="ah-muted">{{ 'approvalHistory.more' | translate: { shown: items().length, total: total() } }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .ah { display: flex; flex-direction: column; gap: 0.375rem; }
    .ah-item { display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem; align-items: baseline;
      padding-block: 0.375rem; padding-inline: 0.5rem; border: 1px solid var(--color-border);
      border-radius: 0.375rem; color: inherit; text-decoration: none; }
    .ah-title { font-weight: 600; }
    .ah-status { font-size: 0.75rem; }
    .ah-meta, .ah-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .ah-error { color: var(--color-danger); }
  `],
})
export class ApprovalHistoryPanelComponent {
  private readonly api = inject(ApiService);

  readonly entityName = input.required<string>();
  readonly recordId = input<string | null>(null);

  readonly items = signal<ApprovalHistoryItem[]>([]);
  readonly total = signal(0);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      if (id) this.load(entity, id);
    });
  }

  private load(entity: string, id: string): void {
    this.error.set(null);
    this.api.get<Page<ApprovalHistoryItem>>(
      `/api/v1/approvals/regarding/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`,
      { page_size: String(APPROVAL_HISTORY_PAGE_SIZE) },
    ).subscribe({
      next: page => { this.items.set(page.items); this.total.set(page.total); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
