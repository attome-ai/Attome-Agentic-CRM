import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { DECISION_COMMENT_MAX } from '../services/my-approvals.service';

/** `attome_api::approval_process::ChangedAttribute`. */
export interface ChangedAttribute {
  attribute: string;
  from: unknown;
  to: unknown;
}

/** `attome_api::approval_process::DecisionEntry`. */
export interface DecisionEntry {
  approver_id: string;
  approver_name: string | null;
  decided_by: string | null;
  step: number;
  decision: 'approved' | 'rejected';
  comment: string | null;
  decided_at: string;
}

/** `attome_api::approval_process::ApprovalDetail` (`GET /api/v1/approvals/{id}`). */
export interface ApprovalDetail {
  id: string;
  action_type: string;
  title: string | null;
  status: string;
  step: number;
  step_count: number;
  requested_by: string;
  requested_by_name: string | null;
  requested_at: string;
  expires_at: string;
  executed_at: string | null;
  row_version: number;
  reason: string | null;
  regarding_entity: string | null;
  regarding_id: string | null;
  changes: ChangedAttribute[];
  payload: unknown;
  can_decide: boolean;
  decisions: DecisionEntry[];
}

/** A value as the change table shows it: `—` for none, text as written,
 *  anything else as JSON. */
export function showValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/**
 * The approval request page (roadmap M9-T4): what is asked, by whom and
 * why, each attribute change as from → to, every decision so far, and —
 * for an eligible approver while the request waits — approve or reject with
 * an optional comment through `POST /api/v1/approvals/{id}/decide`.
 * Logical CSS only.
 */
@Component({
  selector: 'xrm-approval-request-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, RouterLink, TranslatePipe],
  template: `
    <section class="rq">
      @if (error(); as message) { <p class="rq-error" role="alert">{{ message }}</p> }
      @if (detail(); as d) {
        <header class="rq-head">
          <h2>{{ d.title ?? d.action_type }}</h2>
          <span class="rq-status" [attr.data-status]="d.status">{{ 'approvalRequest.status.' + d.status | translate }}</span>
        </header>
        <dl class="rq-facts">
          <dt>{{ 'approvalRequest.requestedBy' | translate }}</dt>
          <dd>{{ d.requested_by_name ?? d.requested_by }} · {{ d.requested_at | localDate }}</dd>
          @if (d.regarding_entity && d.regarding_id) {
            <dt>{{ 'approvalRequest.record' | translate }}</dt>
            <dd dir="ltr">
              <a class="rq-record" [routerLink]="['/xrm/entity', d.regarding_entity, 'form']" [queryParams]="{ id: d.regarding_id }">
                <code>{{ d.regarding_entity }} / {{ d.regarding_id }}</code>
              </a>
            </dd>
          }
          <dt>{{ 'approvalRequest.step' | translate }}</dt>
          <dd>{{ 'approvalRequest.stepOf' | translate: { step: d.step + 1, count: d.step_count } }}</dd>
          <dt>{{ 'approvalRequest.expires' | translate }}</dt>
          <dd>{{ d.expires_at | localDate }}</dd>
        </dl>

        <h3>{{ 'approvalRequest.why' | translate }}</h3>
        @if (d.reason) {
          <blockquote class="rq-reason" dir="auto">{{ d.reason }}</blockquote>
        } @else {
          <p class="rq-muted">{{ 'approvalRequest.noReason' | translate }}</p>
        }

        @if (d.changes.length > 0) {
          <h3>{{ 'approvalRequest.changes' | translate }}</h3>
          <table class="rq-table">
            <thead>
              <tr>
                <th scope="col">{{ 'approvalRequest.attribute' | translate }}</th>
                <th scope="col">{{ 'approvalRequest.from' | translate }}</th>
                <th scope="col">{{ 'approvalRequest.to' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (c of d.changes; track c.attribute) {
                <tr [attr.data-attribute]="c.attribute">
                  <td dir="ltr"><code>{{ c.attribute }}</code></td>
                  <td class="rq-from" dir="auto">{{ show(c.from) }}</td>
                  <td class="rq-to" dir="auto">{{ show(c.to) }}</td>
                </tr>
              }
            </tbody>
          </table>
        }

        <h3>{{ 'approvalRequest.history' | translate }}</h3>
        <ol class="rq-history">
          <li>{{ 'approvalRequest.submitted' | translate: { who: d.requested_by_name ?? d.requested_by } }} · {{ d.requested_at | localDate }}</li>
          @for (g of d.decisions; track g.approver_id + g.step) {
            <li [attr.data-decision]="g.decision">
              {{ 'approvalRequest.decision.' + g.decision | translate: { who: g.approver_name ?? g.approver_id } }}
              · {{ g.decided_at | localDate }}
              @if (g.comment) { <span class="rq-comment" dir="auto">{{ g.comment }}</span> }
            </li>
          }
          @if (d.executed_at) {
            <li>{{ 'approvalRequest.executed' | translate }} · {{ d.executed_at | localDate }}</li>
          }
        </ol>

        @if (d.can_decide && d.status === 'pending') {
          <div class="rq-decide">
            <label for="rq-comment">{{ 'approvalRequest.comment' | translate }}</label>
            <textarea id="rq-comment" rows="3" [maxlength]="commentMax" [(ngModel)]="comment"></textarea>
            <div class="rq-buttons">
              <button type="button" class="rq-approve" (click)="decide('approve')" [disabled]="busy()">{{ 'approvalRequest.approve' | translate }}</button>
              <button type="button" class="rq-reject" (click)="decide('reject')" [disabled]="busy()">{{ 'approvalRequest.reject' | translate }}</button>
            </div>
          </div>
        }
      } @else if (!error()) {
        <p class="rq-muted">{{ 'approvalRequest.loading' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .rq { display: flex; flex-direction: column; gap: 0.5rem; max-inline-size: 56rem; }
    .rq-head { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
    .rq h2 { margin-block: 0; font-size: 1.25rem; }
    .rq h3 { margin-block: 0.75rem 0.25rem; font-size: 1rem; }
    .rq-status { font-size: 0.8125rem; padding-block: 0.125rem; padding-inline: 0.5rem;
      border: 1px solid var(--color-border); border-radius: 999px; }
    .rq-facts { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; margin: 0; }
    .rq-facts dt { color: var(--color-text-secondary); }
    .rq-facts dd { margin: 0; }
    .rq-reason { margin: 0; padding-inline-start: 0.75rem; border-inline-start: 3px solid var(--color-border); }
    .rq-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .rq-table th, .rq-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .rq-from { color: var(--color-text-secondary); text-decoration: line-through; }
    .rq-to { font-weight: 600; }
    .rq-history { margin: 0; padding-inline-start: 1.25rem; display: flex; flex-direction: column; gap: 0.25rem; }
    .rq-comment { display: block; color: var(--color-text-secondary); font-size: 0.8125rem; }
    .rq-decide { display: flex; flex-direction: column; gap: 0.375rem; margin-block-start: 0.75rem; }
    .rq-buttons { display: flex; gap: 0.5rem; }
    .rq-muted { color: var(--color-text-secondary); font-size: 0.875rem; }
    .rq-error { color: var(--color-danger); }
  `],
})
export class ApprovalRequestPageComponent implements OnInit {
  private readonly api = inject(ApiService);

  /** The request id, bound from the route's `:id`. */
  readonly id = input('');

  readonly detail = signal<ApprovalDetail | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly commentMax = DECISION_COMMENT_MAX;
  comment = '';

  show(value: unknown): string {
    return showValue(value);
  }

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.api.get<ApprovalDetail>(`/api/v1/approvals/${encodeURIComponent(this.id())}`).subscribe({
      next: d => this.detail.set(d),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  decide(decision: 'approve' | 'reject'): void {
    const d = this.detail();
    if (!d) return;
    const body: { decision: string; row_version: number; comment?: string } = {
      decision, row_version: d.row_version,
    };
    const note = this.comment.trim();
    if (note) body.comment = note;
    this.busy.set(true);
    this.api.post<unknown>(`/api/v1/approvals/${encodeURIComponent(d.id)}/decide`, body).subscribe({
      next: () => { this.busy.set(false); this.comment = ''; this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
