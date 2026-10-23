import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

import type { ChangedAttribute } from '../request-page/request-page.component';
import { showValue } from '../request-page/request-page.component';
import { DECISION_COMMENT_MAX } from '../services/my-approvals.service';

/** `attome_api::approval_email::LinkView`. */
export interface ApprovalLinkView {
  request_id: string;
  action_type: string;
  title: string | null;
  status: string;
  requested_by_name: string | null;
  requested_at: string;
  reason: string | null;
  changes: ChangedAttribute[];
  decide_here: boolean;
  link_expires_at: string;
}

/**
 * The page an emailed approval link opens (roadmap M9-T3), public: the
 * token sits in the URL fragment, so it never reaches a server log. A
 * low-risk request is approved or rejected here, once; any other request
 * only offers to open the request page, which needs sign-in.
 */
@Component({
  selector: 'xrm-approval-link-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <main class="al">
      <h1>{{ 'approvalLink.title' | translate }}</h1>
      @if (error(); as message) { <p class="al-error" role="alert">{{ message }}</p> }
      @if (invalid()) { <p class="al-error" role="alert">{{ 'approvalLink.invalid' | translate }}</p> }
      @if (done(); as status) {
        <p class="al-done" role="status">{{ 'approvalLink.done.' + status | translate }}</p>
      } @else if (view(); as v) {
        <h2>{{ v.title ?? v.action_type }}</h2>
        <p class="al-muted">{{ v.requested_by_name ?? '' }} · {{ v.requested_at | localDate }}</p>
        @if (v.reason) { <blockquote class="al-reason" dir="auto">{{ v.reason }}</blockquote> }
        @if (v.changes.length > 0) {
          <ul class="al-changes">
            @for (c of v.changes; track c.attribute) {
              <li [attr.data-attribute]="c.attribute">
                <code dir="ltr">{{ c.attribute }}</code>: <span dir="auto">{{ show(c.from) }}</span> → <strong dir="auto">{{ show(c.to) }}</strong>
              </li>
            }
          </ul>
        }
        @if (v.decide_here) {
          <label for="al-comment">{{ 'approvalRequest.comment' | translate }}</label>
          <textarea id="al-comment" rows="3" [maxlength]="commentMax" [(ngModel)]="comment"></textarea>
          <div class="al-buttons">
            <button type="button" class="al-approve" (click)="decide('approve')" [disabled]="busy()">{{ 'approvalRequest.approve' | translate }}</button>
            <button type="button" class="al-reject" (click)="decide('reject')" [disabled]="busy()">{{ 'approvalRequest.reject' | translate }}</button>
          </div>
          <p class="al-muted">{{ 'approvalLink.once' | translate: { date: (v.link_expires_at | localDate) } }}</p>
        } @else {
          <p>{{ 'approvalLink.signIn' | translate }}</p>
          <button type="button" class="al-open" (click)="open(v)">{{ 'approvalLink.open' | translate }}</button>
        }
      } @else if (!error() && !invalid()) {
        <p class="al-muted">{{ 'approvalRequest.loading' | translate }}</p>
      }
    </main>
  `,
  styles: [`
    :host { display: block; }
    .al { max-inline-size: 40rem; margin-inline: auto; padding: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .al h1 { font-size: 1.25rem; margin-block: 0; }
    .al h2 { font-size: 1.0625rem; margin-block: 0.5rem 0; }
    .al-reason { margin: 0; padding-inline-start: 0.75rem; border-inline-start: 3px solid var(--color-border); }
    .al-changes { margin: 0; padding-inline-start: 1.25rem; }
    .al-buttons { display: flex; gap: 0.5rem; }
    .al-muted { color: var(--color-text-secondary); font-size: 0.875rem; }
    .al-error { color: var(--color-danger); }
  `],
})
export class ApprovalLinkPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  readonly view = signal<ApprovalLinkView | null>(null);
  readonly done = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly invalid = signal(false);
  readonly busy = signal(false);
  readonly commentMax = DECISION_COMMENT_MAX;
  comment = '';
  private token = '';

  show(value: unknown): string {
    return showValue(value);
  }

  ngOnInit(): void {
    this.token = (this.route.snapshot.fragment ?? '').trim();
    if (!this.token) {
      this.invalid.set(true);
      return;
    }
    this.api.post<ApprovalLinkView>('/api/v1/approvals/email-link', { token: this.token }).subscribe({
      next: v => this.view.set(v),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  decide(decision: 'approve' | 'reject'): void {
    const body: { token: string; decision: string; comment?: string } = { token: this.token, decision };
    const note = this.comment.trim();
    if (note) body.comment = note;
    this.busy.set(true);
    this.api.post<{ request_id: string; status: string }>('/api/v1/approvals/email-link/decide', body).subscribe({
      next: r => { this.busy.set(false); this.done.set(r.status); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  open(v: ApprovalLinkView): void {
    void this.router.navigate(['/xrm/approvals/requests', v.request_id]);
  }
}
