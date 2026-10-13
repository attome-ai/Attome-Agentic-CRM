import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, AuthService } from '@attome/base';

import { ApprovalRequestItem, ApprovalsAdminService } from '../../../services/approvals-admin.service';

/**
 * D-195 / `document/detailed-plans/P-four-eyes-approval.md` §5 step 10 — the
 * operator UI this plan's own checklist named as not-yet-built. Lists every
 * `pending` four-eyes approval request (`GET /api/v1/admin/approvals`) and
 * lets an admin approve, reject, or (if they submitted it themselves) cancel
 * one. `payload` is rendered as raw JSON rather than a per-action_type
 * custom view — `attome_approval` itself treats `payload` as opaque
 * (guidelines §1), and a generic admin surface over a growing, open-ended set
 * of action_types (see `approval_admin.rs`'s `KNOWN_ACTION_TYPES`) should not
 * have to grow a bespoke renderer every time a new action is wired.
 *
 * **Not built/verified against a running frontend in this session** — the
 * Angular CLI's Node-version engine gate (`ng build`/`ng test` require
 * Node v22.22.3/v24.15.0/v26.0.0; this sandbox has v24.11.1) blocks both
 * building and unit-testing this component here. Written by hand against
 * `failed-jobs-list.component.ts`'s and `s2s-client-list.component.ts`'s
 * conventions (inline template, shared `../../../../../styles/admin-page.css`, signals, `ApiService`
 * error-kind contract) — review against those before trusting it compiles.
 */
@Component({
  selector:   'xrm-approval-queue-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DatePipe, FormsModule, RouterLink],
  styleUrls:  ['../../../../../styles/admin-page.css', './approval-queue-list.component.css'],
  templateUrl: './approval-queue-list.component.html',
})
export class ApprovalQueueListComponent implements OnInit {
  private readonly svc  = inject(ApprovalsAdminService);
  private readonly auth = inject(AuthService);

  readonly items   = signal<ApprovalRequestItem[]>([]);
  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);
  readonly busyId  = signal<string | null>(null);
  readonly selfId  = this.auth.userId;

  /** D-421 — the request currently showing its inline "delegate to" form,
   *  or `null` when none is open. Only one at a time, same pattern as
   *  `busyId`. */
  readonly delegatingId = signal<string | null>(null);
  readonly delegateTarget = signal('');

  /** Draft decision comments, by request id — optional, sent with Approve
   *  or Reject and stored with the decision. */
  readonly comments = signal<Record<string, string>>({});
  readonly commentMax = 2000;

  setComment(id: string, value: string): void {
    this.comments.update(c => ({ ...c, [id]: value }));
  }

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.list().subscribe({
      next:  res => { this.items.set(res.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  payloadPreview(r: ApprovalRequestItem): string {
    const json = JSON.stringify(r.payload);
    return json.length > 80 ? `${json.slice(0, 80)}…` : json;
  }

  /** D-421 — `null` for a request still running the flat
   *  `required_approvals` model; a short "Step N/M" label otherwise. */
  stepLabel(r: ApprovalRequestItem): string | null {
    if (!r.plan) return null;
    return `Step ${r.step + 1}/${r.plan.steps.length}`;
  }

  approve(r: ApprovalRequestItem): void {
    this.busyId.set(r.id);
    this.svc.approve(r.id, r.row_version, this.comments()[r.id]).subscribe({
      next:  () => { this.busyId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  reject(r: ApprovalRequestItem): void {
    this.busyId.set(r.id);
    this.svc.reject(r.id, r.row_version, this.comments()[r.id]).subscribe({
      next:  () => { this.busyId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  cancel(r: ApprovalRequestItem): void {
    this.busyId.set(r.id);
    this.svc.cancel(r.id, r.row_version).subscribe({
      next:  () => { this.busyId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  /** D-421 — opens/closes the inline "delegate to" form for `r`. Only
   *  offered for a plan-bearing request: the flat `required_approvals`
   *  model has no per-step eligibility to delegate. */
  toggleDelegate(r: ApprovalRequestItem): void {
    if (this.delegatingId() === r.id) {
      this.delegatingId.set(null);
    } else {
      this.delegatingId.set(r.id);
      this.delegateTarget.set('');
    }
  }

  submitDelegate(r: ApprovalRequestItem): void {
    const toUserId = this.delegateTarget().trim();
    if (!toUserId) return;
    this.busyId.set(r.id);
    this.svc.delegate(r.id, toUserId).subscribe({
      next: () => {
        this.busyId.set(null);
        this.delegatingId.set(null);
        this.load();
      },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }
}
