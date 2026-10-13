import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import {
  ApprovalDecision, DECISION_COMMENT_MAX, MyApprovalsService, MyWorkAction, MyWorkItem,
} from '../services/my-approvals.service';

/**
 * "My approvals" (U15) — the approver's own inbox, for any signed-in user,
 * over `GET /api/v1/my-work/approvals`. Approve/Reject call the route each
 * item's own action names; eligibility (named approver, role/team/position
 * member, delegate) is decided server-side at click time, so a 403 or 409
 * there is shown on the item, not swallowed. A decided item leaves the list.
 *
 * Each decision sends the item's own `row_version` (the approval request's
 * current version, so a later plan step decides as cleanly as the first)
 * and the item's optional comment, which the server stores with the
 * decision and its audit event.
 */
@Component({
  selector: 'xrm-my-approvals-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe],
  styleUrls: ['../../../styles/admin-page.css', './my-approvals-page.component.css'],
  templateUrl: './my-approvals-page.component.html',
})
export class MyApprovalsPageComponent implements OnInit {
  private readonly svc  = inject(MyApprovalsService);
  private readonly lang = inject(LangService);

  readonly items       = signal<MyWorkItem[]>([]);
  readonly nextCursor  = signal<string | null>(null);
  readonly loading     = signal(true);
  readonly loadingMore = signal(false);
  readonly loadError   = signal<string | null>(null);
  /** The item a decision is in flight for, by `record_id`. */
  readonly busyId      = signal<string | null>(null);
  /** Per-item decision errors, by `record_id`. */
  readonly itemErrors  = signal<Record<string, string>>({});
  /** Polite announcement of the last successful decision. */
  readonly notice      = signal<string | null>(null);
  /** Draft decision comments, by `record_id`. */
  readonly comments    = signal<Record<string, string>>({});
  readonly commentMax  = DECISION_COMMENT_MAX;

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.loadError.set(null);
    this.itemErrors.set({});
    this.svc.list().subscribe({
      next: page => {
        this.items.set(page.items);
        this.nextCursor.set(page.next_cursor ?? null);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.loadError.set(this.errorText(e));
        this.loading.set(false);
      },
    });
  }

  loadMore(): void {
    const cursor = this.nextCursor();
    if (!cursor || this.loadingMore()) return;
    this.loadingMore.set(true);
    this.svc.list(cursor).subscribe({
      next: page => {
        this.items.update(items => [...items, ...page.items]);
        this.nextCursor.set(page.next_cursor ?? null);
        this.loadingMore.set(false);
      },
      error: (e: ApiError) => {
        this.loadError.set(this.errorText(e));
        this.loadingMore.set(false);
      },
    });
  }

  actionFor(item: MyWorkItem, key: ApprovalDecision): MyWorkAction | undefined {
    return item.actions.find(a => a.key === key);
  }

  /** Only an item that carries its `row_version` can be decided here. */
  canDecide(item: MyWorkItem): boolean {
    return typeof item.row_version === 'number';
  }

  setComment(id: string, value: string): void {
    this.comments.update(c => ({ ...c, [id]: value }));
  }

  decide(item: MyWorkItem, decision: ApprovalDecision): void {
    const action = this.actionFor(item, decision);
    const rowVersion = item.row_version;
    if (!action || typeof rowVersion !== 'number' || this.busyId()) return;
    this.busyId.set(item.record_id);
    this.notice.set(null);
    this.setItemError(item.record_id, null);
    this.svc.decide(action, decision, rowVersion, this.comments()[item.record_id]).subscribe({
      next: () => {
        this.busyId.set(null);
        this.items.update(items => items.filter(i => i.record_id !== item.record_id));
        this.comments.update(c => {
          const next = { ...c };
          delete next[item.record_id];
          return next;
        });
        this.notice.set(this.lang.translate(
          decision === 'approve' ? 'myApprovals.approved' : 'myApprovals.rejected',
          { title: item.title },
        ));
      },
      error: (e: ApiError) => {
        this.busyId.set(null);
        this.setItemError(item.record_id, this.errorText(e));
      },
    });
  }

  private setItemError(id: string, message: string | null): void {
    this.itemErrors.update(errors => {
      const next = { ...errors };
      if (message) next[id] = message;
      else delete next[id];
      return next;
    });
  }

  private errorText(e: ApiError): string {
    switch (e.kind) {
      case 'forbidden':        return this.lang.translate('myApprovals.error.forbidden');
      case 'conflict':
      case 'version_conflict': return this.lang.translate('myApprovals.error.conflict');
      case 'not_found':        return this.lang.translate('myApprovals.error.notFound');
      default:                 return e.message || this.lang.translate('myApprovals.error.failed');
    }
  }
}
