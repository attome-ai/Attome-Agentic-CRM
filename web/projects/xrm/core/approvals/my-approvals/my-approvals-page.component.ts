import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import {
  ApprovalDecision, BULK_DECIDE_MAX, BulkDecideResult, DECISION_COMMENT_MAX, MyApprovalsService,
  MyWorkAction, MyWorkItem,
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
  /** Z10-T13: the items ticked for a bulk decision, by `record_id`. */
  readonly selected    = signal<ReadonlySet<string>>(new Set());
  /** The last bulk decision's outcome per request. */
  readonly bulkResults = signal<BulkDecideResult[]>([]);
  readonly bulkBusy    = signal(false);
  readonly bulkMax     = BULK_DECIDE_MAX;

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

  /** Z10-T13: ticks or clears one item for a bulk decision. */
  toggle(item: MyWorkItem): void {
    if (!this.canDecide(item)) return;
    this.selected.update(set => {
      const next = new Set(set);
      if (next.has(item.record_id)) next.delete(item.record_id);
      else if (next.size < BULK_DECIDE_MAX) next.add(item.record_id);
      return next;
    });
  }

  /**
   * Z10-T13: decides every ticked item the same way. Each is decided on its
   * own server-side; a step that asks for a fresh sign-in or a signature is
   * skipped and stays in the list with its reason.
   */
  bulkDecide(decision: ApprovalDecision): void {
    const picked = this.items().filter(
      i => this.selected().has(i.record_id) && typeof i.row_version === 'number',
    );
    if (picked.length === 0 || this.bulkBusy()) return;
    this.bulkBusy.set(true);
    this.notice.set(null);
    const items = picked.map(i => ({ id: i.record_id, row_version: i.row_version as number }));
    this.svc.bulkDecide(items, decision).subscribe({
      next: ({ results }) => {
        this.bulkBusy.set(false);
        this.bulkResults.set(results);
        const decided = new Set(
          results.filter(r => r.status !== 'skipped' && r.status !== 'failed').map(r => r.id),
        );
        this.items.update(list => list.filter(i => !decided.has(i.record_id)));
        this.selected.set(new Set());
        this.notice.set(this.lang.translate('myApprovals.bulk.done', {
          decided: decided.size, total: results.length,
        }));
      },
      error: (e: ApiError) => {
        this.bulkBusy.set(false);
        this.loadError.set(this.errorText(e));
      },
    });
  }

  /** The bulk outcome shown on an item that was not decided. */
  bulkResultFor(id: string): BulkDecideResult | undefined {
    return this.bulkResults().find(r => r.id === id && (r.status === 'skipped' || r.status === 'failed'));
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
