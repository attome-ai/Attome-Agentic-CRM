import { inject, Injectable } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents, ApiError } from '@attome/base';

type Schemas = ApiComponents['schemas'];

export type MyWorkItem = Schemas['MyWorkItem'];
export type MyWorkAction = Schemas['MyWorkAction'];
export type MyWorkPage = Schemas['MyWorkPage'];
/** `POST /api/v1/approvals/{id}/decide` (200). */
export type ApprovalDecisionResponse = Schemas['DecideResponse'];
/** `POST /api/v1/approvals/{id}/decide` request body. */
export type ApprovalDecisionBody = Schemas['DecideBody'];
export type ApprovalDecision = 'approve' | 'reject';

/** The longest decision comment the decide route accepts, in characters
 *  (`attome_approval::MAX_DECISION_COMMENT_CHARS`). */
export const DECISION_COMMENT_MAX = 2000;

/**
 * The approver's own inbox (U15): the caller's pending approvals from the
 * My Work `approvals` provider, decided through the route each item's own
 * action names (`/api/v1/approvals/{id}/decide`, eligibility enforced
 * server-side) — never the admin queue's `/api/v1/admin/...` routes.
 */
@Injectable({ providedIn: 'root' })
export class MyApprovalsService {
  private readonly api = inject(ApiService);

  list(cursor?: string | null, limit = 50): Observable<MyWorkPage> {
    const params: Record<string, string> = { limit: String(limit) };
    if (cursor) params['cursor'] = cursor;
    return this.api.get<MyWorkPage>('/api/v1/my-work/approvals', params);
  }

  /**
   * Invokes `action.route` — the provider's authoritative route, ids already
   * substituted. Refuses anything but a POST to an `/api/v1/` path, so a
   * malformed action can never send the decision somewhere else.
   *
   * `rowVersion` is the item's own `row_version` (the approval request's
   * current version); a stale one is a 409 the caller surfaces. `comment`
   * is trimmed and sent only when it is not blank.
   */
  decide(
    action: MyWorkAction, decision: ApprovalDecision, rowVersion: number, comment?: string | null,
  ): Observable<ApprovalDecisionResponse> {
    if (action.method.toUpperCase() !== 'POST' || !action.route.startsWith('/api/v1/')) {
      const error: ApiError = { kind: 'validation', status: 0, message: 'Unsupported approval action.' };
      return throwError(() => error);
    }
    const body: ApprovalDecisionBody = { decision, row_version: rowVersion };
    const note = comment?.trim();
    if (note) body.comment = note;
    return this.api.post<ApprovalDecisionResponse>(action.route, body);
  }
}
