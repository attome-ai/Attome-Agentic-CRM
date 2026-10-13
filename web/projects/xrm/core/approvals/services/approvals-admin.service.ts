import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Response types (mirror attome_api::approval_admin::ApprovalRequestView /
// attome_approval::ApprovalRequest exactly — crates/engine/attome-api/src/approval_admin.rs) ──

/** D-421 — mirrors `attome_approval::StepMode`. */
export type StepMode = 'any' | 'all' | 'n_of_m';

/** D-421 — mirrors `attome_approval::OnTimeout`. */
export type OnTimeout = 'escalate' | 'auto_approve' | 'auto_reject';

/** D-421 — mirrors `attome_approval::ApprovalStep`. `approvers` are opaque
 *  tokens (`"user:<uuid>"`/`"role:<uuid>"` are the only ones this release
 *  resolves — see `attome_audit::approval::validate_approver_token`). */
export interface ApprovalStep {
  mode:         StepMode;
  threshold:    number | null;
  approvers:    string[];
  sla_minutes:  number | null;
  on_timeout:   OnTimeout;
}

/** D-421 — mirrors `attome_approval::ApprovalPlan`. */
export interface ApprovalPlan {
  steps: ApprovalStep[];
}

export interface ApprovalRequestItem {
  id:                  string;
  action_type:         string;
  payload:             unknown;
  requested_by:        string;
  requested_at:        string;
  status:              string;
  required_approvals:  number;
  row_version:         number;
  expires_at:          string;
  executed_at:         string | null;
  /** D-421 — `null` for a request still running the original flat
   *  `required_approvals` model; present only when a policy (or a workflow
   *  approval node consulting one) supplied a multi-step plan. */
  plan:                ApprovalPlan | null;
  step:                number;
  step_started_at:     string | null;
  escalated_at:        string | null;
  policy_id:           string | null;
}

export interface ApprovalRequestsPage {
  items:     ApprovalRequestItem[];
  total:     number;
  page:      number;
  page_size: number;
}

export interface DecideResponse {
  id:       string;
  status:   string;
  executed: unknown;
}

/** D-421 — mirrors `attome_api::approval_policy_admin::ApprovalPolicyView`. */
export interface ApprovalPolicy {
  id:          string;
  name:        string;
  is_active:   boolean;
  action_type: string;
  /** M45 expression string — schema-ready, never evaluated in this release. */
  condition:   string | null;
  plan:        ApprovalPlan;
  row_version: number;
  created_at:  string;
  updated_at:  string;
  created_by:  string;
}

export interface ApprovalPoliciesPage {
  items:     ApprovalPolicy[];
  total:     number;
  page:      number;
  page_size: number;
}

export interface CreateApprovalPolicyBody {
  name:        string;
  is_active?:  boolean;
  action_type: string;
  condition?:  string | null;
  plan:        ApprovalPlan;
}

export interface UpdateApprovalPolicyBody {
  name?:       string;
  is_active?:  boolean;
  condition?:  string | null;
  plan?:       ApprovalPlan;
  row_version: number;
}

@Injectable({ providedIn: 'root' })
export class ApprovalsAdminService {
  private readonly api = inject(ApiService);

  /** Always `status = "pending"` server-side (`attome_approval::list_pending`)
   *  — this is deliberately the only queue view; a decided/expired/cancelled
   *  request stops showing up here but is never deleted (its row is its own
   *  audit trail). */
  list(page = 1, pageSize = 50, actionType?: string): Observable<ApprovalRequestsPage> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (actionType) params['action_type'] = actionType;
    return this.api.get<ApprovalRequestsPage>('/api/v1/admin/approvals', params);
  }

  approve(id: string, rowVersion: number, comment?: string | null): Observable<DecideResponse> {
    return this.decide(id, 'approve', rowVersion, comment);
  }

  reject(id: string, rowVersion: number, comment?: string | null): Observable<DecideResponse> {
    return this.decide(id, 'reject', rowVersion, comment);
  }

  /** The optional decision `comment` (at most 2000 characters, stored with
   *  the decision and its audit event) is trimmed and sent only when it is
   *  not blank. */
  private decide(
    id: string, decision: 'approve' | 'reject', rowVersion: number, comment?: string | null,
  ): Observable<DecideResponse> {
    const body: { decision: string; row_version: number; comment?: string } = {
      decision, row_version: rowVersion,
    };
    const note = comment?.trim();
    if (note) body.comment = note;
    return this.api.post<DecideResponse>(`/api/v1/admin/approvals/${id}/decide`, body);
  }

  /** Only the request's own `requested_by` may cancel it — a different admin
   *  gets a 403 (`attome_approval::cancel`'s separation-of-duties check, the
   *  inverse of `decide()`'s). */
  cancel(id: string, rowVersion: number): Observable<ApprovalRequestItem> {
    return this.api.post<ApprovalRequestItem>(`/api/v1/admin/approvals/${id}/cancel`, {
      row_version: rowVersion,
    });
  }

  /** D-421 — hands the caller's own standing on this request's current plan
   *  step to `toUserId`. Only valid on a plan-bearing request; the caller
   *  must actually be one of that step's named approvers
   *  (`attome_audit::approval::create_request_delegation`'s `Forbidden`
   *  otherwise), and delegating to the request's own requester is rejected
   *  with `422` — D-421's core invariant, that a delegation can never
   *  manufacture a path to self-approval. */
  delegate(id: string, toUserId: string, validTo?: string): Observable<{ delegation_id: string }> {
    return this.api.post<{ delegation_id: string }>(`/api/v1/admin/approvals/${id}/delegate`, {
      to_user_id: toUserId, valid_to: validTo ?? null,
    });
  }

  // ── D-421 — approval policies ─────────────────────────────────────────

  listPolicies(page = 1, pageSize = 50, actionType?: string): Observable<ApprovalPoliciesPage> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (actionType) params['action_type'] = actionType;
    return this.api.get<ApprovalPoliciesPage>('/api/v1/admin/approval-policies', params);
  }

  getPolicy(id: string): Observable<ApprovalPolicy> {
    return this.api.get<ApprovalPolicy>(`/api/v1/admin/approval-policies/${id}`);
  }

  createPolicy(body: CreateApprovalPolicyBody): Observable<ApprovalPolicy> {
    return this.api.post<ApprovalPolicy>('/api/v1/admin/approval-policies', body);
  }

  updatePolicy(id: string, body: UpdateApprovalPolicyBody): Observable<ApprovalPolicy> {
    return this.api.put<ApprovalPolicy>(`/api/v1/admin/approval-policies/${id}`, body);
  }

  deletePolicy(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/approval-policies/${id}`);
  }
}
