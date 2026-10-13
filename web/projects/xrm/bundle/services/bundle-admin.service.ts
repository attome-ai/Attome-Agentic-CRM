import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Response/request types (mirror crates/engine/attome-api/src/bundle/{routes,
//    plan,ledger}.rs exactly — M92 Phase 1 lifecycle UI). Hand-declared
//    rather than imported from the generated `api-types.ts`, same convention
//    `S2sAdminService` already established in this workspace. ──────────────

export type PlanStatus = 'planned' | 'queued' | 'claimed' | 'applying' | 'succeeded' | 'failed';

export type PlanAction = 'create' | 'update' | 'retire' | 'noop' | 'blocked';

/** One object's line in a plan (`PlanEntry`). */
export interface PlanEntry {
  component: string;
  key:       string;
  action:    PlanAction;
  reason?:   string | null;
  changes?:  string[];
}

export interface PlanSummary {
  creates: number;
  updates: number;
  retires: number;
  noops:   number;
  blocked: number;
}

/** `GET …/plans` list row (`routes::PlanListItem`). */
export interface PlanListItem {
  id:               string;
  status:           PlanStatus;
  bundle_hash:      string;
  basis_hash:       string;
  format_version:   string;
  platform_version: string;
  allow_retire:     boolean;
  bundle_name:      string | null;
  bundle_version:   string | null;
  requested_by:     string | null;
  approval_ref:     string | null;
  cursor:           number;
  applied_count:    number;
  error_message:    string | null;
  created_at:       string;
  claimed_at:       string | null;
  finished_at:      string | null;
}

/** `GET …/plans/{id}` full row (`ledger::PlanRow`) — adds the stored payloads. */
export interface PlanDetail extends PlanListItem {
  bundle: Record<string, unknown>;
  plan:   Record<string, unknown>;
}

export interface AppliedRef {
  plan_id:     string;
  bundle_hash: string;
  finished_at: string | null;
}

export interface DriftDiff {
  live_hash: string;
  summary:   PlanSummary;
  entries:   PlanEntry[];
  retires:   PlanEntry[];
  blocked:   PlanEntry[];
  clean:     boolean;
}

export interface DriftReport {
  applied: AppliedRef | null;
  drift:   DriftDiff | null;
}

/** `mode=apply` / rollback 202 reply (`routes::ApplyAccepted`). */
export interface ApplyAccepted {
  plan_id:               string;
  status:                PlanStatus;
  approval_pending:      boolean;
  approval_request_id:   string | null;
}

export interface RollbackBody {
  to_version:    string;
  allow_retire?: boolean;
}

@Injectable({ providedIn: 'root' })
export class BundleAdminService {
  private readonly api = inject(ApiService);

  /** Newest first. `status` narrows to one lifecycle state (e.g. `succeeded`
   * for "installed bundles", `planned`/`queued` for "pending plans"). */
  listPlans(status?: PlanStatus): Observable<PlanListItem[]> {
    return this.api.getAllPages<PlanListItem>(
      '/api/v1/admin/metadata/plans',
      status ? { status } : {},
    );
  }

  getPlan(id: string): Observable<PlanDetail> {
    return this.api.get<PlanDetail>(`/api/v1/admin/metadata/plans/${id}`);
  }

  getDrift(): Observable<DriftReport> {
    return this.api.get<DriftReport>('/api/v1/admin/metadata/drift');
  }

  /** `POST …/bundles/{name}/rollback` — undo = re-apply the ledger's own
   * prior snapshot of a named bundle at `to_version` (verticals skill,
   * "Undoing an applied bundle"), through the ordinary plan/apply/approval
   * gates. `name` is a path segment; `encodeURIComponent` mirrors
   * `bundle-tool`'s own `encode_segment` so an odd bundle name round-trips
   * the same way from either client. */
  rollback(name: string, body: RollbackBody): Observable<ApplyAccepted> {
    return this.api.post<ApplyAccepted>(
      `/api/v1/admin/metadata/bundles/${encodeURIComponent(name)}/rollback`,
      body,
    );
  }
}
