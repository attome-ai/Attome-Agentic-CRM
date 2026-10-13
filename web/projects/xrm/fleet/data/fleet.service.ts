import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { Page } from '@attome/base';
import { StepUpService } from '@attome/base/step-up';
import type {
  ActionView, ApplyTargetBody, ChangesetFile, CredentialBody, DeploymentView, FleetReleaseReport,
  FleetReportItem, ItemDecision, OpenItemView, RegisterDeploymentBody, RolloutDetail, RolloutView,
  SetCredentialBody, StartRolloutBody, StepsQueued, SyncQueued, TargetView, UpdateDeploymentBody,
} from './fleet.types';

/** Every console route lives under this prefix (D-792). */
export const FLEET_API = '/api/v1/fleet';

/**
 * The step-up operation the server asks for on publish and credential
 * changes. `attome_fleet::routes::STEP_UP_OPERATION` reuses attome-auth's
 * 15-minute `api_key_create` elevation until a dedicated operation exists;
 * keep the two equal (`fleet.service.spec.ts` pins it).
 */
export const FLEET_STEP_UP_OPERATION = 'api_key_create';

/** The largest page the server serves (`attome_types::MAX_PAGE_SIZE`). */
export const FLEET_MAX_PAGE_SIZE = 200;

export interface ItemFilter {
  status?: string;
  kind?:   string;
}

function pageParams(page: number, pageSize: number): Record<string, string> {
  return { page: String(page), page_size: String(pageSize) };
}

/**
 * The fleet console's HTTP client (`/api/v1/fleet/**`). Every list is
 * one-based (`OnePageQuery`). The server owns every check: loopback only,
 * `system.admin`, a cookie session, and a fresh MFA step-up for publish and
 * credential changes. Calls that can answer `reauth_required` go through
 * `StepUpService.run`, which opens the app's step-up prompt and retries the
 * call once after the user confirms. A refused first call changed nothing on
 * the server, so the single retry is safe.
 */
@Injectable({ providedIn: 'root' })
export class FleetService {
  private readonly api    = inject(ApiService);
  private readonly stepUp = inject(StepUpService);

  private guarded<T>(request: () => Observable<T>): Observable<T> {
    return this.stepUp.run(FLEET_STEP_UP_OPERATION, request);
  }

  // ── Deployments ─────────────────────────────────────────────────────────

  listDeployments(includeInactive: boolean, page: number, pageSize: number): Observable<Page<DeploymentView>> {
    return this.api.get<Page<DeploymentView>>(`${FLEET_API}/deployments`, {
      ...pageParams(page, pageSize),
      include_inactive: String(includeInactive),
    });
  }

  /** Every deployment (for pickers), walked page by page. */
  allDeployments(includeInactive: boolean): Observable<DeploymentView[]> {
    return this.api.getAllPages<DeploymentView>(
      `${FLEET_API}/deployments`,
      { include_inactive: String(includeInactive) },
      FLEET_MAX_PAGE_SIZE,
      undefined,
      1,
    );
  }

  getDeployment(id: string): Observable<DeploymentView> {
    return this.api.get<DeploymentView>(`${FLEET_API}/deployments/${encodeURIComponent(id)}`);
  }

  /** Step-up only when a credential is included; `run` prompts only if the server asks. */
  registerDeployment(body: RegisterDeploymentBody): Observable<DeploymentView> {
    return this.guarded(() => this.api.post<DeploymentView>(`${FLEET_API}/deployments`, body));
  }

  /** Moving a deployment that holds a credential (a new `base_url`) needs a step-up. */
  updateDeployment(id: string, body: UpdateDeploymentBody): Observable<DeploymentView> {
    return this.guarded(() =>
      this.api.patch<DeploymentView>(`${FLEET_API}/deployments/${encodeURIComponent(id)}`, body));
  }

  setCredential(id: string, rowVersion: number, credential: CredentialBody, verify: boolean): Observable<DeploymentView> {
    const body: SetCredentialBody = { row_version: rowVersion, ...credential, verify };
    return this.guarded(() =>
      this.api.put<DeploymentView>(`${FLEET_API}/deployments/${encodeURIComponent(id)}/credential`, body));
  }

  syncDeployment(id: string): Observable<DeploymentView> {
    return this.api.post<DeploymentView>(`${FLEET_API}/deployments/${encodeURIComponent(id)}/sync`, {});
  }

  syncAll(): Observable<SyncQueued> {
    return this.api.post<SyncQueued>(`${FLEET_API}/sync`, {});
  }

  listActions(id: string, page: number, pageSize: number): Observable<Page<ActionView>> {
    return this.api.get<Page<ActionView>>(
      `${FLEET_API}/deployments/${encodeURIComponent(id)}/actions`, pageParams(page, pageSize));
  }

  // ── Changesets ──────────────────────────────────────────────────────────

  /** Every closed changeset file under `fleet.changesets_dir`, platform first. */
  allChangesets(): Observable<ChangesetFile[]> {
    return this.api.getAllPages<ChangesetFile>(`${FLEET_API}/changesets`, {}, FLEET_MAX_PAGE_SIZE, undefined, 1);
  }

  // ── Release reports (read from the customer) ─────────────────────────────

  listReports(deploymentId: string, status: string | null, page: number, pageSize: number): Observable<Page<FleetReleaseReport>> {
    const params = pageParams(page, pageSize);
    if (status) params['status'] = status;
    return this.api.get<Page<FleetReleaseReport>>(
      `${FLEET_API}/deployments/${encodeURIComponent(deploymentId)}/release-reports`, params);
  }

  listItems(
    deploymentId: string, reportId: string, filter: ItemFilter, page: number, pageSize: number,
  ): Observable<Page<FleetReportItem>> {
    const params = pageParams(page, pageSize);
    if (filter.status) params['status'] = filter.status;
    if (filter.kind) params['kind'] = filter.kind;
    return this.api.get<Page<FleetReportItem>>(
      `${FLEET_API}/deployments/${encodeURIComponent(deploymentId)}/release-reports/${encodeURIComponent(reportId)}/items`,
      params,
    );
  }

  openItems(page: number, pageSize: number): Observable<Page<OpenItemView>> {
    return this.api.get<Page<OpenItemView>>(`${FLEET_API}/open-items`, pageParams(page, pageSize));
  }

  /**
   * Accept, Use mine or Dismiss, sent to the customer with the item's
   * `row_version` (and, for Use mine on a record conflict, the record's).
   * The answer is the customer's decided item.
   */
  decideItem(
    deploymentId: string, itemId: string, decision: ItemDecision, rowVersion: number,
    recordRowVersion: number | null = null,
  ): Observable<FleetReportItem> {
    const body = decision === 'use-mine'
      ? { row_version: rowVersion, record_row_version: recordRowVersion }
      : { row_version: rowVersion };
    return this.api.post<FleetReportItem>(
      `${FLEET_API}/deployments/${encodeURIComponent(deploymentId)}/release-report-items/${encodeURIComponent(itemId)}/${decision}`,
      body,
    );
  }

  // ── Rollouts ────────────────────────────────────────────────────────────

  listRollouts(page: number, pageSize: number): Observable<Page<RolloutView>> {
    return this.api.get<Page<RolloutView>>(`${FLEET_API}/rollouts`, pageParams(page, pageSize));
  }

  startRollout(body: StartRolloutBody): Observable<RolloutDetail> {
    return this.guarded(() => this.api.post<RolloutDetail>(`${FLEET_API}/rollouts`, body));
  }

  getRollout(id: string): Observable<RolloutDetail> {
    return this.api.get<RolloutDetail>(`${FLEET_API}/rollouts/${encodeURIComponent(id)}`);
  }

  applyTarget(rolloutId: string, targetId: string, body: ApplyTargetBody): Observable<TargetView> {
    return this.guarded(() => this.api.post<TargetView>(
      `${FLEET_API}/rollouts/${encodeURIComponent(rolloutId)}/targets/${encodeURIComponent(targetId)}/apply`, body));
  }

  skipTarget(rolloutId: string, targetId: string, rowVersion: number): Observable<TargetView> {
    return this.api.post<TargetView>(
      `${FLEET_API}/rollouts/${encodeURIComponent(rolloutId)}/targets/${encodeURIComponent(targetId)}/skip`,
      { row_version: rowVersion },
    );
  }

  haltRollout(id: string, rowVersion: number): Observable<RolloutDetail> {
    return this.api.post<RolloutDetail>(
      `${FLEET_API}/rollouts/${encodeURIComponent(id)}/halt`, { row_version: rowVersion });
  }

  resumeRollout(id: string, rowVersion: number): Observable<RolloutDetail> {
    return this.guarded(() => this.api.post<RolloutDetail>(
      `${FLEET_API}/rollouts/${encodeURIComponent(id)}/resume`, { row_version: rowVersion }));
  }

  cancelRollout(id: string, rowVersion: number): Observable<RolloutDetail> {
    return this.api.post<RolloutDetail>(
      `${FLEET_API}/rollouts/${encodeURIComponent(id)}/cancel`, { row_version: rowVersion });
  }

  refreshRollout(id: string): Observable<StepsQueued> {
    return this.api.post<StepsQueued>(`${FLEET_API}/rollouts/${encodeURIComponent(id)}/refresh`, {});
  }
}
