import { inject, Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';
import { ApiComponents, Page, SdkService } from '@attome/base';

/**
 * M07 / U8 — `state_model`/`state_transition` admin CRUD,
 * `/api/v1/admin/state-models*` (`crates/engine/attome-state/src/admin.rs`,
 * `Authorized<Admin>`, license-gated by the state module).
 *
 * Both updates carry `row_version` in the body; a stale one is a 409
 * `version_conflict`, which the screen shows rather than retrying.
 */
export type StateModelListItem    = ApiComponents['schemas']['StateModelListItem'];
export type StateModelDetail      = ApiComponents['schemas']['StateModelDetail'];
export type StateTransition       = ApiComponents['schemas']['TransitionListItem'];
export type CreateStateModelBody  = ApiComponents['schemas']['CreateStateModelBody'];
export type UpdateStateModelBody  = ApiComponents['schemas']['UpdateStateModelBody'];
export type CreateTransitionBody  = ApiComponents['schemas']['CreateTransitionBody'];
export type UpdateTransitionBody  = ApiComponents['schemas']['UpdateTransitionBody'];
export type StateHistoryChange    = ApiComponents['schemas']['RecordHistoryChange'];
export type StateHistoryPage      = ApiComponents['schemas']['CursorPage_RecordHistoryChange'];

/** The most changes of a record's state the time-in-state view reads at once. */
const STATE_HISTORY_PAGE = 200;

@Injectable({ providedIn: 'root' })
export class StateModelsService {
  private readonly sdk = inject(SdkService);

  /** The route returns every live model in one page (`page_size` = total). */
  listModels(): Observable<StateModelListItem[]> {
    return this.sdk.get<Page<StateModelListItem>>('/api/v1/admin/state-models').pipe(map(p => p.items));
  }

  /** M8-T4: a record's changes to its state field, newest first, by the caller's access. */
  stateHistory(entity: string, recordId: string, field: string): Observable<StateHistoryPage> {
    return this.sdk.get<StateHistoryPage>(
      `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(recordId)}/history`,
      { query: { field, page_size: String(STATE_HISTORY_PAGE) } },
    );
  }

  getModel(id: string): Observable<StateModelDetail> {
    return this.sdk.get<StateModelDetail>(`/api/v1/admin/state-models/${id}`);
  }

  createModel(body: CreateStateModelBody): Observable<StateModelDetail> {
    return this.sdk.post<StateModelDetail>('/api/v1/admin/state-models', { body });
  }

  updateModel(id: string, body: UpdateStateModelBody): Observable<StateModelDetail> {
    return this.sdk.patch<StateModelDetail>(`/api/v1/admin/state-models/${id}`, { body });
  }

  deleteModel(id: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/state-models/${id}`);
  }

  createTransition(modelId: string, body: CreateTransitionBody): Observable<StateTransition> {
    return this.sdk.post<StateTransition>(`/api/v1/admin/state-models/${modelId}/transitions`, { body });
  }

  updateTransition(modelId: string, transitionId: string, body: UpdateTransitionBody): Observable<StateTransition> {
    return this.sdk.patch<StateTransition>(
      `/api/v1/admin/state-models/${modelId}/transitions/${transitionId}`, { body },
    );
  }

  deleteTransition(modelId: string, transitionId: string): Observable<void> {
    return this.sdk.delete(`/api/v1/admin/state-models/${modelId}/transitions/${transitionId}`);
  }
}
