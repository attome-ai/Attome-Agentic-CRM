import { inject, Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

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

@Injectable({ providedIn: 'root' })
export class StateModelsService {
  private readonly api = inject(ApiService);

  /** The route returns every live model in one page (`page_size` = total). */
  listModels(): Observable<StateModelListItem[]> {
    return this.api.get<Page<StateModelListItem>>('/api/v1/admin/state-models').pipe(map(p => p.items));
  }

  getModel(id: string): Observable<StateModelDetail> {
    return this.api.get<StateModelDetail>(`/api/v1/admin/state-models/${id}`);
  }

  createModel(body: CreateStateModelBody): Observable<StateModelDetail> {
    return this.api.post<StateModelDetail>('/api/v1/admin/state-models', body);
  }

  updateModel(id: string, body: UpdateStateModelBody): Observable<StateModelDetail> {
    return this.api.patch<StateModelDetail>(`/api/v1/admin/state-models/${id}`, body);
  }

  deleteModel(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/state-models/${id}`);
  }

  createTransition(modelId: string, body: CreateTransitionBody): Observable<StateTransition> {
    return this.api.post<StateTransition>(`/api/v1/admin/state-models/${modelId}/transitions`, body);
  }

  updateTransition(modelId: string, transitionId: string, body: UpdateTransitionBody): Observable<StateTransition> {
    return this.api.patch<StateTransition>(
      `/api/v1/admin/state-models/${modelId}/transitions/${transitionId}`, body,
    );
  }

  deleteTransition(modelId: string, transitionId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/state-models/${modelId}/transitions/${transitionId}`);
  }
}
