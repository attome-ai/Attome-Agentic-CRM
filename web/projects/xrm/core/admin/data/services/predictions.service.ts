import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// M36 Phase 0+1 (Predictive Intelligence, D-473) — mirrors
// attome_predict::predictions::PredictionSummary exactly
// (crates/engine/attome-predict/src/predictions.rs).

export interface FeatureContribution {
  key: string;
  value: number;
  contribution: number;
}

export interface Prediction {
  id: string;
  model_ref: string;
  regarding_entity: string;
  regarding_id: string;
  score: number;
  label: string;
  explanation: FeatureContribution[] | null;
  predicted_at: string;
  horizon_at: string;
  /** `true` once the outcome-fill sweep has recorded whether this
   *  prediction actually came true. */
  resolved: boolean;
}

export interface PredictionsPage {
  items: Prediction[]; total: number; page: number; page_size: number;
}

@Injectable({ providedIn: 'root' })
export class PredictionsService {
  private readonly api = inject(ApiService);

  /** The record banner's/widget's own read — no `Admin` gate server-side,
   *  only the caller's own `{regardingEntity}.read` (`predictions.rs`'s own
   *  module doc). Newest first. */
  forRecord(regardingEntity: string, regardingId: string, pageSize = 5): Observable<PredictionsPage> {
    return this.api.get<PredictionsPage>('/api/v1/predictions', {
      regarding_entity: regardingEntity,
      regarding_id: regardingId,
      page: '1',
      page_size: String(pageSize),
    });
  }
}
