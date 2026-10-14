import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Wire types (mirror attome_api::model_admin's FormPlan exactly) ──

export interface FormPlanField {
  /** The attribute's logical name: the key of its value in a record. */
  attribute:  string;
  label:      string;
  /** The attribute's field type number (attome_core::FieldType). */
  field_type: number;
  required:   boolean;
}

export interface FormPlanSection {
  label:  string;
  fields: FormPlanField[];
}

export interface FormPlan {
  id:       string;
  name:     string;
  /** The entity's logical name, as the record API addresses it. */
  entity:   string;
  sections: FormPlanSection[];
}

/** A record as the generic entity API returns it: values under `data`. */
export interface RecordView {
  id:          string;
  row_version: number;
  data:        Record<string, unknown>;
}

/** The published metadata model, as the renderer reads it (roadmap Y14). */
@Injectable({ providedIn: 'root' })
export class ModelService {
  private readonly api = inject(ApiService);

  /** A published form's render plan. */
  formPlan(formId: string): Observable<FormPlan> {
    return this.api.get<FormPlan>(`/api/v1/model/forms/${encodeURIComponent(formId)}/plan`);
  }

  record(entity: string, id: string): Observable<RecordView> {
    return this.api.get<RecordView>(`/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`);
  }

  /** Saves changed values; `rowVersion` guards against a lost update. */
  updateRecord(entity: string, id: string, values: Record<string, unknown>, rowVersion: number): Observable<RecordView> {
    return this.api.patch<RecordView>(
      `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`,
      values,
      rowVersion,
    );
  }
}
