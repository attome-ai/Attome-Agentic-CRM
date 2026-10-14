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

// ── Admin model API (attome_api::model_admin, `/api/v1/admin/model`) ──

/** `base_types::PaginatedResponse<T>`. */
export interface Page<T> {
  items:     T[];
  total:     number;
  page:      number;
  page_size: number;
}

export interface KindView {
  name:           string;
  schema_version: number;
  description:    string;
}

export interface ObjectSummary {
  id:            string;
  name:          string;
  app:           string;
  owner_layer:   string;
  version_no:    number;
  state:         string;
  content_hash:  string;
}

export interface VersionSummary {
  version_no:   number;
  state:        string;
  content_hash: string;
  created_by:   string | null;
  created_at:   string;
}

export interface ObjectVersion {
  id:                  string;
  kind:                string;
  name:                string;
  version_no:          number;
  kind_schema_version: number;
  state:               string;
  doc:                 unknown;
  content_hash:        string;
  created_at:          string;
}

/** One RFC 6902 operation. */
export interface PatchOp {
  op:     string;
  path:   string;
  value?: unknown;
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

  // ── Admin: the metadata explorer (roadmap Y1-T15) ──

  kinds(): Observable<Page<KindView>> {
    return this.api.get<Page<KindView>>('/api/v1/admin/model/kinds');
  }

  objects(kind: string, page: number): Observable<Page<ObjectSummary>> {
    return this.api.get<Page<ObjectSummary>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}`,
      { page: String(page) },
    );
  }

  history(kind: string, id: string): Observable<Page<VersionSummary>> {
    return this.api.get<Page<VersionSummary>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/history`,
    );
  }

  version(kind: string, id: string, version: number): Observable<ObjectVersion> {
    return this.api.get<ObjectVersion>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/versions/${version}`,
    );
  }

  diff(kind: string, id: string, from: number, to: number): Observable<Page<PatchOp>> {
    return this.api.get<Page<PatchOp>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/diff`,
      { from: String(from), to: String(to) },
    );
  }
}
