import { inject, Injectable } from '@angular/core';
import { Observable, defer, from, map, of, switchMap, tap } from 'rxjs';
import { ApiService } from '@attome/base';

import { PlanStore, StoredPlan } from './plan-store';

// ── Wire types (mirror attome_api::model_admin's FormPlan exactly) ──

export interface FormPlanField {
  /** The attribute's logical name: the key of its value in a record. */
  attribute:  string;
  label:      string;
  /** The attribute's field type number (attome_core::FieldType). */
  field_type: number;
  required:   boolean;
  /** An AI attribute: `record.ai_field` can suggest its value (N11-T1). */
  ai?:        boolean;
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

/** One edit command (`attome_model::commands::Command`). */
export type ModelCommand =
  | { op: 'set'; path: string; value: unknown }
  | { op: 'add'; path: string; value: unknown }
  | { op: 'remove'; path: string }
  | { op: 'move'; from: string; to: string };

export interface ModelIssue {
  path:    string;
  code:    string;
  message: string;
}

/** What saving a draft returns. */
export interface DraftSaved {
  id:           string;
  version_no:   number;
  content_hash: string;
  /** References to objects that do not exist; they do not block the draft. */
  issues:       ModelIssue[];
}

/** One limit class's use today (`GET /api/v1/admin/ai/agents/{agent}/usage`). */
/** `GET /api/v1/admin/ai/eval-runs/{id}` (`eval_runner::EvalRun`). */
export interface EvalRun {
  id:        string;
  status:    'running' | 'passed' | 'failed' | 'error' | string;
  score:     number | null;
  outcome:   { cases: { name: string; passed: boolean; safety: boolean; failures: string[] }[] } | null;
  error:     string | null;
}

export interface AgentUsage {
  class: string;
  used:  number;
  limit: number | null;
}

/** One menu item as the server sends it (A21-T2). */
export interface MenuItem {
  label:   string;
  /** `view` | `form` | `dashboard` | `page` | `report` | `flow` | `url`. */
  kind:    string;
  target?: string;
  url?:    string;
  badge?:  string;
}

/** A published menu filtered for the caller (`GET /api/v1/model/navigation/{id}`). */
export interface MenuView {
  id:      string;
  name:    string;
  groups:  { label: string; items: MenuItem[] }[];
  /** `<group>/<item>` of the caller's landing page. */
  landing: string | null;
}

/** An action an agent may be given (`GET /api/v1/actions`). */
export interface ActionSummary {
  id:          string;
  description: string;
  risk:        string;
}

/** The published metadata model, as the renderer reads it (roadmap Y14). */
@Injectable({ providedIn: 'root' })
export class ModelService {
  private readonly api = inject(ApiService);
  private readonly store = inject(PlanStore);

  /** Plans already current in this session, by form id. */
  private readonly plans = new Map<string, StoredPlan<FormPlan>>();

  /**
   * A published form's render plan, fetched once per version (Y14-T2): a
   * plan already checked this session is served from memory with no
   * request; one stored by an earlier session is sent back as
   * `If-None-Match`, so an unchanged plan costs a bodyless 304. The live
   * channel calls `forgetPlans` when a new version is published.
   */
  formPlan(formId: string): Observable<FormPlan> {
    const current = this.plans.get(formId);
    if (current) return of(current.plan);
    const path = `/api/v1/model/forms/${encodeURIComponent(formId)}/plan`;
    return defer(() => from(this.store.read<FormPlan>(formId))).pipe(
      switchMap(stored => this.api.getIfChanged<FormPlan>(path, stored?.etag ?? null).pipe(
        map(({ body, etag }) => {
          if (body === null && stored) return stored;
          if (body === null) throw new Error('the server answered 304 for a plan this browser does not hold');
          return { etag: etag ?? '', plan: body };
        }),
      )),
      tap(fresh => {
        this.plans.set(formId, fresh);
        if (fresh.etag) void this.store.write(formId, fresh);
      }),
      map(fresh => fresh.plan),
    );
  }

  /** Drops the in-memory plans, so the next read revalidates each one. */
  forgetPlans(): void {
    this.plans.clear();
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

  object(kind: string, id: string): Observable<ObjectVersion> {
    return this.api.get<ObjectVersion>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`,
    );
  }

  /** Applies edit commands to a draft; `baseHash` is `''` for a new object. */
  saveDraft(kind: string, id: string, baseHash: string, name: string | null, commands: ModelCommand[]): Observable<DraftSaved> {
    return this.api.post<DraftSaved>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/commands`,
      { base_hash: baseHash, name, commands },
    );
  }

  publish(kind: string, id: string): Observable<{ id: string; version_no: number }> {
    return this.api.post<{ id: string; version_no: number }>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/publish`,
      {},
    );
  }

  /** What a published agent did today against its daily limits (AH4-T4). */
  /** Starts a run of an eval suite against its agent (N23-T1). */
  startEvalRun(suite: string): Observable<{ run_id: string; cases: number; status: string }> {
    return this.api.post<{ run_id: string; cases: number; status: string }>(
      `/api/v1/admin/ai/eval-suites/${encodeURIComponent(suite)}/runs`, {},
    );
  }

  /** One eval run and, once finished, its graded cases. */
  evalRun(id: string): Observable<EvalRun> {
    return this.api.get<EvalRun>(`/api/v1/admin/ai/eval-runs/${encodeURIComponent(id)}`);
  }

  agentUsage(agent: string): Observable<{ items: AgentUsage[] }> {
    return this.api.get<{ items: AgentUsage[] }>(
      `/api/v1/admin/ai/agents/${encodeURIComponent(agent)}/usage`,
    );
  }

  /** A published menu as this user sees it (A21-T2). */
  /** A21-T5: counts one open of a menu item (`<group>/<item>`). */
  menuItemOpened(id: string, item: string): Observable<void> {
    return this.api.post<void>(`/api/v1/model/navigation/${encodeURIComponent(id)}/opened`, { item });
  }

  menu(id: string): Observable<MenuView> {
    return this.api.get<MenuView>(`/api/v1/model/navigation/${encodeURIComponent(id)}`);
  }

  /** The actions the caller may invoke, which an agent may be given as tools. */
  actions(): Observable<{ items: ActionSummary[] }> {
    return this.api.get<{ items: ActionSummary[] }>('/api/v1/actions');
  }
}
