import { inject, Injectable } from '@angular/core';
import { Observable, defer, from, map, of, switchMap, tap } from 'rxjs';
import { SdkService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';

import { PlanStore, StoredPlan } from './plan-store';
import type { FormHookAnswer, FormHookRequest } from './form-renderer/form-hooks';

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
  /** A12-T2: the caller may not change it (no write grant, or seen masked). */
  read_only?: boolean;
  /** A12-T2: its value reaches the caller masked. */
  masked?:    boolean;
}

export interface FormPlanSection {
  label:    string;
  /** A12-T2: the columns its fields are laid out in, 1 to 4. */
  columns?: number;
  fields:   FormPlanField[];
}

/** A12-T2: one tab, holding the next `sections` of the plan's sections. */
export interface FormPlanTab {
  label:    string;
  sections: number;
}

export interface FormPlan {
  id:         string;
  name:       string;
  /** The entity's logical name, as the record API addresses it. */
  entity:     string;
  /** A12-T2: `main`, `quick_create`, `quick_view` or `card`. */
  form_kind?: string;
  sections:   FormPlanSection[];
  /** A12-T2: absent for a form without tabs. */
  tabs?:      FormPlanTab[];
}

/**
 * A12-T2: the plan's sections under tab `index`, or all of them for a form
 * without tabs. Pure.
 */
export function tabSections(plan: FormPlan, index: number): FormPlanSection[] {
  const tabs = plan.tabs ?? [];
  if (!tabs.length) return plan.sections;
  let start = 0;
  for (let i = 0; i < index && i < tabs.length; i++) start += tabs[i].sections;
  return plan.sections.slice(start, start + (tabs[index]?.sections ?? 0));
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

/** One menu item's use (`GET /api/v1/admin/model/navigation/{id}/usage`). */
export interface MenuItemUsage {
  /** `<group label>/<item label>`. */
  item: string;
  opens: number;
  last_opened: string | null;
  /** Not opened in the period: a candidate to hide. */
  unused: boolean;
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

/** T7-T2: one customer test a publish can affect, as it ran. */
export interface AffectedTest {
  id: string;
  name: string;
  blocking: boolean;
  passed: boolean;
  failures: string[];
}

/** T1-T4: what a publish of an object would meet, from the validate preview. */
export interface QualityReport {
  tests: AffectedTest[];
  /** Accessibility findings (B22-T2), each with its fix. */
  warnings: string[];
  /** Performance findings, each with its fix. */
  performance: string[];
  /** `block` when the findings refuse a publish, else `warn`. */
  quality_gate: 'warn' | 'block';
}

/** The published metadata model, as the renderer reads it (roadmap Y14). */
@Injectable({ providedIn: 'root' })
export class ModelService {
  private readonly sdk = inject(SdkService);
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
      switchMap(stored => this.sdk.getIfChanged<FormPlan>(path, stored?.etag ?? null).pipe(
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

  /** A12-T4: runs the entity's form hooks (its extensions) on the form's state. */
  formHooks(entity: string, request: FormHookRequest): Observable<FormHookAnswer> {
    return this.sdk.post<FormHookAnswer>(
      `/api/v1/${encodeURIComponent(entity)}/form-hooks`, { body: request },
    );
  }

  /** A12-T2: the entity's schema, for its fields' kinds and the caller's business rules. */
  schema(entity: string): Observable<EntitySchema> {
    return this.sdk.get<EntitySchema>(`/api/v1/schema/${encodeURIComponent(entity)}`);
  }

  record(entity: string, id: string): Observable<RecordView> {
    return this.sdk.get<RecordView>(`/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`);
  }

  /** Saves changed values; `rowVersion` guards against a lost update. */
  /** A12-T5: a new record from a metadata form. */
  createRecord(entity: string, values: Record<string, unknown>): Observable<RecordView> {
    return this.sdk.post<RecordView>(`/api/v1/${encodeURIComponent(entity)}`, { body: values });
  }

  updateRecord(entity: string, id: string, values: Record<string, unknown>, rowVersion: number): Observable<RecordView> {
    return this.sdk.patch<RecordView>(
      `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`,
      { body: values, ifMatch: rowVersion },
    );
  }

  // ── Admin: the metadata explorer (roadmap Y1-T15) ──

  kinds(): Observable<Page<KindView>> {
    return this.sdk.get<Page<KindView>>('/api/v1/admin/model/kinds');
  }

  objects(kind: string, page: number): Observable<Page<ObjectSummary>> {
    return this.sdk.get<Page<ObjectSummary>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}`,
      { query: { page: String(page) } },
    );
  }

  history(kind: string, id: string): Observable<Page<VersionSummary>> {
    return this.sdk.get<Page<VersionSummary>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/history`,
    );
  }

  version(kind: string, id: string, version: number): Observable<ObjectVersion> {
    return this.sdk.get<ObjectVersion>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/versions/${version}`,
    );
  }

  diff(kind: string, id: string, from: number, to: number): Observable<Page<PatchOp>> {
    return this.sdk.get<Page<PatchOp>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/diff`,
      { query: { from: String(from), to: String(to) } },
    );
  }

  object(kind: string, id: string): Observable<ObjectVersion> {
    return this.sdk.get<ObjectVersion>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`,
    );
  }

  /** Applies edit commands to a draft; `baseHash` is `''` for a new object. */
  saveDraft(kind: string, id: string, baseHash: string, name: string | null, commands: ModelCommand[]): Observable<DraftSaved> {
    return this.sdk.post<DraftSaved>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/commands`,
      { body: { base_hash: baseHash, name, commands } },
    );
  }

  /**
   * T7-T2, T1-T4: the publish preview: runs the customer tests a publish of
   * the object can affect and returns them with the accessibility and
   * performance findings and whether those block.
   */
  previewQuality(kind: string, id: string, doc: unknown): Observable<QualityReport> {
    return this.sdk.post<Partial<QualityReport>>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/validate`,
      { body: { doc, run_tests: true } },
    ).pipe(map(r => ({
      tests: r.tests ?? [],
      warnings: r.warnings ?? [],
      performance: r.performance ?? [],
      quality_gate: r.quality_gate === 'block' ? 'block' : 'warn',
    })));
  }

  publish(kind: string, id: string): Observable<{ id: string; version_no: number }> {
    return this.sdk.post<{ id: string; version_no: number }>(
      `/api/v1/admin/model/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/publish`,
      { body: {} },
    );
  }

  /** What a published agent did today against its daily limits (AH4-T4). */
  /** Starts a run of an eval suite against its agent (N23-T1). */
  startEvalRun(suite: string): Observable<{ run_id: string; cases: number; status: string }> {
    return this.sdk.post<{ run_id: string; cases: number; status: string }>(
      `/api/v1/admin/ai/eval-suites/${encodeURIComponent(suite)}/runs`, { body: {} },
    );
  }

  /** One eval run and, once finished, its graded cases. */
  evalRun(id: string): Observable<EvalRun> {
    return this.sdk.get<EvalRun>(`/api/v1/admin/ai/eval-runs/${encodeURIComponent(id)}`);
  }

  agentUsage(agent: string): Observable<{ items: AgentUsage[] }> {
    return this.sdk.get<{ items: AgentUsage[] }>(
      `/api/v1/admin/ai/agents/${encodeURIComponent(agent)}/usage`,
    );
  }

  /** A published menu as this user sees it (A21-T2). */
  /** A21-T5: counts one open of a menu item (`<group>/<item>`). */
  menuItemOpened(id: string, item: string): Observable<void> {
    return this.sdk.post<void>(`/api/v1/model/navigation/${encodeURIComponent(id)}/opened`, { body: { item } });
  }

  /** AK6-T2 / A21-T5: how often each item of a menu was opened in the last `days`. */
  menuUsage(id: string, days = 60): Observable<Page<MenuItemUsage>> {
    return this.sdk.get<Page<MenuItemUsage>>(
      `/api/v1/admin/model/navigation/${encodeURIComponent(id)}/usage`, { query: { days: String(days) } },
    );
  }

  menu(id: string): Observable<MenuView> {
    return this.sdk.get<MenuView>(`/api/v1/model/navigation/${encodeURIComponent(id)}`);
  }

  /** The actions the caller may invoke, which an agent may be given as tools. */
  actions(): Observable<{ items: ActionSummary[] }> {
    return this.sdk.get<{ items: ActionSummary[] }>('/api/v1/actions');
  }
}
