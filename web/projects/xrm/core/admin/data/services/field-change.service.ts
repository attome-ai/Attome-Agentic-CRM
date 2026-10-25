import { inject, Injectable } from '@angular/core';
import { HttpResponse } from '@angular/common/http';
import { Observable, catchError, map, of, throwError } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';
import { AdminHttp, type AdminApiError } from './admin-http';
import type { RestoreCounts } from './release-report.service';

/**
 * Solution 7 Phase 2 (D-788 rules 3–6 and 9; `SOLUTION-7-PHASE-2-DESIGN.md`
 * §3.1–§3.5, §8.5) — the field structure changes of the metadata designer
 * and the 30-day recovery archive.
 *
 * Routes: `crates/engine/attome-api/src/admin/attribute.rs` (rename, delete,
 * change-type, choices, run abandon), `field_changes.rs` (the result shape)
 * and `admin/recovery_archive.rs`. None of the structure routes takes
 * `If-Match`. Each one can answer three ways, and the screen needs all three:
 *
 * - `200` — done, or the dry-run report;
 * - `202` — a large table continues as a batched run (`run_id`), or the
 *   change waits for an approval (`approval_pending`);
 * - `409` — blocked: the body is still the full result, with the refusal in
 *   `error` and the reasons in `blockers`.
 *
 * Wire types are the generated `ApiComponents['schemas']`; the reference,
 * blocker and report-draft rows stay hand-written (see `FieldChangeResult`).
 */

/** Target types of an in-place type change (`change_field_type`). */
export const CONVERTIBLE_FIELD_TYPES = ['text', 'number', 'currency', 'date', 'date_time', 'bool', 'choice', 'rich_text'] as const;
export type ConvertibleFieldType = typeof CONVERTIBLE_FIELD_TYPES[number];

/**
 * The defined conversions, from → to. Mirrors `CONVERSIONS` in
 * `scripts/changesets/lib.mjs` and `conversion_defined` in
 * `attome_metadata::provision::field_change`; the server refuses anything else
 * with `conversion_not_defined`.
 */
export const FIELD_CONVERSIONS: Readonly<Record<string, readonly ConvertibleFieldType[]>> = {
  text:     ['number', 'currency', 'date', 'date_time', 'bool', 'choice', 'rich_text'],
  number:   ['text', 'currency'],
  currency: ['text', 'number'],
  date:     ['text', 'date_time'],
  date_time: ['text', 'date'],
  bool:     ['text'],
  choice:   ['text'],
};

/** Text ↔ date formats (`DATE_FORMATS` in `lib.mjs`). */
export const CONVERSION_DATE_FORMATS = ['iso8601', 'dd/mm/yyyy', 'mm/dd/yyyy', 'dd.mm.yyyy'] as const;

/** The types a field of `fromType` can change to (empty when none). */
export function conversionTargets(fromType: string): readonly ConvertibleFieldType[] {
  return FIELD_CONVERSIONS[fromType] ?? [];
}

// Hand-written: `openapi.json` types `FieldChangeResult.references` as bare objects (no `FieldRef` schema).
export interface FieldReference {
  /** The hook that found it (`views`, `labels`, ...). */
  hook:        string;
  /** `view`, `stored_query`, `rule`, `label`, ... */
  object_kind: string;
  object_ref:  string | null;
  /** A human name for the object (view name, rule name, label key). */
  name:        string;
  owner:       'ours' | 'customer';
}

// Hand-written: `openapi.json` types `FieldChangeResult.blockers` as bare objects (no `Blocker` schema).
export interface FieldBlocker {
  hook:        string;
  object_kind: string;
  object_ref:  string | null;
  name:        string;
  /** Why it cannot be rewritten or removed automatically. */
  reason:      string;
}

// Hand-written: `openapi.json` types `FieldChangeResult.report` as bare objects (no `ReportItemDraft` schema).
export interface FieldReportDraft {
  kind:        string;
  entity:      string;
  field:       string | null;
  object_kind: string | null;
  object_ref:  string | null;
  detail:      Record<string, unknown>;
}

export type FieldChangeOp =
  'rename_field' | 'delete_field' | 'change_field_type' | 'add_choice_value' | 'remove_choice_value';

/**
 * The generated schema, with its three row lists typed: the generated document
 * has them as untyped objects (`Record<string, never>[]`).
 */
export type FieldChangeResult = Omit<ApiComponents['schemas']['FieldChangeResult'], 'references' | 'blockers' | 'report'> & {
  references: FieldReference[];
  blockers:   FieldBlocker[];
  report:     FieldReportDraft[];
};

/** What a structure route answered. */
export type FieldChangeOutcome =
  | { kind: 'result'; result: FieldChangeResult; status: number }
  | { kind: 'approval'; approvalRequestId: string };

export interface ConversionInput {
  /** The type the caller expects the field to have now (`type_drift` otherwise). */
  from_type?:    string;
  /** text ↔ date. */
  format?:       string;
  /** text → bool. */
  true_values?:  string[];
  false_values?: string[];
  /** text → choice: source text → choice value. */
  map?:          Record<string, string>;
}

export interface AddChoiceInput {
  value:  string;
  label:  string;
  /** Place after this value; omitted = at the end. */
  after?: string;
  /** The label's language (`en`, `ar`); the server defaults to `en`. */
  locale?: string;
}

export type AbandonedFieldRun = ApiComponents['schemas']['AbandonedFieldRun'];

/** Y12-T5: a data step run's progress. */
export type DataStepRunStatus = ApiComponents['schemas']['DataStepRunStatus'];

/** `field_deleted | conversion_nulled`. */
export const ARCHIVE_REASONS = ['field_deleted', 'conversion_nulled'] as const;
export type ArchiveReason = typeof ARCHIVE_REASONS[number];

/** One archived value's row (the value itself is not listed); `reason` is an `ArchiveReason`. */
export type ArchiveRow = ApiComponents['schemas']['ArchiveRow'];

export interface ArchiveFilter {
  entity?:           string;
  field?:            string;
  reason?:           ArchiveReason;
  include_restored?: boolean;
}

interface ApprovalPendingBody {
  approval_pending:    boolean;
  approval_request_id: string;
}

function isApproval(body: unknown): body is ApprovalPendingBody {
  return !!body && typeof body === 'object' && (body as ApprovalPendingBody).approval_pending === true;
}

function isResult(body: unknown): body is FieldChangeResult {
  return !!body && typeof body === 'object' && typeof (body as FieldChangeResult).op === 'string';
}

/** A `200`/`202` answer → the outcome. */
function toOutcome(res: HttpResponse<unknown>): FieldChangeOutcome {
  if (isApproval(res.body)) return { kind: 'approval', approvalRequestId: res.body.approval_request_id };
  return { kind: 'result', result: res.body as FieldChangeResult, status: res.status };
}

/**
 * A `409` whose body is a `FieldChangeResult` is a blocked change, not an
 * error: the screen shows its `blockers`. Any other failure stays an error.
 */
function blockedAsOutcome(err: AdminApiError): Observable<FieldChangeOutcome> {
  if (err.status === 409 && isResult(err.body)) {
    return of({ kind: 'result', result: err.body, status: 409 });
  }
  return throwError(() => err);
}

const ARCHIVE = '/api/v1/admin/metadata/recovery-archive';

@Injectable({ providedIn: 'root' })
export class FieldChangeService {
  private readonly api  = inject(ApiService);
  private readonly http = inject(AdminHttp);

  private fieldPath(entityId: string, fieldId: string): string {
    return `/api/v1/admin/entities/${encodeURIComponent(entityId)}/fields/${encodeURIComponent(fieldId)}`;
  }

  private send(
    method: 'POST' | 'DELETE', path: string, body?: unknown, params?: Record<string, string>,
  ): Observable<FieldChangeOutcome> {
    return this.http.request<unknown>(method, path, { body, params }).pipe(
      map(toOutcome),
      catchError((err: AdminApiError) => blockedAsOutcome(err)),
    );
  }

  /** Renames the field in place; every reference follows. No alias for API callers. */
  rename(entityId: string, fieldId: string, newName: string, dryRun: boolean): Observable<FieldChangeOutcome> {
    return this.send('POST', `${this.fieldPath(entityId, fieldId)}/rename`, { new_name: newName, dry_run: dryRun });
  }

  /** Deletes the field for real; its values go to the 30-day recovery archive. */
  delete(entityId: string, fieldId: string, dryRun: boolean): Observable<FieldChangeOutcome> {
    return this.send('DELETE', this.fieldPath(entityId, fieldId), undefined,
      dryRun ? { dry_run: 'true' } : undefined);
  }

  /** Converts the field's type in place; values that do not convert become empty and are archived. */
  changeType(
    entityId: string, fieldId: string, fieldType: string, conversion: ConversionInput, dryRun: boolean,
  ): Observable<FieldChangeOutcome> {
    return this.send('POST', `${this.fieldPath(entityId, fieldId)}/change-type`,
      { field_type: fieldType, conversion, dry_run: dryRun });
  }

  addChoice(entityId: string, fieldId: string, input: AddChoiceInput): Observable<FieldChangeOutcome> {
    const body: Record<string, unknown> = { value: input.value, label: input.label };
    if (input.after) body['after'] = input.after;
    if (input.locale) body['locale'] = input.locale;
    return this.send('POST', `${this.fieldPath(entityId, fieldId)}/choices`, body);
  }

  /** Stored values stay in place (shown empty); the result counts them. */
  removeChoice(entityId: string, fieldId: string, value: string, dryRun: boolean): Observable<FieldChangeOutcome> {
    return this.send('DELETE', `${this.fieldPath(entityId, fieldId)}/choices/${encodeURIComponent(value)}`,
      undefined, dryRun ? { dry_run: 'true' } : undefined);
  }

  /** Abandons a FAILED batched run (`run_not_failed` otherwise). */
  /** Y12-T5: a run's status, counts and ETA. */
  runStatus(runId: string): Observable<DataStepRunStatus> {
    return this.api.get<DataStepRunStatus>(`/api/v1/admin/data-step-runs/${encodeURIComponent(runId)}`);
  }

  /** Y12-T5: pause, resume or cancel a run; answers its new status. */
  controlRun(runId: string, action: 'pause' | 'resume' | 'cancel'): Observable<DataStepRunStatus> {
    return this.api.post<DataStepRunStatus>(
      `/api/v1/admin/data-step-runs/${encodeURIComponent(runId)}/${action}`, {},
    );
  }

  abandonRun(entityId: string, fieldId: string, runId: string): Observable<AbandonedFieldRun> {
    return this.api.post<AbandonedFieldRun>(
      `${this.fieldPath(entityId, fieldId)}/runs/${encodeURIComponent(runId)}/abandon`, {},
    );
  }

  // ── Recovery archive ────────────────────────────────────────────────────

  /** Archived values (the values themselves are not included), newest first. One-based. */
  listArchive(filter: ArchiveFilter = {}, page = 1, pageSize = 25): Observable<Page<ArchiveRow>> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (filter.entity) params['entity'] = filter.entity;
    if (filter.field) params['field'] = filter.field;
    if (filter.reason) params['reason'] = filter.reason;
    if (filter.include_restored) params['include_restored'] = 'true';
    return this.api.get<Page<ArchiveRow>>(ARCHIVE, params);
  }

  /** Restores one value (fills an empty field only). */
  restoreArchived(archiveId: string): Observable<RestoreCounts> {
    return this.api.post<RestoreCounts>(`${ARCHIVE}/${encodeURIComponent(archiveId)}/restore`, {});
  }

  /** Restores every unexpired value of a field; repeat while `remaining > 0`. */
  restoreField(entity: string, field: string): Observable<RestoreCounts> {
    return this.api.post<RestoreCounts>(`${ARCHIVE}/restore`, { entity, field });
  }
}
