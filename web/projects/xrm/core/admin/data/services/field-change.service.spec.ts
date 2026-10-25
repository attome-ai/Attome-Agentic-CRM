import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AdminApiError } from './admin-http';
import { FieldChangeService, conversionTargets, type FieldChangeOutcome } from './field-change.service';

function asResult(o: FieldChangeOutcome | null): Extract<FieldChangeOutcome, { kind: 'result' }> {
  if (!o || o.kind !== 'result') throw new Error('expected a result outcome');
  return o;
}

describe('FieldChangeService', () => {
  const API = 'http://localhost:7865';
  const FIELD = `${API}/api/v1/admin/entities/e1/fields/f1`;
  let service: FieldChangeService;
  let http: HttpTestingController;

  const result = (over: Record<string, unknown> = {}) => ({
    op: 'delete_field', entity: 'contact', field: 'rating', dry_run: true, applied: false,
    error: null, references: [], blockers: [], values_to_archive: 3, not_convertible: null,
    sample_record_ids: [], archived: 0, nulled: 0, records_with_value: null, run_id: null,
    report: [], labels: [], ...over,
  });

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(FieldChangeService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('sends a dry-run delete as ?dry_run=true and returns the result', () => {
    let out = null as FieldChangeOutcome | null;
    service.delete('e1', 'f1', true).subscribe(o => (out = o));
    const req = http.expectOne(r => r.url === FIELD);
    expect(req.request.method).toBe('DELETE');
    expect(req.request.params.get('dry_run')).toBe('true');
    req.flush(result());
    expect(asResult(out).result.values_to_archive).toBe(3);
  });

  it('treats a 409 that carries the result as a blocked change, not an error', () => {
    let out = null as FieldChangeOutcome | null;
    service.delete('e1', 'f1', true).subscribe(o => (out = o));
    http.expectOne(r => r.url === FIELD).flush(
      result({ error: 'field_referenced', blockers: [{ hook: 'views', object_kind: 'view', object_ref: null, name: 'All', reason: 'r' }] }),
      { status: 409, statusText: 'Conflict' },
    );
    const blocked = asResult(out);
    expect(blocked.status).toBe(409);
    expect(blocked.result.error).toBe('field_referenced');
    expect(blocked.result.blockers.length).toBe(1);
  });

  it('keeps a plain 409 an error', () => {
    let error = null as AdminApiError | null;
    service.rename('e1', 'f1', 'new_name', false).subscribe({ error: e => (error = e) });
    http.expectOne(`${FIELD}/rename`).flush(
      { error: 'conflict', message: 'conflict: field_busy: still running' },
      { status: 409, statusText: 'Conflict' },
    );
    expect(error!.message).toContain('field_busy');
  });

  it('maps a 202 approval answer', () => {
    let out = null as FieldChangeOutcome | null;
    service.changeType('e1', 'f1', 'number', { from_type: 'text' }, false).subscribe(o => (out = o));
    const req = http.expectOne(`${FIELD}/change-type`);
    expect(req.request.body).toEqual({ field_type: 'number', conversion: { from_type: 'text' }, dry_run: false });
    req.flush({ approval_pending: true, approval_request_id: 'a1' }, { status: 202, statusText: 'Accepted' });
    expect(out).toEqual({ kind: 'approval', approvalRequestId: 'a1' });
  });

  it('keeps the 202 status of a large-table run', () => {
    let out = null as FieldChangeOutcome | null;
    service.delete('e1', 'f1', false).subscribe(o => (out = o));
    const req = http.expectOne(r => r.url === FIELD);
    expect(req.request.params.has('dry_run')).toBe(false);
    req.flush(result({ dry_run: false, applied: true, run_id: 'run1' }), { status: 202, statusText: 'Accepted' });
    const queued = asResult(out);
    expect(queued.status).toBe(202);
    expect(queued.result.run_id).toBe('run1');
  });

  it('adds and removes choices on the choices routes', () => {
    service.addChoice('e1', 'f1', { value: 'on_hold', label: 'On hold', after: 'active' }).subscribe();
    const add = http.expectOne(`${FIELD}/choices`);
    expect(add.request.body).toEqual({ value: 'on_hold', label: 'On hold', after: 'active' });
    add.flush(result({ op: 'add_choice_value', dry_run: false, applied: true }));

    service.removeChoice('e1', 'f1', 'a b', true).subscribe();
    const remove = http.expectOne(r => r.url === `${FIELD}/choices/a%20b`);
    expect(remove.request.method).toBe('DELETE');
    expect(remove.request.params.get('dry_run')).toBe('true');
    remove.flush(result({ op: 'remove_choice_value', records_with_value: 4 }));
  });

  it('abandons a run', () => {
    service.abandonRun('e1', 'f1', 'run1').subscribe();
    const req = http.expectOne(`${FIELD}/runs/run1/abandon`);
    expect(req.request.method).toBe('POST');
    req.flush({ run_id: 'run1', kind: 'retype', status: 'abandoned', shadow_dropped: true, archive_rows_removed: 2, conversion_completed: false, labels: [] });
  });

  it('lists and restores the recovery archive', () => {
    service.listArchive({ entity: 'contact', field: 'rating', include_restored: true }, 1, 25).subscribe();
    const list = http.expectOne(r => r.url === `${API}/api/v1/admin/metadata/recovery-archive`);
    expect(list.request.params.get('entity')).toBe('contact');
    expect(list.request.params.get('field')).toBe('rating');
    expect(list.request.params.get('include_restored')).toBe('true');
    expect(list.request.params.get('page')).toBe('1');
    list.flush({ items: [], total: 0, page: 1, page_size: 25 });

    service.restoreField('contact', 'rating').subscribe();
    const all = http.expectOne(`${API}/api/v1/admin/metadata/recovery-archive/restore`);
    expect(all.request.body).toEqual({ entity: 'contact', field: 'rating' });
    all.flush({ restored: 0, skipped_filled: 0, skipped_not_convertible: 0, missing_records: 0, remaining: 0 });

    service.restoreArchived('a1').subscribe();
    http.expectOne(`${API}/api/v1/admin/metadata/recovery-archive/a1/restore`)
      .flush({ restored: 1, skipped_filled: 0, skipped_not_convertible: 0, missing_records: 0, remaining: 0 });
  });

  it('knows the defined conversions', () => {
    expect(conversionTargets('text')).toContain('number');
    expect(conversionTargets('date')).toEqual(['text', 'date_time']);
    expect(conversionTargets('date_time')).toEqual(['text', 'date']);
    expect(conversionTargets('lookup')).toEqual([]);
  });
});
