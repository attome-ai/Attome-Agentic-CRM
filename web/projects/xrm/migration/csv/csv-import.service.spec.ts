import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { firstValueFrom } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CsvImportService } from './csv-import.service';

const API = 'http://api';

describe('CsvImportService', () => {
  let svc: CsvImportService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { intlLocale: () => 'ar-SA' } },
      ],
    });
    svc = TestBed.inject(CsvImportService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('stages a chunk with its idempotency key', async () => {
    const done = svc.stage('contact', { records: [] }, 'csv-stage:p:0:a');
    const req = http.expectOne(`${API}/api/v1/contact/staged-import`);
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get('x-idempotency-key')).toBe('csv-stage:p:0:a');
    req.flush({ id: 'si', status: 'pending_review', total: 0, passed: 0, failed: 0, rejected: 0 });
    expect((await done).id).toBe('si');
  });

  it('links a run and approves with keys', async () => {
    const link = svc.linkRun('p', 'si', 'csv-link:p:si');
    const lr = http.expectOne(`${API}/api/v1/admin/migration-projects/p/runs`);
    expect(lr.request.body).toEqual({ staged_import_id: 'si' });
    expect(lr.request.headers.get('x-idempotency-key')).toBe('csv-link:p:si');
    lr.flush({ validation_report: [] });
    await link;

    const approve = svc.approve('contact', 'si', 'csv-approve:si');
    const ar = http.expectOne(`${API}/api/v1/contact/staged-import/si/approve`);
    expect(ar.request.headers.get('x-idempotency-key')).toBe('csv-approve:si');
    ar.flush({});
    await approve;
  });

  it('saves a mapping and a project as csv sources', async () => {
    const m = firstValueFrom(svc.createMapping({ name: 'n', target_entity: 'contact', fields: [] }));
    const mr = http.expectOne(`${API}/api/v1/admin/data/mappings`);
    expect(mr.request.body).toEqual({ name: 'n', target_entity: 'contact', fields: [], source_kind: 'csv' });
    mr.flush({ id: 'm' });
    await m;

    const p = firstValueFrom(svc.createProject({ name: 'p', target_entity: 'contact', mapping_ref: 'm', source_ref: 'r' }));
    const pr = http.expectOne(`${API}/api/v1/admin/migration-projects`);
    expect(pr.request.body.source_kind).toBe('csv');
    pr.flush({ id: 'p' });
    await p;
  });

  it('lists only resumable CSV projects and reads the schema in the active locale', async () => {
    const list = firstValueFrom(svc.listProjects('contact'));
    http
      .expectOne(r => r.url === `${API}/api/v1/admin/migration-projects` && r.params.get('target_entity') === 'contact')
      .flush({
        items: [
          { id: 'a', source_kind: 'csv', status: 'draft' },
          { id: 'b', source_kind: 'json', status: 'draft' },
          { id: 'c', source_kind: 'csv', status: 'archived' },
        ],
        total: 3, page: 1, page_size: 200,
      });
    expect((await list).map(p => p.id)).toEqual(['a']);

    const schema = firstValueFrom(svc.schema('contact'));
    http.expectOne(r => r.url === `${API}/api/v1/schema/contact` && r.params.get('locale') === 'ar-SA').flush({ fields: [] });
    await schema;
  });
});
