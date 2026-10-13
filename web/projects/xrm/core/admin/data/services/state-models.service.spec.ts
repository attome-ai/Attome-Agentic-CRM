import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { StateModelsService } from './state-models.service';

describe('StateModelsService', () => {
  const API = 'http://localhost:7865';
  const BASE = `${API}/api/v1/admin/state-models`;
  let service: StateModelsService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(StateModelsService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('unwraps the list envelope', () => {
    let names: string[] = [];
    service.listModels().subscribe(items => (names = items.map(i => i.name)));
    http.expectOne(BASE).flush({
      items: [{ id: 'm1', entity_logicalname: 'x', name: 'Lifecycle', state_field: 's', initial_state: 'new', is_active: true, row_version: 1 }],
      total: 1, page: 1, page_size: 1,
    });
    expect(names).toEqual(['Lifecycle']);
  });

  it('sends row_version in the model PATCH body', () => {
    service.updateModel('m1', { name: 'n', state_field: 's', initial_state: 'a', is_active: true, row_version: 4 }).subscribe();
    const req = http.expectOne(`${BASE}/m1`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body.row_version).toBe(4);
    req.flush({});
  });

  it('creates, updates and deletes transitions under the model', () => {
    service.createTransition('m1', { from_state: 'a', to_state: 'b', name: 'Go' }).subscribe();
    const create = http.expectOne(`${BASE}/m1/transitions`);
    expect(create.request.method).toBe('POST');
    create.flush({});

    service.updateTransition('m1', 't1', { name: 'Go', row_version: 2 }).subscribe();
    const update = http.expectOne(`${BASE}/m1/transitions/t1`);
    expect(update.request.method).toBe('PATCH');
    expect(update.request.body.row_version).toBe(2);
    update.flush({});

    service.deleteTransition('m1', 't1').subscribe();
    const del = http.expectOne(`${BASE}/m1/transitions/t1`);
    expect(del.request.method).toBe('DELETE');
    del.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('deletes a model', () => {
    service.deleteModel('m1').subscribe();
    const req = http.expectOne(`${BASE}/m1`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null, { status: 204, statusText: 'No Content' });
  });
});
