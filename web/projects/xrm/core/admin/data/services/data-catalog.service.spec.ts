import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DataCatalogService } from './data-catalog.service';

describe('DataCatalogService', () => {
  const API = 'http://localhost:7865';
  let service: DataCatalogService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(DataCatalogService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('searches from page 1 (one-based endpoint) and trims the query', () => {
    service.searchEntities({ q: '  acc ' }).subscribe();
    const req = http.expectOne(r => r.url === `${API}/api/v1/catalog/entities`);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('q')).toBe('acc');
    expect(req.request.params.has('classification')).toBe(false);
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
  });

  it('omits an empty query', () => {
    service.searchEntities({ q: '   ', classification: 'personal' }).subscribe();
    const req = http.expectOne(r => r.url === `${API}/api/v1/catalog/entities`);
    expect(req.request.params.has('q')).toBe(false);
    expect(req.request.params.get('classification')).toBe('personal');
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
  });

  it('reads one entity by logical name', () => {
    service.getEntity('contact').subscribe();
    const req = http.expectOne(`${API}/api/v1/catalog/entities/contact`);
    expect(req.request.method).toBe('GET');
    req.flush({});
  });
});
