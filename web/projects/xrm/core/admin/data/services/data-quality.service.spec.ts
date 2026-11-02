import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DataQualityService } from './data-quality.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('DataQualityService', () => {
  const API = 'http://localhost:7865';
  let service: DataQualityService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(DataQualityService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('walks the scores list from page 1 (one-based endpoint)', async () => {
    let count = -1;
    service.listScores('contact').subscribe(items => (count = items.length));
    await tick();
    const req = http.expectOne(r => r.url === `${API}/api/v1/admin/data/quality/scores`);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('entity')).toBe('contact');
    req.flush({ items: [], total: 0, page: 1, page_size: 200 });
    await tick();
    expect(count).toBe(0);
  });

  it('asks for one entity+dimension history', async () => {
    service.scoreHistory('contact', 'uniqueness', 10).subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${API}/api/v1/admin/data/quality/scores/history`);
    expect(req.request.params.get('entity')).toBe('contact');
    expect(req.request.params.get('dimension')).toBe('uniqueness');
    expect(req.request.params.get('page_size')).toBe('10');
    req.flush({ items: [], total: 0, page: 1, page_size: 10 });
    await tick();
  });

  it('sends only the issue filters that are set', async () => {
    service.listIssues({ status: 'open' }, 2, 25).subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${API}/api/v1/admin/data/quality/issues`);
    expect(req.request.params.get('status')).toBe('open');
    expect(req.request.params.has('entity')).toBe(false);
    expect(req.request.params.has('dimension')).toBe(false);
    expect(req.request.params.get('page')).toBe('2');
    req.flush({ items: [], total: 0, page: 2, page_size: 25 });
    await tick();
  });

  it('posts the resolve action', async () => {
    service.resolveIssue('i-1').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/admin/data/quality/issues/i-1/resolve`);
    expect(req.request.method).toBe('POST');
    req.flush(null, { status: 204, statusText: 'No Content' });
    await tick();
  });
});
