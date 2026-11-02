import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ChangeFeedService } from './change-feed.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('ChangeFeedService', () => {
  const API = 'http://localhost:7865';
  let service: ChangeFeedService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(ChangeFeedService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('sends kind, window and the cursor when set', async () => {
    service.listChanges({ kind: 'metadata', from: '2026-09-01T00:00:00.000Z', to: '2026-09-02T00:00:00.000Z' }, 'djE6abc', 20)
      .subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${API}/api/v1/admin/changes`);
    expect(req.request.params.get('kind')).toBe('metadata');
    expect(req.request.params.get('from')).toBe('2026-09-01T00:00:00.000Z');
    expect(req.request.params.get('to')).toBe('2026-09-02T00:00:00.000Z');
    expect(req.request.params.get('cursor')).toBe('djE6abc');
    expect(req.request.params.get('page_size')).toBe('20');
    expect(req.request.params.has('page')).toBe(false);
    req.flush({ items: [] });
  });

  it('asks for the first page with no cursor and leaves the server defaults alone', async () => {
    service.listChanges({}).subscribe();
    await tick();
    const req = http.expectOne(r => r.url === `${API}/api/v1/admin/changes`);
    expect(req.request.params.keys()).toEqual(['page_size']);
    expect(req.request.params.get('page_size')).toBe('50');
    req.flush({ items: [], total: 0 });
  });
});
