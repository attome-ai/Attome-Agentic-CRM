import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ATTOME_CONFIG } from './config';
import {
  IMPERSONATION_HEADER, ImpersonationService, impersonationInterceptor,
} from './impersonation.service';

const BASE = 'http://localhost:7865';

describe('impersonationInterceptor (Q13-T2)', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let service: ImpersonationService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([impersonationInterceptor])),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: BASE } },
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    service = TestBed.inject(ImpersonationService);
  });

  afterEach(() => {
    httpMock.verify();
    sessionStorage.clear();
  });

  function startView(): void {
    service.start('u1', 'view', 'ticket 41', 'sara@example.com').subscribe();
    const start = httpMock.expectOne(`${BASE}/api/v1/admin/security/impersonation`);
    expect(start.request.headers.has(IMPERSONATION_HEADER)).toBe(false);
    start.flush({
      id: 's1', subject_id: 'u1', mode: 'view',
      expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
    });
  }

  it('names no session until one starts', () => {
    http.get(`${BASE}/api/v1/contact`).subscribe();
    expect(httpMock.expectOne(`${BASE}/api/v1/contact`).request.headers.has(IMPERSONATION_HEADER)).toBe(false);
  });

  it('names the session on API requests but not on the session routes', () => {
    startView();
    expect(service.session()?.subject_label).toBe('sara@example.com');
    http.get(`${BASE}/api/v1/contact`).subscribe();
    expect(httpMock.expectOne(`${BASE}/api/v1/contact`).request.headers.get(IMPERSONATION_HEADER)).toBe('s1');

    service.end().subscribe();
    const end = httpMock.expectOne(`${BASE}/api/v1/admin/security/impersonation/s1`);
    expect(end.request.method).toBe('DELETE');
    expect(end.request.headers.has(IMPERSONATION_HEADER)).toBe(false);
    end.flush(null);
    expect(service.active()).toBe(false);
  });

  it('forgets the session when the server says it has ended', () => {
    startView();
    http.get(`${BASE}/api/v1/contact`).subscribe({ error: () => undefined });
    httpMock.expectOne(`${BASE}/api/v1/contact`).flush(
      { error: 'validation', message: 'impersonation_ended: the session has ended' },
      { status: 422, statusText: 'Unprocessable Entity' },
    );
    expect(service.active()).toBe(false);
  });
});
