import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SlaService } from './sla.service';

describe('SlaService', () => {
  const API = 'http://localhost:7865';
  const ID = '01900000-0000-7000-8000-0000000000t1';
  let service: SlaService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: ATTOME_CONFIG, useValue: { apiUrl: API } }],
    });
    service = TestBed.inject(SlaService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('applies the policy and passes the 200 body through', () => {
    let result: unknown;
    service.applyPolicy(ID).subscribe(r => (result = r));
    const req = http.expectOne(`${API}/api/v1/ticket/${ID}/apply-sla-policy`);
    expect(req.request.method).toBe('POST');
    const body = { sla_policy_id: 'p', resolution_due_at: null, sla_calculation_status: 'unresolved', sla_unresolved_reason: 'calculation_failed' };
    req.flush(body);
    expect(result).toEqual(body);
  });

  it('maps the 204 "no matching policy" answer to null', () => {
    let result: unknown = 'unset';
    service.applyPolicy(ID).subscribe(r => (result = r));
    http.expectOne(`${API}/api/v1/ticket/${ID}/apply-sla-policy`).flush(null, { status: 204, statusText: 'No Content' });
    expect(result).toBeNull();
  });

  it('pauses with the reason in the body', () => {
    service.pauseClock(ID, 'on_hold').subscribe();
    const req = http.expectOne(`${API}/api/v1/ticket/${ID}/sla-clock/pause`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ reason: 'on_hold' });
    req.flush({ state: 'paused', paused_reason: 'on_hold', elapsed_business_seconds: 0, state_changed_at: '2026-09-23T00:00:00Z' });
  });

  it('resumes and recalculates on their own routes', () => {
    service.resumeClock(ID).subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${API}/api/v1/ticket/${ID}/sla-clock/resume`)
      .flush({ state: 'running', paused_reason: null, elapsed_business_seconds: 0, state_changed_at: '2026-09-23T00:00:00Z' });
    service.recalculate(ID).subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${API}/api/v1/ticket/${ID}/sla/recalculate`)
      .flush({ ticket_id: ID, recalculated: false });
  });
});
