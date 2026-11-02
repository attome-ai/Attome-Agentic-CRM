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

  /** The SDK sends, and answers, after a promise turn (Y9-T3). */
  const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

  it('applies the policy and passes the 200 body through', async () => {
    let result: unknown;
    service.applyPolicy(ID).subscribe(r => (result = r));
    await tick();
    const req = http.expectOne(`${API}/api/v1/ticket/${ID}/apply-sla-policy`);
    expect(req.request.method).toBe('POST');
    const body = { sla_policy_id: 'p', resolution_due_at: null, sla_calculation_status: 'unresolved', sla_unresolved_reason: 'calculation_failed' };
    req.flush(body);
    await tick();
    expect(result).toEqual(body);
  });

  it('maps the 204 "no matching policy" answer to null', async () => {
    let result: unknown = 'unset';
    service.applyPolicy(ID).subscribe(r => (result = r));
    await tick();
    http.expectOne(`${API}/api/v1/ticket/${ID}/apply-sla-policy`).flush(null, { status: 204, statusText: 'No Content' });
    await tick();
    expect(result).toBeNull();
  });

  it('pauses with the reason in the body', async () => {
    service.pauseClock(ID, 'on_hold').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/ticket/${ID}/sla-clock/pause`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ reason: 'on_hold' });
    req.flush({ state: 'paused', paused_reason: 'on_hold', elapsed_business_seconds: 0, state_changed_at: '2026-09-23T00:00:00Z' });
  });

  it('resumes and recalculates on their own routes', async () => {
    service.resumeClock(ID).subscribe();
    await tick();
    http.expectOne(r => r.method === 'POST' && r.url === `${API}/api/v1/ticket/${ID}/sla-clock/resume`)
      .flush({ state: 'running', paused_reason: null, elapsed_business_seconds: 0, state_changed_at: '2026-09-23T00:00:00Z' });
    service.recalculate(ID).subscribe();
    await tick();
    http.expectOne(r => r.method === 'POST' && r.url === `${API}/api/v1/ticket/${ID}/sla/recalculate`)
      .flush({ ticket_id: ID, recalculated: false });
  });
});
