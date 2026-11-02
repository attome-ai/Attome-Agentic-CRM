import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PUSH_SUBSCRIPTION_KEY, PushService, approvalIdOf, isAppRoute } from './push.service';

const APPROVAL = '019a0000-0000-7000-8000-000000000001';

function setup(): { service: PushService; http: HttpTestingController; navigate: ReturnType<typeof vi.fn> } {
  const navigate = vi.fn(async () => true);
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: Router, useValue: { navigateByUrl: navigate } },
    ],
  });
  return { service: TestBed.inject(PushService), http: TestBed.inject(HttpTestingController), navigate };
}

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  TestBed.resetTestingModule();
});

describe('PushService (B17-T8)', () => {
  it('tap navigates by id', async () => {
    const { service, navigate } = setup();
    await service.onAction('tap', { route: '/xrm/entity/ticket/form/42' });
    expect(navigate).toHaveBeenCalledWith('/xrm/entity/ticket/form/42');
    await service.onAction('tap', { route: 'https://elsewhere.example.com' });
    expect(navigate).toHaveBeenCalledOnce();
    expect(isAppRoute('//evil.example.com')).toBe(false);
  });

  it('approve decides through the decide route', async () => {
    const { service, http } = setup();
    const done = service.onAction('approve', { route: `/xrm/approvals/requests/${APPROVAL}` });
    http.expectOne(`/api/v1/approvals/${APPROVAL}`).flush({ row_version: 3 });
    await vi.waitFor(() => {
      const decide = http.expectOne(`/api/v1/approvals/${APPROVAL}/decide`);
      expect(decide.request.body).toEqual({ decision: 'approve', row_version: 3 });
      decide.flush({});
    });
    await done;
    expect(approvalIdOf('/xrm/entity/ticket/form/42')).toBeNull();
  });

  it('sign-out unregisters token', async () => {
    const { service, http } = setup();
    localStorage.setItem(PUSH_SUBSCRIPTION_KEY, 's1');
    const done = service.stop();
    http.expectOne(r => r.method === 'DELETE' && r.url === '/api/v1/push/subscriptions/s1').flush(null);
    await done;
    expect(localStorage.getItem(PUSH_SUBSCRIPTION_KEY)).toBeNull();
  });
});
