import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { firstValueFrom } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { WorkforceApiService } from './workforce-api.service';

const JSON_HEADERS = { headers: { 'content-type': 'application/json' } };
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

function setup(): { service: WorkforceApiService; http: HttpTestingController } {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: ATTOME_CONFIG, useValue: { apiUrl: '' } },
    ],
  });
  return { service: TestBed.inject(WorkforceApiService), http: TestBed.inject(HttpTestingController) };
}

describe('WorkforceApiService (Y9-T3, through the SDK)', () => {
  it('reads my schedule between two days', async () => {
    const { service, http } = setup();
    const shifts = firstValueFrom(service.mySchedule('2026-11-01', '2026-11-14'));
    await tick();
    http.expectOne('/api/v1/workforce/me/schedule?from=2026-11-01&to=2026-11-14')
      .flush(JSON.stringify([{ id: 'a1' }]), JSON_HEADERS);
    expect(await shifts).toEqual([{ id: 'a1' }]);
  });

  it('publishes a schedule at its row version', async () => {
    const { service, http } = setup();
    const published = firstValueFrom(service.publish('s1', 3));
    await tick();
    const req = http.expectOne('/api/v1/workforce/schedules/s1/publish');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get('If-Match')).toBe('"3"');
    req.flush(JSON.stringify({ id: 's1' }), JSON_HEADERS);
    expect(await published).toEqual({ id: 's1' });
  });

  it('lists planning groups as options', async () => {
    const { service, http } = setup();
    const groups = firstValueFrom(service.groups());
    await tick();
    http.expectOne(r => r.url.startsWith('/api/v1/wfm_planning_group?'))
      .flush(JSON.stringify({ items: [{ id: 'g1', name: 'Riyadh desk' }] }), JSON_HEADERS);
    expect(await groups).toEqual([{ id: 'g1', label: 'Riyadh desk' }]);
  });
});
