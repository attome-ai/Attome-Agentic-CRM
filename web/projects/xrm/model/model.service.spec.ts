import { TestBed } from '@angular/core/testing';
import { ApiService } from '@attome/base';
import { firstValueFrom, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ModelService } from './model.service';
import { PlanStore } from './plan-store';

const PLAN = { id: 'f1', name: 'Contact', entity: 'contact', sections: [] };

describe('ModelService.formPlan (Y14-T2)', () => {
  let api: { getIfChanged: ReturnType<typeof vi.fn> };
  let store: { read: ReturnType<typeof vi.fn>; write: ReturnType<typeof vi.fn> };
  let svc: ModelService;

  beforeEach(() => {
    store = { read: vi.fn().mockResolvedValue(null), write: vi.fn().mockResolvedValue(undefined) };
    api = { getIfChanged: vi.fn().mockReturnValue(of({ body: PLAN, etag: '"v1"' })) };
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: api },
        { provide: PlanStore, useValue: store },
      ],
    });
    svc = TestBed.inject(ModelService);
  });

  it('loads a plan once per session', async () => {
    expect(await firstValueFrom(svc.formPlan('f1'))).toEqual(PLAN);
    expect(await firstValueFrom(svc.formPlan('f1'))).toEqual(PLAN);
    expect(api.getIfChanged).toHaveBeenCalledTimes(1);
    expect(api.getIfChanged).toHaveBeenCalledWith('/api/v1/model/forms/f1/plan', null);
    expect(store.write).toHaveBeenCalledWith('f1', { etag: '"v1"', plan: PLAN });
  });

  it('revalidates a stored plan with its ETag and keeps it on 304', async () => {
    store.read.mockResolvedValue({ etag: '"v1"', plan: PLAN });
    api.getIfChanged.mockReturnValue(of({ body: null, etag: '"v1"' }));
    expect(await firstValueFrom(svc.formPlan('f1'))).toEqual(PLAN);
    expect(api.getIfChanged).toHaveBeenCalledWith('/api/v1/model/forms/f1/plan', '"v1"');
  });

  it('fetches again after forgetPlans', async () => {
    await firstValueFrom(svc.formPlan('f1'));
    svc.forgetPlans();
    await firstValueFrom(svc.formPlan('f1'));
    expect(api.getIfChanged).toHaveBeenCalledTimes(2);
  });
});
