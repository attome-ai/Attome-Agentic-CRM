import { TestBed } from '@angular/core/testing';
import { SdkService } from '@attome/base';
import { firstValueFrom, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ModelService } from './model.service';
import { isFilled, sectionShown, type FormPlanSection } from './model.service';
import { PlanStore } from './plan-store';
import { sdkFromApi } from '../testing/sdk-from-api';

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
        { provide: SdkService, useValue: sdkFromApi(api) },
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

// D24-T11: a section shown only when filled.
describe('account form hides empty company details section', () => {
  const field = (attribute: string) => ({ attribute, label: attribute, field_type: 1, required: false, ai: false });
  const details: FormPlanSection = {
    label: 'Company details', visible_when: 'any_filled',
    fields: [field('industry_code'), field('employee_count'), field('annual_revenue')],
  };

  it('is hidden while every field is empty and shown once one is filled', () => {
    expect(sectionShown(details, { industry_code: null, employee_count: '', annual_revenue: [] }, {})).toBe(false);
    expect(sectionShown(details, { employee_count: 250 }, {})).toBe(true);
    expect(sectionShown(details, {}, { industry_code: 'C10' }), 'a value being edited keeps it').toBe(true);
    expect(sectionShown({ ...details, visible_when: undefined }, {}, {}), 'always shown by default').toBe(true);
    expect(isFilled(0)).toBe(true);
    expect(isFilled(false)).toBe(true);
    expect(isFilled('  ')).toBe(false);
  });
});

