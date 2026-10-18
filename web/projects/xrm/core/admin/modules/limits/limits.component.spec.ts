import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { SettingsService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LimitView, LimitsComponent, inRange, peakPercent } from './limits.component';

const LIMITS: LimitView[] = [
  {
    key: 'bulk.max_records_per_request', purpose: 'records one bulk request may carry', kind: 'resource',
    scope: 'runtime_setting', value: 500, default: 500, floor: 1, ceiling: 10000, unit: 'records',
    hits_7d: 0, peak_7d: 425, warning: true,
  },
  {
    key: 'http.max_body_bytes', purpose: 'the largest request body read', kind: 'resource',
    scope: 'boot_config', value: 10485760, default: 10485760, floor: 1, ceiling: 1073741824, unit: 'bytes',
    hits_7d: 0, peak_7d: 0, warning: false,
  },
];

describe('LimitsComponent (AA9-T8)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: LIMITS }));
    const putAdminSetting = vi.fn((..._: unknown[]) => of({}));
    TestBed.configureTestingModule({
      imports: [LimitsComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: SettingsService, useValue: { putAdminSetting } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(LimitsComponent);
    fixture.detectChanges();
    return { fixture, get, putAdminSetting };
  }

  it('shows raise only for runtime limits', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/limits');
    const root = fixture.nativeElement as HTMLElement;
    const runtime = root.querySelector('li[data-key="bulk.max_records_per_request"]')!;
    const boot = root.querySelector('li[data-key="http.max_body_bytes"]')!;
    expect(runtime.querySelector('.lim-raise-btn')).not.toBeNull();
    expect(runtime.querySelector('.lim-chip')).not.toBeNull();
    expect(boot.querySelector('.lim-raise-btn')).toBeNull();
    expect(boot.querySelector('.lim-config')).not.toBeNull();
  });

  it('blocks a value above ceiling', () => {
    const { fixture, putAdminSetting } = create();
    const component = fixture.componentInstance;
    component.edit(LIMITS[0]);
    component.draft.set(10001);
    fixture.detectChanges();
    const save = (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.lim-raise button[type="submit"]')!;
    expect(save.disabled).toBe(true);
    component.save(LIMITS[0]);
    expect(putAdminSetting).not.toHaveBeenCalled();

    component.draft.set(800);
    component.save(LIMITS[0]);
    expect(putAdminSetting).toHaveBeenCalledWith('limits.bulk.max_records_per_request', 'deployment', 800);
  });

  it('never raises a boot-config limit and reads the peak as a share', () => {
    const { fixture, putAdminSetting } = create();
    fixture.componentInstance.draft.set(5);
    fixture.componentInstance.save(LIMITS[1]);
    expect(putAdminSetting).not.toHaveBeenCalled();
    expect(peakPercent(LIMITS[0])).toBe(85);
    expect(inRange(LIMITS[0], 0)).toBe(false);
    expect(inRange(LIMITS[0], 2.5)).toBe(false);
    expect(inRange(LIMITS[0], null)).toBe(false);
  });
});
