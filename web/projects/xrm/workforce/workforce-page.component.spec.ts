import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { WorkforceApiService } from './workforce-api.service';
import type { ScheduleDetail } from './workforce-api.service';
import { WorkforcePageComponent, writeErrorKey } from './workforce-page.component';

const DETAIL: ScheduleDetail = {
  id: 's-1',
  period_from: '2026-11-01',
  period_to: '2026-11-01',
  planning_group_id: 'g-1',
  row_version: 4,
  status: 'draft',
  assignments: [],
  coverage: [],
};

describe('WorkforcePageComponent (G17-T13)', () => {
  let api: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    api = {
      groups: vi.fn(() => of([{ id: 'g-1', label: 'Riyadh voice' }])),
      users: vi.fn(() => of([])),
      schedules: vi.fn(() => of([DETAIL])),
      schedule: vi.fn(() => of(DETAIL)),
      publish: vi.fn(() => throwError(() => ({ status: 409, kind: 'conflict', message: 'stale' }))),
      swaps: vi.fn(() => of([])),
      proposals: vi.fn(() => of([])),
      live: vi.fn(() => of([])),
    };
    TestBed.configureTestingModule({
      imports: [WorkforcePageComponent],
      providers: [
        { provide: WorkforceApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US', current: () => 'en', translate: (k: string) => k,
            errorText: (e: { message: string }) => e.message,
          },
        },
        {
          provide: UserPreferencesService,
          useValue: { timezone: () => null, calendar: () => null, digits: () => null },
        },
      ],
    });
  });

  it('409 says the schedule changed since it was loaded', () => {
    expect(writeErrorKey({ status: 409 })).toBe('xrm.workforce.conflict');
    expect(writeErrorKey({ status: 422 })).toBeNull();

    const fixture = TestBed.createComponent(WorkforcePageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    (el.querySelector('[data-schedule="s-1"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const publish = () => {
      (el.querySelector('[data-testid="workforce-publish"]') as HTMLButtonElement).click();
      fixture.detectChanges();
    };
    publish();
    expect(api['publish']).not.toHaveBeenCalled();
    publish();
    expect(api['publish']).toHaveBeenCalledWith('s-1', 4);
    expect(el.querySelector('[data-testid="workforce-error"]')?.textContent).toContain('xrm.workforce.conflict');
  });
});
