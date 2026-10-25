import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, ATTOME_CONFIG, LangService, UserPreferencesService } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DrillFreshness, DrillHistoryComponent, DrillRun, DrillSchedule, trendPoints } from './drill-history.component';

const FRESHNESS: DrillFreshness[] = [
  { kind: 'restore', status: 'stale', last_run_at: '2026-08-01T00:00:00Z', last_ok_run_at: '2026-08-01T00:00:00Z', period_days: 31, failing_checks: [] },
  { kind: 'failover', status: 'failed', last_run_at: '2026-10-01T00:00:00Z', last_ok_run_at: null, period_days: 31, failing_checks: ['sample_api_reads'] },
];

const RUN = (id: string, at: string, rpo: number, rto: number): DrillRun => ({
  id, kind: 'restore', started_at: at, finished_at: at, overall_ok: true, restore_ok: true,
  provenance_ok: true, rpo_seconds: rpo, rto_seconds: rto, data_size_bytes: null,
  platform_version: '2.0.0', key_id: 'k', sha256: 's', uploaded_by: null, created_at: at,
});

const RESTORE_OFF: DrillSchedule = {
  id: 'sch-1', kind: 'restore', cadence: 'monthly', enabled: false, next_due_at: null,
  last_run_id: null, row_version: 4, updated_by: null, updated_at: null,
};

const page = <T>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20 });

describe('DrillHistoryComponent (AB4-T11)', () => {
  function create(privileges: string[]) {
    TestBed.resetTestingModule();
    const get = vi.fn((url: string) => {
      if (url === '/api/v1/ops/drills/freshness') return of(page(FRESHNESS));
      if (url === '/api/v1/ops/drill-schedules') return of(page([RESTORE_OFF]));
      return of(page([RUN('r-1', '2026-09-01T00:00:00Z', 60, 300), RUN('r-2', '2026-10-01T00:00:00Z', 30, 240)]));
    });
    const patch = vi.fn((_url: string, _body: unknown, _etag?: number) => of({ ...RESTORE_OFF, enabled: true, row_version: 5 }));
    TestBed.configureTestingModule({
      imports: [DrillHistoryComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, patch } },
        { provide: AccessService, useValue: { ready: () => of(undefined), hasPrivilege: (k: string) => privileges.includes(k) } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'https://crm.example' } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', current: signal('en'), intlLocale: () => 'en-US' },
        },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(DrillHistoryComponent);
    fixture.detectChanges();
    return { fixture, get, patch };
  }

  it('shows stale badge', () => {
    const { fixture } = create([]);
    const badges: HTMLElement[] = Array.from(fixture.nativeElement.querySelectorAll('[data-testid="dh-badge"]'));
    expect(badges.map(b => b.getAttribute('data-status'))).toEqual(['stale', 'failed']);
    expect(badges[1].textContent).toContain('sample_api_reads');
    expect(fixture.nativeElement.querySelector('[data-testid="dh-restore-off"]')).not.toBeNull();
  });

  it('enable switch sends If-Match', () => {
    const { fixture, patch } = create(['ops.drill.manage']);
    const on: HTMLButtonElement = fixture.nativeElement.querySelector('[data-testid="dh-restore-on"]');
    on.click();
    fixture.detectChanges();
    expect(patch).toHaveBeenCalledWith('/api/v1/ops/drill-schedules/sch-1', { enabled: true }, 4);
    expect(fixture.nativeElement.querySelector('[data-testid="dh-restore-off"]')).toBeNull();
  });

  it('auditor form hidden without privilege', () => {
    const { fixture } = create(['ops.read']);
    expect(fixture.nativeElement.querySelector('[data-testid="dh-pack"]')).toBeNull();
    const auditor = create(['ops.auditor.read']).fixture;
    expect(auditor.nativeElement.querySelector('[data-testid="dh-pack"]')).not.toBeNull();
    const component = auditor.componentInstance;
    component.from = '2026-01-01';
    component.to = '2026-03-31';
    expect(component.packUrl()).toBe('https://crm.example/api/v1/ops/drills/auditor-pack?from=2026-01-01&to=2026-03-31');
  });

  it('plots the trend oldest first', () => {
    const runs = [RUN('b', '2026-10-01T00:00:00Z', 30, 240), RUN('a', '2026-09-01T00:00:00Z', 60, 300)];
    expect(trendPoints(runs, 'rpo_seconds', 300)).toBe('0,64 320,72');
    expect(trendPoints([], 'rto_seconds', 300)).toBe('');
  });
});
