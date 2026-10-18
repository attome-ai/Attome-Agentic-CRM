import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { CustomerTestListComponent } from './customer-test-list.component';
import type { CustomerTest } from './customer-test.model';

const TESTS: CustomerTest[] = [
  {
    id: 't1', name: 'Discount needs approval', description: null, definition: {}, blocking: true,
    is_active: true, row_version: 1, created_at: '2026-10-18T08:00:00Z', updated_at: '2026-10-18T08:00:00Z',
    created_by: null, last_passed: false, last_run_at: '2026-10-18T09:00:00Z',
  },
  {
    id: 't2', name: 'Lead gets an owner', description: 'routing', definition: {}, blocking: false,
    is_active: true, row_version: 3, created_at: '2026-10-18T08:00:00Z', updated_at: '2026-10-18T08:00:00Z',
    created_by: null, last_passed: null, last_run_at: null,
  },
];

const FAILED_RUN = { test_id: 't1', name: 'x', run_id: 'r', passed: false, failures: ['account a.name is x, expected y'] };

describe('CustomerTestListComponent (Z15-T15)', () => {
  function create() {
    const getAllPages = vi.fn((_: string) => of(TESTS));
    const post = vi.fn((path: string, _body: unknown) =>
      of(path.endsWith('/run-all') ? { passed: 0, failed: 1, results: [FAILED_RUN] } : FAILED_RUN));
    TestBed.configureTestingModule({
      imports: [CustomerTestListComponent],
      providers: [
        { provide: ApiService, useValue: { getAllPages, post, delete: vi.fn(() => of(undefined)) } },
        { provide: AdminService, useValue: { listEntities: () => of([]), getEntity: vi.fn() } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(CustomerTestListComponent);
    fixture.detectChanges();
    return { fixture, getAllPages, post };
  }

  it('renders rows from the API', () => {
    const { fixture, getAllPages } = create();
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/admin/customer-tests');
    const rows = fixture.nativeElement.querySelectorAll('tr[data-test]');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('Discount needs approval');
    expect(rows[0].querySelector('.ct-fail')).not.toBeNull();
    expect(rows[1].textContent).toContain('customerTestsPage.notRun');
  });

  it('runs one test and shows its failures', () => {
    const { fixture, post } = create();
    fixture.componentInstance.run(TESTS[0]);
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/customer-tests/t1/run', null);
    expect(fixture.nativeElement.querySelector('.ct-result').textContent).toContain('a.name');
  });

  it('runs all and shows the summary', () => {
    const { fixture, post } = create();
    fixture.componentInstance.runAll();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/customer-tests/run-all', null);
    expect(fixture.componentInstance.summary()?.failed).toBe(1);
    expect(fixture.nativeElement.querySelector('.ct-summary')).not.toBeNull();
  });
});
