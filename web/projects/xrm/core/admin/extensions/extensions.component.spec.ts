import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ExtensionAdminService } from '../data/services/extension-admin.service';
import { ExtensionsComponent } from './extensions.component';

describe('ExtensionsComponent (AE2-T4)', () => {
  function setUp() {
    const versions = [
      { id: 'v3', name: 'erp_sync', version: 3, status: 'published', module_sha256: 'a', manifest: {}, created_at: '2026-11-05T10:00:00Z' },
      { id: 'v2', name: 'erp_sync', version: 2, status: 'superseded', module_sha256: 'b', manifest: {}, created_at: '2026-11-04T10:00:00Z' },
      { id: 'w1', name: 'welcome', version: 1, status: 'draft', module_sha256: 'c', manifest: {}, created_at: '2026-11-03T10:00:00Z' },
    ];
    const runs = [
      {
        id: 'r1', version: 3, started_at: '2026-11-05T10:01:00Z', duration_ms: 12, fuel_used: 1234,
        ok: false, error: 'trap: <b>bad</b>', is_test: false,
        logs: [{ level: 'info', message: 'called ERP with key ***' }, { oops: true }],
      },
      { id: 'r2', version: 3, started_at: '2026-11-05T10:00:00Z', duration_ms: 5, fuel_used: 10, ok: true, is_test: true, logs: [] },
    ];
    const svc = {
      versions: vi.fn(() => of({ items: versions, total: 3, page: 1, page_size: 3 })),
      runs: vi.fn(() => of({ items: runs, total: 2, page: 1, page_size: 2 })),
    };
    TestBed.configureTestingModule({
      imports: [ExtensionsComponent],
      providers: [
        { provide: ExtensionAdminService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(ExtensionsComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, svc };
  }

  it('lists each extension once, as its newest version', () => {
    const { root } = setUp();
    const rows = Array.from(root.querySelectorAll('[data-extension-row]'));
    expect(rows.map(r => r.getAttribute('data-extension-row'))).toEqual(['erp_sync', 'welcome']);
    expect(rows[0].textContent).toContain('published');
  });

  it('shows the chosen extension runs with their result, and a run logs as text', () => {
    const { fixture, root, svc } = setUp();
    (root.querySelector('[data-show-runs="erp_sync"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc.runs).toHaveBeenCalledWith('erp_sync');
    expect(root.querySelector('[data-run-row="r1"] [data-result]')?.getAttribute('data-result')).toBe('failed');
    expect(root.querySelector('[data-run-row="r2"] [data-result]')?.getAttribute('data-result')).toBe('ok');

    (root.querySelector('[data-open-run="r1"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const logs = root.querySelectorAll('[data-run-logs] li');
    expect(logs.length).toBe(1);
    expect(logs[0].textContent).toContain('called ERP with key ***');
    const error = root.querySelector('[data-run-error]');
    expect(error?.textContent).toContain('<b>bad</b>');
    expect(error?.querySelector('b')).toBeNull();
  });
});
