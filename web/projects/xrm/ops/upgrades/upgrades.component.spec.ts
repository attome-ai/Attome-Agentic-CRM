import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { SdkService, LangService, UserPreferencesService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { UpgradesComponent } from './upgrades.component';
import { Upgrade, activeImpact, rollbackState } from './upgrade-detail.component';
import { sdkFromApi } from '../../testing/sdk-from-api';

const UPGRADE = (over: Partial<Upgrade> = {}): Upgrade => ({
  id: 'up-1',
  from_version: '2.3.0',
  to_version: '2.4.0',
  started_by: null,
  started_at: '2026-10-01T00:00:00Z',
  finished_at: '2026-10-01T00:20:00Z',
  status: 'verified',
  safety_point: 'pre-2.4.0-20261001',
  check_report: {
    findings: [
      { check: 'version_path', verdict: 'pass', detail: '' },
      { check: 'disk', verdict: 'warn', detail: 'free space is tight' },
    ],
    previous_binary: '/opt/attome/attome-2.3.0',
    impact: [
      { module: 'sales', en: 'Quotes gain a validity date.', ar: 'تحمل عروض الأسعار تاريخ صلاحية.' },
      { module: 'grc', en: 'Risk scores move to 5 x 5.', ar: 'تصبح درجات المخاطر 5 × 5.' },
      { module: 'platform', en: 'Faster list pages.', ar: 'صفحات قوائم أسرع.' },
    ],
    rehearsal: {
      old_binary: { ok: false, detail: 'the 2.3 binary refused the new schema' },
      customer_tests: { passed: 4, failed: 1, failures: ['discount_cap'] },
      conflicts: [{ object: 'view:account_list', detail: 'changed in both' }],
    },
  },
  verification_evidence_id: 'ev-1',
  contract_applied_at: null,
  row_version: 2,
  ...over,
});

const page = <T>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20 });

describe('UpgradesComponent (AB8-T8)', () => {
  function create(lang: 'en' | 'ar', modules: unknown = { modules: [{ name: 'sales', enabled: true }, { name: 'grc', enabled: false }] }) {
    TestBed.resetTestingModule();
    const get = vi.fn((url: string) => {
      if (url === '/api/v1/admin/license/modules') {
        return modules instanceof Error ? throwError(() => modules) : of(modules);
      }
      return of(page([UPGRADE(), UPGRADE({ id: 'up-0', to_version: '2.3.0', status: 'rolled_back', check_report: null })]));
    });
    TestBed.configureTestingModule({
      imports: [UpgradesComponent],
      providers: [
        provideRouter([]),
        { provide: SdkService, useValue: sdkFromApi({ get }) },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', current: signal(lang), intlLocale: () => 'en-US' },
        },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(UpgradesComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('lists the history newest first and opens the newest', () => {
    const { fixture, get } = create('en');
    expect(get).toHaveBeenCalledWith('/api/v1/ops/upgrades', { page: '1', page_size: '20' });
    expect(fixture.nativeElement.querySelectorAll('[data-testid="up-row"]').length).toBe(2);
    expect(fixture.nativeElement.querySelector('[data-testid="ud-evidence"]')).not.toBeNull();
    expect(fixture.nativeElement.querySelectorAll('[data-testid="ud-finding"]').length).toBe(2);
  });

  it('filters impact to active modules', () => {
    const { fixture } = create('en');
    const items: HTMLElement[] = Array.from(fixture.nativeElement.querySelectorAll('[data-testid="ud-impact-item"]'));
    const text = items.map(i => i.textContent ?? '');
    expect(text.length).toBe(2);
    expect(text.some(t => t.includes('Quotes gain a validity date.'))).toBe(true);
    expect(text.some(t => t.includes('Faster list pages.'))).toBe(true);
    expect(text.some(t => t.includes('Risk scores'))).toBe(false);
  });

  it('shows impact in Arabic for an Arabic user', () => {
    const { fixture } = create('ar');
    const text = fixture.nativeElement.querySelector('[data-testid="ud-impact"]').textContent as string;
    expect(text).toContain('تحمل عروض الأسعار تاريخ صلاحية.');
    expect(text).not.toContain('Quotes gain');
  });

  it('keeps only platform items when the module list cannot be read', () => {
    const { fixture } = create('en', new Error('forbidden'));
    const items = fixture.nativeElement.querySelectorAll('[data-testid="ud-impact-item"]');
    expect(items.length).toBe(1);
    expect(items[0].textContent).toContain('Faster list pages.');
  });

  it('shows old-binary check result', () => {
    const { fixture } = create('en');
    const old: HTMLElement = fixture.nativeElement.querySelector('[data-testid="ud-old-binary"]');
    expect(old.getAttribute('data-ok')).toBe('false');
    expect(old.textContent).toContain('ops.upgrades.oldBinaryFailed');
    expect(old.textContent).toContain('the 2.3 binary refused the new schema');
    expect(fixture.nativeElement.querySelector('[data-testid="ud-customer-tests"]').textContent).toContain('4');
    expect(fixture.nativeElement.querySelector('[data-testid="ud-conflicts"]').textContent).toContain('view:account_list');
  });

  it('opens another upgrade and shows its rollback status', () => {
    const { fixture } = create('en');
    const picks: HTMLButtonElement[] = Array.from(fixture.nativeElement.querySelectorAll('.up-pick'));
    picks[1].click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="ud-rollback"]').textContent).toContain('ops.upgrades.rollbackState.done');
    expect(fixture.nativeElement.querySelector('[data-testid="ud-old-binary"]')).toBeNull();
  });

  it('rollback state follows status and the contract step', () => {
    expect(rollbackState(UPGRADE())).toBe('open');
    expect(rollbackState(UPGRADE({ contract_applied_at: '2026-10-20T00:00:00Z' }))).toBe('closed');
    expect(rollbackState(UPGRADE({ status: 'rolled_back' }))).toBe('done');
    expect(rollbackState(UPGRADE({ check_report: null }))).toBe('none');
  });

  it('activeImpact falls back to English when the Arabic text is missing', () => {
    const out = activeImpact([{ module: 'sales', en: 'Only English.', ar: '' }], new Set(['sales']), 'ar');
    expect(out).toEqual([{ module: 'sales', text: 'Only English.' }]);
  });
});
