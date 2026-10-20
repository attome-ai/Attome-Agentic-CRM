import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AdminConsoleComponent } from './admin-console.component';

const SETTINGS = [
  { key: 'core.locale', area: 'general', description: 'Preferred language and region', description_ar: 'اللغة والمنطقة المفضلة', id: 's-1' },
  { key: 'auth.mfa_required', area: 'security', description: 'Require a second factor', description_ar: 'اشتراط عامل ثانٍ', id: null },
  { key: 'ai.budget', area: 'ai', description: 'Monthly AI spend', description_ar: null, id: 's-3' },
];

describe('AdminConsoleComponent (U10-T3)', () => {
  function setUp(lang = 'en') {
    const api = {
      get: vi.fn((path: string) => path === '/api/v1/admin/settings'
        ? of({ items: SETTINGS })
        : of({ items: [{ id: 'a-1', changed_on: '2026-10-01T10:00:00Z', user_name: 'Huda', user_email: 'h@example.test' }], total: 1, page: 1, page_size: 50 })),
    };
    TestBed.configureTestingModule({
      imports: [AdminConsoleComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal(lang), intlLocale: signal('en-US'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(AdminConsoleComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, api };
  }

  const keys = (root: HTMLElement) =>
    Array.from(root.querySelectorAll('[data-setting]')).map(e => e.getAttribute('data-setting'));

  it('lists settings by area', () => {
    const { fixture, root } = setUp();
    expect(keys(root)).toEqual(['core.locale', 'auth.mfa_required', 'ai.budget']);
    (root.querySelector('[data-area="security"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(keys(root)).toEqual(['auth.mfa_required']);
    expect(root.querySelector('[data-screen="/xrm/admin/secrets"]')).not.toBeNull();
    expect(root.querySelector('[data-screen="/xrm/admin/caches"]')).toBeNull();
  });

  it('finds a setting by its English or Arabic description', () => {
    const { fixture, root } = setUp();
    fixture.componentInstance.query.set('second factor');
    fixture.detectChanges();
    expect(keys(root)).toEqual(['auth.mfa_required']);
    fixture.componentInstance.query.set('اللغة');
    fixture.detectChanges();
    expect(keys(root)).toEqual(['core.locale']);
  });

  it('finds an admin screen by name', () => {
    const { fixture, root } = setUp();
    fixture.componentInstance.query.set('caches');
    fixture.detectChanges();
    expect(root.querySelector('[data-screen="/xrm/admin/caches"]')).not.toBeNull();
    expect(root.querySelector('[data-screen="/xrm/admin/secrets"]')).toBeNull();
  });

  it('shows a setting\'s change history from the audit trail', () => {
    const { fixture, root, api } = setUp();
    fixture.componentInstance.open(SETTINGS[0] as never);
    fixture.detectChanges();
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/audit/search', {
      entity_name: 'setting', record_id: 's-1', page: '1', page_size: '50',
    });
    expect(root.querySelectorAll('[data-history-row]').length).toBe(1);
    expect(root.querySelector('[data-history-row]')?.textContent).toContain('Huda');
  });

  it('a setting never changed has no history to ask for', () => {
    const { fixture, root, api } = setUp();
    fixture.componentInstance.open(SETTINGS[1] as never);
    fixture.detectChanges();
    expect(api.get).toHaveBeenCalledTimes(1);
    expect(root.querySelector('[data-history-empty]')).not.toBeNull();
  });
});
