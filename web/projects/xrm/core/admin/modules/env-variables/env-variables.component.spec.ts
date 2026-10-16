import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EnvVariable, EnvVariablesComponent, isMissing, parseDraft, shown } from './env-variables.component';

const VARS: EnvVariable[] = [
  {
    name: 'erp_url', type: 'url', required: true, default: null, description_en: null,
    description_ar: null, value: null, is_set: false, updated_at: null, updated_by: null, row_version: null,
  },
  {
    name: 'erp_key', type: 'secret', required: true, default: null, description_en: null,
    description_ar: null, value: null, is_set: true, updated_at: '2026-10-16T08:00:00Z',
    updated_by: 'u', row_version: 2,
  },
];

describe('EnvVariablesComponent (A30-T3)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: VARS }));
    const put = vi.fn(() => of(undefined));
    TestBed.configureTestingModule({
      imports: [EnvVariablesComponent],
      providers: [
        { provide: ApiService, useValue: { get, put, delete: vi.fn(() => of(undefined)) } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(EnvVariablesComponent);
    fixture.detectChanges();
    return { fixture, get, put };
  }

  it('flags a required variable with no value and never shows a secret', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/env-variables');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-variable="erp_url"]')?.classList.contains('ev-missing')).toBe(true);
    expect(el.querySelector('[data-variable="erp_key"]')?.classList.contains('ev-missing')).toBe(false);
    expect(el.querySelector('[data-variable="erp_key"]')?.textContent).toContain('envVariablesPage.secretSet');
  });

  it('saves a typed value with the row version', () => {
    const { fixture, put } = create();
    const component = fixture.componentInstance;
    component.edit(VARS[0]);
    component.draft = 'https://erp.test.local';
    component.save(VARS[0]);
    expect(put).toHaveBeenCalledWith('/api/v1/admin/env-variables/erp_url', {
      value: 'https://erp.test.local', row_version: null,
    });
    component.edit(VARS[0]);
    component.draft = 'not a url';
    put.mockClear();
    component.save(VARS[0]);
    expect(put).not.toHaveBeenCalled();
  });

  it('parses drafts by type', () => {
    expect(parseDraft('number', '3.5')).toBe(3.5);
    expect(parseDraft('number', '')).toBeUndefined();
    expect(parseDraft('boolean', 'true')).toBe(true);
    expect(parseDraft('url', 'ftp://x')).toBeUndefined();
    expect(isMissing({ ...VARS[0], default: 'https://default.test' })).toBe(false);
    expect(shown(VARS[1])).toBe('');
  });
});
