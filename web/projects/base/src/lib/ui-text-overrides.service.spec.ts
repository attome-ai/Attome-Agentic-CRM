import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApiService } from './api.service';
import { LangService, nestKeys } from './lang.service';
import { UiTextOverrides } from './ui-text-overrides.service';

describe('UiTextOverrides (B20-T3)', () => {
  it('nests dotted keys the way a catalogue is shaped', () => {
    expect(nestKeys({ 'xrmForm.save': 'Keep', 'xrmForm.cancel': 'Back', title: 'Home' }))
      .toEqual({ xrmForm: { save: 'Keep', cancel: 'Back' }, title: 'Home' });
  });

  it('lays the current language\'s overrides over the catalogue, and again on a switch', () => {
    const current = signal<'en' | 'ar'>('en');
    const applyOverrides = vi.fn();
    const get = vi.fn((_path: string, params: Record<string, string>) =>
      of({ texts: params['locale'] === 'ar' ? { 'xrmForm.save': 'احفظ' } : { 'xrmForm.save': 'Keep' } }));
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { current, applyOverrides } },
      ],
    });
    const overrides = TestBed.inject(UiTextOverrides);
    overrides.start();
    TestBed.flushEffects();
    expect(get).toHaveBeenCalledWith('/api/v1/i18n/overrides', { locale: 'en' });
    expect(applyOverrides).toHaveBeenLastCalledWith('en', { 'xrmForm.save': 'Keep' });

    current.set('ar');
    TestBed.flushEffects();
    expect(applyOverrides).toHaveBeenLastCalledWith('ar', { 'xrmForm.save': 'احفظ' });
  });
});
