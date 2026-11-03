import { TestBed } from '@angular/core/testing';
import { SdkService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RuntimeFormSwitch } from './runtime-form-switch';

function make(get: ReturnType<typeof vi.fn>): RuntimeFormSwitch {
  TestBed.configureTestingModule({ providers: [{ provide: SdkService, useValue: { get } }] });
  return TestBed.inject(RuntimeFormSwitch);
}

describe('RuntimeFormSwitch (A12-T5)', () => {
  it('answers the form an entity is switched to, asking once', () => {
    const get = vi.fn().mockReturnValue(of({ form_id: 'f1' }));
    const forms = make(get);
    expect(forms.formFor('deal')).toBeUndefined();
    expect(forms.formFor('deal')).toBe('f1');
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('keeps the hand-written form when the entity is not switched', () => {
    const forms = make(vi.fn().mockReturnValue(throwError(() => ({ status: 404 }))));
    forms.formFor('lead');
    expect(forms.formFor('lead')).toBeNull();
  });

  it('treats an answer without a form id as not switched', () => {
    const forms = make(vi.fn().mockReturnValue(of({ items: [] })));
    forms.formFor('account');
    expect(forms.formFor('account')).toBeNull();
  });
});
