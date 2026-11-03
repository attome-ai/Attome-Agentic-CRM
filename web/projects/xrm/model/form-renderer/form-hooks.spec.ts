import { TestBed } from '@angular/core/testing';
import { LangService, RulesEvaluatorService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { LiveService } from '../live.service';
import { ModelService } from '../model.service';
import { sdkFromApi } from '../../testing/sdk-from-api';
import { FormHookAnswer, rejectionText, withChanges } from './form-hooks';
import { FormRendererComponent } from './form-renderer.component';

const PLAN = {
  id: 'f1', name: 'Deal', entity: 'deal',
  sections: [{ label: 'Main', fields: [
    { attribute: 'amount', label: 'Amount', field_type: 1, required: false },
    { attribute: 'tier', label: 'Tier', field_type: 3, required: false },
  ] }],
};

function answer(part: Partial<FormHookAnswer>): FormHookAnswer {
  return { changes: {}, rejection: null, rejection_translations: {}, events: [], ...part };
}

describe('form hook answers (A12-T4)', () => {
  it('reads a refusal in the person\'s language, else in English', () => {
    const refused = answer({ rejection: 'Too big', rejection_translations: { ar: 'كبير جدًا' } });
    expect(rejectionText(refused, 'ar')).toBe('كبير جدًا');
    expect(rejectionText(refused, 'fr')).toBe('Too big');
    expect(rejectionText(answer({}), 'en')).toBeNull();
  });

  it('fills in what the extensions set', () => {
    expect(withChanges({ amount: 5 }, answer({ changes: { tier: 'gold' } }))).toEqual({ amount: 5, tier: 'gold' });
  });
});

describe('FormRendererComponent form hooks (A12-T4)', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    svc = {
      formPlan: vi.fn().mockReturnValue(of(PLAN)),
      schema: vi.fn().mockReturnValue(of({ fields: [], business_rules: [] })),
      record: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 2, data: { amount: 10, tier: null } })),
      updateRecord: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 3, data: { amount: 900, tier: 'gold' } })),
      formHooks: vi.fn().mockReturnValue(of(answer({ events: ['load', 'before_save'], changes: { tier: 'silver' } }))),
    };
    TestBed.configureTestingModule({
      imports: [FormRendererComponent],
      providers: [
        { provide: ModelService, useValue: svc },
        { provide: SdkService, useValue: sdkFromApi({}) },
        { provide: LiveService, useValue: { connect: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key, current: () => 'en' } },
        { provide: RulesEvaluatorService, useValue: { evaluate: vi.fn() } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(FormRendererComponent);
    fixture.componentRef.setInput('formId', 'f1');
    fixture.componentRef.setInput('recordId', 'r1');
    fixture.detectChanges();
    return fixture;
  }

  it('runs the load hooks when the record opens and fills in their values', () => {
    const fixture = render();
    expect(svc['formHooks']).toHaveBeenCalledWith('deal', expect.objectContaining({ event: 'load', record_id: 'r1' }));
    expect(fixture.componentInstance.values()['tier']).toBe('silver');
    expect(fixture.componentInstance.hookEvents()).toEqual(['load', 'before_save']);
  });

  it('a refusal before the save stops it and shows the message', async () => {
    const fixture = render();
    const cmp = fixture.componentInstance;
    svc['formHooks'].mockReturnValue(of(answer({ events: ['load', 'before_save'], rejection: 'Needs approval' })));
    cmp.set(PLAN.sections[0].fields[0], '900');
    await cmp.save();
    fixture.detectChanges();
    expect(svc['updateRecord']).not.toHaveBeenCalled();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="form-renderer-hook-message"]')?.textContent?.trim()).toBe('Needs approval');
  });

  it('saves the values the before-save hooks set with the person\'s change', async () => {
    const fixture = render();
    const cmp = fixture.componentInstance;
    svc['formHooks'].mockReturnValue(of(answer({ events: ['load', 'before_save'], changes: { tier: 'gold' } })));
    cmp.set(PLAN.sections[0].fields[0], '900');
    await cmp.save();
    expect(svc['updateRecord']).toHaveBeenCalledWith('deal', 'r1', { amount: 900, tier: 'gold' }, 2);
  });
});
