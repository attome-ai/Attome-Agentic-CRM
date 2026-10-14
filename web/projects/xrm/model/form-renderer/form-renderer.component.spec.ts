import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { FormRendererComponent, controlFor } from './form-renderer.component';

const PLAN = {
  id: 'f1', name: 'Contact', entity: 'contact',
  sections: [
    { label: 'Main', fields: [
      { attribute: 'full_name', label: 'Full name', field_type: 3, required: true },
      { attribute: 'age', label: 'Age', field_type: 1, required: false },
      { attribute: 'active', label: 'Active', field_type: 6, required: false },
    ] },
  ],
};

describe('controlFor', () => {
  it('maps field types to their editors', () => {
    expect(controlFor(3)).toBe('text');
    expect(controlFor(1)).toBe('number');
    expect(controlFor(2)).toBe('number');
    expect(controlFor(5)).toBe('date');
    expect(controlFor(6)).toBe('checkbox');
    expect(controlFor(16)).toBe('readonly');
    expect(controlFor(99)).toBe('text');
  });
});

describe('FormRendererComponent', () => {
  let svc: { formPlan: ReturnType<typeof vi.fn>; record: ReturnType<typeof vi.fn>; updateRecord: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = {
      formPlan: vi.fn().mockReturnValue(of(PLAN)),
      record: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 4, data: { full_name: 'Ada', age: 36, active: true } })),
      updateRecord: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 5, data: { full_name: 'Ada L.', age: 36, active: true } })),
    };
    TestBed.configureTestingModule({
      imports: [FormRendererComponent],
      providers: [
        { provide: ModelService, useValue: svc },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render(recordId: string | null) {
    const fixture = TestBed.createComponent(FormRendererComponent);
    fixture.componentRef.setInput('formId', 'f1');
    fixture.componentRef.setInput('recordId', recordId);
    fixture.detectChanges();
    return fixture;
  }

  it('draws each section and field of the plan with the record\'s values', () => {
    const fixture = render('r1');
    expect(svc.formPlan).toHaveBeenCalledWith('f1');
    expect(svc.record).toHaveBeenCalledWith('contact', 'r1');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('legend')?.textContent?.trim()).toBe('Main');
    const name = el.querySelector<HTMLInputElement>('[data-attribute="full_name"] input');
    expect(name?.value).toBe('Ada');
    expect(el.querySelector('[data-attribute="age"] input')?.getAttribute('type')).toBe('number');
    expect(el.querySelector<HTMLInputElement>('[data-attribute="active"] input')?.checked).toBe(true);
  });

  it('saves only the changed fields with the record\'s row version', () => {
    const fixture = render('r1');
    const cmp = fixture.componentInstance;
    cmp.set(PLAN.sections[0].fields[0], 'Ada L.');
    expect(cmp.changed()).toEqual(['full_name']);
    cmp.save();
    expect(svc.updateRecord).toHaveBeenCalledWith('contact', 'r1', { full_name: 'Ada L.' }, 4);
    expect(cmp.saved()).toBe(true);
    expect(cmp.changed()).toEqual([]);
  });

  it('draws an empty form without a record and offers no save', () => {
    const fixture = render(null);
    expect(svc.record).not.toHaveBeenCalled();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="form-renderer"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="form-renderer-save"]')).toBeNull();
  });
});
