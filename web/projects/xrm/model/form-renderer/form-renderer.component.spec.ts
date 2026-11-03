import { TestBed } from '@angular/core/testing';
import { RulesEvaluatorService, SdkService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { LiveService } from '../live.service';
import { ModelService, tabSections } from '../model.service';
import { FormRendererComponent, controlFor } from './form-renderer.component';
import { sdkFromApi } from '../../testing/sdk-from-api';

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

const SCHEMA = {
  id: 'e1', name: 'contact', plural_name: 'contacts', relationships: [], allowed_actions: ['read', 'update'],
  fields: [
    { name: 'full_name', field_type: 'text', options: null },
    { name: 'age', field_type: 'number', options: null },
    { name: 'active', field_type: 'bool', options: null },
  ],
  business_rules: [
    {
      name: 'minors_hide_active', display_name: null,
      condition: { field: 'age', op: 'lt', value: 18 },
      policies: [{ type: 'hidden', field: 'active' }],
    },
  ],
};

const TABBED = {
  id: 'f2', name: 'Contact', entity: 'contact', form_kind: 'main',
  tabs: [{ label: 'General', sections: 1 }, { label: 'More', sections: 1 }],
  sections: [
    { label: 'Main', columns: 2, fields: [
      { attribute: 'full_name', label: 'Full name', field_type: 3, required: true },
      { attribute: 'age', label: 'Age', field_type: 1, required: false, read_only: true },
    ] },
    { label: 'Other', columns: 1, fields: [
      { attribute: 'active', label: 'Active', field_type: 6, required: false },
    ] },
  ],
};

describe('tabSections', () => {
  it('takes each tab\'s sections in turn, or all of them without tabs', () => {
    expect(tabSections(TABBED, 0).map(s => s.label)).toEqual(['Main']);
    expect(tabSections(TABBED, 1).map(s => s.label)).toEqual(['Other']);
    expect(tabSections(PLAN, 0).map(s => s.label)).toEqual(['Main']);
  });
});

describe('FormRendererComponent', () => {
  let svc: {
    formPlan: ReturnType<typeof vi.fn>; record: ReturnType<typeof vi.fn>;
    updateRecord: ReturnType<typeof vi.fn>; schema: ReturnType<typeof vi.fn>;
    formHooks: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    svc = {
      schema: vi.fn().mockReturnValue(of(SCHEMA)),
      formHooks: vi.fn().mockReturnValue(of({ changes: {}, rejection: null, rejection_translations: {}, events: [] })),
      formPlan: vi.fn().mockReturnValue(of(PLAN)),
      record: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 4, data: { full_name: 'Ada', age: 36, active: true } })),
      updateRecord: vi.fn().mockReturnValue(of({ id: 'r1', row_version: 5, data: { full_name: 'Ada L.', age: 36, active: true } })),
    };
    TestBed.configureTestingModule({
      imports: [FormRendererComponent],
      providers: [
        { provide: ModelService, useValue: svc },
        { provide: SdkService, useValue: sdkFromApi({ post: vi.fn().mockReturnValue(of({ status: 'completed', result: { suggestion: 'AI text' } })) }) },
        { provide: LiveService, useValue: { connect: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key, current: () => 'en' } },
        { provide: RulesEvaluatorService, useValue: { evaluate: vi.fn() } },
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

  it('saves only the changed fields with the record\'s row version', async () => {
    const fixture = render('r1');
    const cmp = fixture.componentInstance;
    cmp.set(PLAN.sections[0].fields[0], 'Ada L.');
    expect(cmp.changed()).toEqual(['full_name']);
    await cmp.save();
    expect(svc.updateRecord).toHaveBeenCalledWith('contact', 'r1', { full_name: 'Ada L.' }, 4);
    expect(cmp.saved()).toBe(true);
    expect(cmp.changed()).toEqual([]);
  });

  it('applies a rule live: it hides a field while its condition holds', () => {
    const fixture = render('r1');
    const el: HTMLElement = fixture.nativeElement;
    expect(svc.schema).toHaveBeenCalledWith('contact');
    expect(el.querySelector('[data-attribute="active"]')).not.toBeNull();
    fixture.componentInstance.set(PLAN.sections[0].fields[1], '12');
    fixture.detectChanges();
    expect(el.querySelector('[data-attribute="active"]')).toBeNull();
  });

  it('draws the tabs and a section\'s columns, and a read-only field disabled', () => {
    svc.formPlan.mockReturnValue(of(TABBED));
    const fixture = render('r1');
    const el: HTMLElement = fixture.nativeElement;
    const tabs = el.querySelectorAll('[role="tab"]');
    expect(tabs.length).toBe(2);
    expect(el.querySelector('fieldset')?.getAttribute('data-columns')).toBe('2');
    expect(el.querySelector<HTMLInputElement>('[data-attribute="age"] input')?.disabled).toBe(true);
    expect(el.querySelector('[data-attribute="active"]')).toBeNull();
    (tabs[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('legend')?.textContent?.trim()).toBe('Other');
    expect(el.querySelector('[data-attribute="active"]')).not.toBeNull();
  });

  it('draws an empty form without a record and offers no save', () => {
    const fixture = render(null);
    expect(svc.record).not.toHaveBeenCalled();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="form-renderer"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="form-renderer-save"]')).toBeNull();
  });
});
