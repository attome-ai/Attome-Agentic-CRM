import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LeadConvertApiService, LeadConvertPreview } from '../lead-convert-api';
import { convertBody, LeadConvertComponent, valueLines } from './lead-convert.component';

describe('LeadConvertComponent (D3-T3)', () => {
  const preview: LeadConvertPreview = {
    lead_id: 'lead-1',
    account: { name: 'Acme', website: 'acme.sa', industry: null },
    contact: { full_name: 'Sara Ali', email: 'sara@acme.sa' },
    opportunity: { name: 'Acme deal' },
    account_matches: [{ record_id: 'acc-9', rule_id: 'r1', rule_name: 'Same domain', score: 0.92 }],
    contact_matches: [],
    hidden_matches: 1,
  };

  function setUp(status = 'qualified') {
    const convert = vi.fn(() => of({
      lead_id: 'lead-1', conversion_id: 'conv-1', account_id: 'acc-9', contact_id: 'con-1', opportunity_id: null, moved: 3,
    }));
    const undo = vi.fn(() => of({ lead_id: 'lead-1', conversion_id: 'conv-1', removed: 1 }));
    const api = {
      lead: vi.fn(() => of({ id: 'lead-1', row_version: 7, name: 'Sara', status })),
      preview: vi.fn(() => of(preview)),
      matchName: vi.fn(() => of('Acme Holdings')),
      convert,
      undo,
    };
    TestBed.configureTestingModule({
      imports: [LeadConvertComponent],
      providers: [
        provideRouter([]),
        { provide: LeadConvertApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(LeadConvertComponent);
    fixture.componentRef.setInput('recordId', 'lead-1');
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, api };
  }

  it('shows the matches by name with their rule, and the values each record gets', () => {
    const { cmp, el } = setUp();
    expect(cmp.accountMatches()).toEqual([{ id: 'acc-9', name: 'Acme Holdings', rule: 'Same domain', percent: 92 }]);
    const account = el.querySelector('[data-target="account"]')!;
    expect(account.textContent).toContain('"name":"Acme Holdings"');
    expect(account.textContent).toContain('acme.sa');
    expect(account.textContent).not.toContain('industry');
    expect(el.textContent).toContain('leadConvert.hiddenMatches {"count":1}');
  });

  it('sends create, link and skip as chosen, with the lead version', () => {
    const { cmp, el, fixture, api } = setUp();
    (el.querySelector('[data-link="account:acc-9"]') as HTMLInputElement).click();
    (el.querySelector('[data-skip="opportunity"]') as HTMLInputElement).click();
    fixture.detectChanges();
    (el.querySelector('[data-lead-confirm]') as HTMLButtonElement).click();
    expect(api.convert).toHaveBeenCalledWith('lead-1', {
      account: { mode: 'link', id: 'acc-9' }, contact: { mode: 'create' }, opportunity: { mode: 'skip' },
    }, 7);
    fixture.detectChanges();
    expect(cmp.converted()?.conversion_id).toBe('conv-1');
    expect(el.querySelector('[data-lead-converted]')?.textContent).toContain('"moved":3');
  });

  it('undoes a conversion and reloads the lead', () => {
    const { cmp, fixture, el, api } = setUp();
    cmp.confirm();
    fixture.detectChanges();
    (el.querySelector('[data-lead-undo]') as HTMLButtonElement).click();
    expect(api.undo).toHaveBeenCalledWith('conv-1');
    expect(cmp.undone()).toBe(true);
    expect(api.preview).toHaveBeenCalledTimes(2);
  });

  it('offers no conversion for a converted lead', () => {
    const { el } = setUp('converted');
    expect(el.querySelector('[data-lead-not-convertible]')).not.toBeNull();
    expect(el.querySelector('[data-lead-confirm]')).toBeNull();
  });

  it('builds the body and value lines purely', () => {
    expect(convertBody({ mode: 'link', id: null }, { mode: 'skip', id: null }, { mode: 'create', id: null })).toEqual({
      account: { mode: 'create' }, contact: { mode: 'skip' }, opportunity: { mode: 'create' },
    });
    expect(valueLines({ a: 'x', b: '', c: null, d: 2 })).toEqual([{ field: 'a', value: 'x' }, { field: 'd', value: '2' }]);
  });
});
