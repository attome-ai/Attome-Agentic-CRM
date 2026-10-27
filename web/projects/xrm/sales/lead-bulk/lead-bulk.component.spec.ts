import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LeadConvertApiService } from '../lead-convert-api';
import { LEAD_BULK_MAX, LeadBulkComponent } from './lead-bulk.component';

describe('LeadBulkComponent (D3-T3)', () => {
  function setUp(ids: string[]) {
    const api = {
      lead: vi.fn((id: string) => of({ id, row_version: 3, name: id, status: 'qualified' })),
      convert: vi.fn((id: string) => (id === 'bad' ? throwError(() => new Error('409')) : of({}))),
      disqualify: vi.fn(() => of({})),
    };
    const finished = vi.fn();
    TestBed.configureTestingModule({
      imports: [LeadBulkComponent],
      providers: [
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
    const fixture = TestBed.createComponent(LeadBulkComponent);
    fixture.componentRef.setInput('recordIds', ids);
    fixture.componentRef.setInput('finished', finished);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, api, finished };
  }

  it('converts each lead with its version and counts the ones that fail', () => {
    const { cmp, api, finished, fixture, el } = setUp(['a', 'bad', 'c']);
    cmp.convertAll();
    expect(api.convert).toHaveBeenCalledTimes(3);
    expect(api.convert).toHaveBeenCalledWith('a', {}, 3);
    expect(cmp.result()).toEqual({ done: 2, failed: 1 });
    expect(finished).toHaveBeenCalledOnce();
    fixture.detectChanges();
    expect(el.querySelector('[data-lead-bulk-result]')?.textContent).toContain('"failed":1');
  });

  it('disqualifies with the chosen reason', () => {
    const { cmp, api, el } = setUp(['a', 'b']);
    const select = el.querySelector('[data-lead-bulk-reason]') as HTMLSelectElement;
    select.value = 'competitor';
    select.dispatchEvent(new Event('change'));
    cmp.disqualifyAll();
    expect(api.disqualify).toHaveBeenCalledWith('a', 'competitor', 3);
    expect(api.disqualify).toHaveBeenCalledWith('b', 'competitor', 3);
    expect(cmp.result()).toEqual({ done: 2, failed: 0 });
  });

  it('refuses a selection over the cap', () => {
    const { cmp, api } = setUp(Array.from({ length: LEAD_BULK_MAX + 1 }, (_, i) => `l${i}`));
    cmp.convertAll();
    expect(cmp.tooMany()).toBe(true);
    expect(api.lead).not.toHaveBeenCalled();
  });
});
