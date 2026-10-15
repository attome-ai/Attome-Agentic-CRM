import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { DuplicatesService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DuplicateBannerComponent } from './duplicate-banner.component';
import { DuplicateNotice, duplicateWarningsOf } from './duplicate-notice';

describe('DuplicateBannerComponent (A15-T4/T10)', () => {
  function setUp(notice: DuplicateNotice | null) {
    TestBed.configureTestingModule({
      imports: [DuplicateBannerComponent],
      providers: [
        provideRouter([]),
        { provide: DuplicatesService, useValue: { candidatesForRecord: vi.fn(() => of([])) } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(DuplicateBannerComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.componentRef.setInput('recordId', null);
    fixture.componentRef.setInput('notice', notice);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  const match = { record_id: 'r1', rule_id: 'm1', rule_name: 'Phone', score: 0.92 };

  it('shows hidden-count message', () => {
    const { el } = setUp({ refused: true, action: 'block', matches: [match], hidden: 2 });
    const hidden = el.querySelector('[data-duplicate-hidden]');
    expect(hidden?.textContent).toContain('duplicateBanner.hidden');
    expect(hidden?.textContent).toContain('"count":2');
    expect(el.textContent).toContain('duplicateBanner.blocked');
    expect(el.querySelector('[data-duplicate-reason]')).toBeNull();
  });

  it('asks for a reason under allow_with_reason and emits it', () => {
    const { fixture, el } = setUp({ refused: true, action: 'allow_with_reason', matches: [match], hidden: 0 });
    const emitted: string[] = [];
    fixture.componentInstance.saveWithReason.subscribe(r => emitted.push(r));
    expect(el.querySelector('[data-duplicate-hidden]')).toBeNull();
    const input = el.querySelector<HTMLInputElement>('[data-duplicate-reason]');
    expect(input).not.toBeNull();
    input!.value = 'second branch';
    input!.dispatchEvent(new Event('input'));
    fixture.componentInstance.submitReason();
    expect(emitted).toEqual(['second branch']);
  });

  it('reads the warnings a saved record carries', () => {
    expect(duplicateWarningsOf({ id: 'x' })).toBeNull();
    expect(duplicateWarningsOf({ duplicate_warnings: [match], hidden_duplicates: 1 }))
      .toEqual({ refused: false, action: 'warn', matches: [match], hidden: 1 });
  });
});
