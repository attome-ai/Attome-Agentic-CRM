import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';

import type { PrecheckReport } from './deliverability.service';
import { PrecheckPanelComponent, orderFindings } from './precheck-panel.component';

const report: PrecheckReport = {
  score: 40,
  passed: false,
  findings: [
    { code: 'spam_wording', severity: 'warning', guidance_key: 'deliverabilityGuidance.spam_wording', detail: 'act now' },
    { code: 'never_mailed_audience', severity: 'info', guidance_key: 'deliverabilityGuidance.never_mailed_audience' },
    { code: 'missing_unsubscribe', severity: 'error', guidance_key: 'deliverabilityGuidance.missing_unsubscribe' },
    { code: 'missing_text_part', severity: 'warning', guidance_key: 'deliverabilityGuidance.missing_text_part' },
  ],
};

describe('orderFindings (E6-T13)', () => {
  it('puts the costliest first and keeps the order of equal costs', () => {
    expect(orderFindings(report.findings).map(f => f.code)).toEqual([
      'missing_unsubscribe', 'spam_wording', 'missing_text_part', 'never_mailed_audience',
    ]);
    expect(orderFindings([])).toEqual([]);
  });
});

describe('PrecheckPanelComponent (E6-T13)', () => {
  const current = signal<'en' | 'ar'>('en');

  beforeEach(() => {
    current.set('en');
    TestBed.configureTestingModule({
      imports: [PrecheckPanelComponent],
      providers: [{
        provide: LangService,
        useValue: { current, translate: (k: string) => k, isRtl: () => current() === 'ar' },
      }],
    });
  });

  it('lists the findings in score order under the score', () => {
    const fixture = TestBed.createComponent(PrecheckPanelComponent);
    fixture.componentRef.setInput('report', report);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="dpc-score"]')?.textContent).toContain('40/100');
    expect(root.querySelector('[data-testid="dpc-score"]')?.textContent).toContain('marketingDeliverability.failed');
    const codes = [...root.querySelectorAll('[data-testid="dpc-finding"]')].map(e => e.getAttribute('data-code'));
    expect(codes).toEqual(['missing_unsubscribe', 'spam_wording', 'missing_text_part', 'never_mailed_audience']);
    expect(root.textContent).toContain('act now');
  });

  it('mirrors in Arabic', () => {
    current.set('ar');
    const fixture = TestBed.createComponent(PrecheckPanelComponent);
    fixture.componentRef.setInput('report', { score: 100, passed: true, findings: [] });
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="dpc"]')?.getAttribute('dir')).toBe('rtl');
    expect(root.querySelectorAll('[data-testid="dpc-finding"]').length).toBe(0);
    expect(root.querySelector('[data-testid="dpc-score"]')?.textContent).toContain('marketingDeliverability.passed');
  });
});
