import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { RevrecChangePreviewComponent, RevrecChangeService, periodRows } from './revrec-change-preview.component';
import type { ChangePreview } from './revrec-change-preview.component';

const PREVIEW: ChangePreview = {
  change_id: 'c1', contract_id: 'k1', change_kind: 'amendment', treatment: 'prospective',
  overridden: false, status: 'previewed',
  obligations: [{
    obligation_id: 'o1', recognised: '400', old_total: '1200', new_total: '1500',
    lines: [
      { line_id: 'l2', fiscal_period: '2027-06', from: '100', to: '137.5' },
      { line_id: 'l1', fiscal_period: '2027-05', from: '100', to: '137.5' },
    ],
  }],
};

async function render(rtl: boolean): Promise<ComponentFixture<RevrecChangePreviewComponent>> {
  const svc = {
    record: vi.fn(() => of({ data: { preview_json: JSON.stringify(PREVIEW), status: 'previewed' } })),
    apply: vi.fn(() => of({ change_id: 'c1', lines: 2 })),
    discard: vi.fn(() => of({})),
  };
  await TestBed.configureTestingModule({
    imports: [RevrecChangePreviewComponent],
    providers: [
      { provide: RevrecChangeService, useValue: svc },
      {
        provide: LangService,
        useValue: {
          translate: (key: string) => key,
          errorText: () => 'errors.unknown',
          intlLocale: () => (rtl ? 'ar-SA' : 'en-US'),
          isRtl: signal(rtl),
        },
      },
    ],
  }).compileComponents();
  const fixture = TestBed.createComponent(RevrecChangePreviewComponent);
  fixture.componentRef.setInput('changeId', 'c1');
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
  return fixture;
}

describe('RevrecChangePreviewComponent', () => {
  it('shows per-period difference', async () => {
    const fixture = await render(false);
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="period-row"]');
    expect(rows.length).toBe(2);
    expect(periodRows(PREVIEW.obligations[0]).map(r => [r.period, r.difference])).toEqual([
      ['2027-05', 37.5],
      ['2027-06', 37.5],
    ]);
    expect(fixture.nativeElement.querySelector('[data-testid="apply"]')).not.toBeNull();
  });

  it('renders rtl in Arabic', async () => {
    TestBed.resetTestingModule();
    const fixture = await render(true);
    expect(fixture.nativeElement.getAttribute('dir')).toBe('rtl');
  });
});
