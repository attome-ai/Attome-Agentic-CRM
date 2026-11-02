import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SegmentInsightPanelComponent } from './segment-insight-panel.component';
import { SegmentInsightService } from './segment-insight.service';

const LIST = '019a0000-0000-7000-8000-000000000001';
const PERSON = '019a0000-0000-7000-8000-000000000002';

const AR: Record<string, string> = {
  'segmentInsight.estimated': 'العدد التقديري',
  'segmentInsight.reachable': 'يمكن مراسلتهم بالبريد لغرض',
};

describe('SegmentInsightPanelComponent (E7-T12)', () => {
  const current = signal<'en' | 'ar'>('en');
  const insight = {
    count: vi.fn((list: string, options: { exact?: boolean; purpose?: string } = {}) =>
      of({
        list_id: list,
        count: options.exact ? 1234 : 1200,
        basis: options.exact ? 'exact' : 'estimate',
        reachable: options.purpose ? 987 : null,
      })),
    sample: vi.fn(() => of({ list_id: LIST, target_entity: 'contact', person_ids: [PERSON] })),
    usage: vi.fn(() => of([{ kind: 'journey', id: 'j1', name: 'Welcome', status: 'live' }])),
    explain: vi.fn(),
  };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [SegmentInsightPanelComponent],
      providers: [
        { provide: SegmentInsightService, useValue: insight },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => (current() === 'ar' ? AR[k] ?? k : k),
            isRtl: () => current() === 'ar',
            intlLocale: () => (current() === 'ar' ? 'ar' : 'en'),
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(SegmentInsightPanelComponent);
    fixture.componentRef.setInput('entityName', 'marketing_list');
    fixture.componentRef.setInput('recordId', LIST);
    fixture.detectChanges();
    return fixture;
  }

  it('shows the estimate, the sample and the uses for the list', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(insight.count).toHaveBeenCalledWith(LIST);
    expect(root.querySelector('[data-testid="si-count"]')?.textContent).toContain('1,200');
    expect(root.querySelector('[data-testid="si-sample"]')?.textContent).toContain(PERSON);
    expect(root.querySelector('[data-testid="si-uses"]')?.textContent).toContain('Welcome');
  });

  it('shows the reachable count for a purpose, and the exact count on request', () => {
    const fixture = render();
    const component = fixture.componentInstance;
    (component as unknown as { purpose: string }).purpose = 'newsletter';
    component.reach();
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(insight.count).toHaveBeenCalledWith(LIST, { purpose: 'newsletter' });
    expect(root.querySelector('[data-testid="si-reachable"]')?.textContent).toContain('987');

    component.exact();
    fixture.detectChanges();
    expect(insight.count).toHaveBeenCalledWith(LIST, { exact: true });
    expect(root.querySelector('[data-testid="si-count"]')?.textContent).toContain('1,234');
  });

  it('renders right to left in Arabic, with the numbers left to right', () => {
    current.set('ar');
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="si"]')?.getAttribute('dir')).toBe('rtl');
    const count = root.querySelector('[data-testid="si-count"]') as HTMLElement;
    expect(count.textContent).toContain('العدد التقديري');
    expect(count.querySelector('[dir="ltr"]')?.textContent?.trim()).toBe('1,200');
  });

  it('opens the explanation of a sampled person', () => {
    insight.explain.mockReturnValue(of({ list_id: LIST, person_id: PERSON, member: true, steps: [] }));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-testid="si-why"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(insight.explain).toHaveBeenCalledWith(LIST, PERSON);
    expect(root.querySelector('[data-testid="me"]')).not.toBeNull();
  });
});
