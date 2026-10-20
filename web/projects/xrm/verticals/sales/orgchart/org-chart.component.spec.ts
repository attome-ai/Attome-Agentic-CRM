import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CARD_W, OrgChartComponent, isUnder, layoutChart, matches } from './org-chart.component';
import { OrgChart, OrgChartService, OrgNode } from './orgchart.service';

const person = (id: string, name: string, children: OrgNode[] = []): OrgNode => ({
  id, full_name: name, job_title: null, department: null, department_ar: null,
  is_former_employee: false, children, collapsed_children: null,
});

const ceo = (): OrgNode => person('ceo', 'Ceo', [person('a', 'Amal'), person('b', 'Badr')]);

describe('org chart layout (D23-T11)', () => {
  it('centres a manager over the reports', () => {
    const { cards, connectors, width } = layoutChart([ceo()], false);
    const at = (id: string) => cards.find(c => c.node.id === id)!;
    expect(at('a').x).toBeLessThan(at('b').x);
    expect(at('ceo').x).toBe((at('a').x + at('b').x) / 2);
    expect(at('a').y).toBeGreaterThan(at('ceo').y);
    expect(connectors.map(c => c.to)).toEqual(['a', 'b']);
    expect(width).toBe(2 * CARD_W + 24);
  });

  it('tree mirrors in right to left', () => {
    const ltr = layoutChart([ceo()], false);
    const rtl = layoutChart([ceo()], true);
    const x = (l: typeof ltr, id: string) => l.cards.find(c => c.node.id === id)!.x;
    // The first report is on the right in Arabic.
    expect(x(rtl, 'a')).toBeGreaterThan(x(rtl, 'b'));
    expect(x(rtl, 'a')).toBe(ltr.width - x(ltr, 'a') - CARD_W);
    expect(x(rtl, 'ceo')).toBe(x(ltr, 'ceo'));
  });

  it('finds people and refuses a loop', () => {
    expect(matches(person('x', 'Huda Saleh'), 'huda')).toBe(true);
    expect(matches(person('x', 'Huda Saleh'), '')).toBe(false);
    expect(isUnder([ceo()], 'ceo', 'b')).toBe(true);
    expect(isUnder([ceo()], 'a', 'b')).toBe(false);
  });
});

describe('OrgChartComponent (D23-T11)', () => {
  const service = { chart: vi.fn(), setManager: vi.fn() };
  const current = signal<'en' | 'ar'>('en');
  const chart: OrgChart = { roots: [ceo()], unplaced: [person('u', 'Unplaced')], companies: [{ id: 'acc', name: 'Acme' }] };

  beforeEach(() => {
    vi.resetAllMocks();
    current.set('en');
    service.chart.mockReturnValue(of(chart));
    service.setManager.mockImplementation((contact: string) => of({
      contact_id: contact, row_version: 2, previous_manager_id: contact === 'a' ? 'ceo' : 'b',
    }));
    TestBed.configureTestingModule({
      imports: [OrgChartComponent],
      providers: [
        provideRouter([]),
        { provide: OrgChartService, useValue: service },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k, current, errorText: () => 'failed',
            isRtl: () => current() === 'ar',
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(OrgChartComponent);
    fixture.componentRef.setInput('id', 'acc');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  function card(root: HTMLElement, id: string): HTMLElement {
    return root.querySelector(`[data-testid="oc-card"][data-id="${id}"]`) as HTMLElement;
  }

  it('drag sets manager and undo restores it', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(service.chart).toHaveBeenCalledWith('acc', false, []);
    expect(root.querySelectorAll('[data-testid="oc-card"]').length).toBe(3);

    card(root, 'a').dispatchEvent(new Event('dragstart'));
    card(root, 'b').dispatchEvent(new Event('drop'));
    fixture.detectChanges();
    expect(service.setManager).toHaveBeenCalledWith('a', 'b');
    expect(root.querySelector('[data-testid="oc-undo"]')?.textContent).toContain('Amal');

    (root.querySelector('[data-testid="oc-undo-button"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(service.setManager).toHaveBeenLastCalledWith('a', 'ceo');
    expect(root.querySelector('[data-testid="oc-undo"]')).toBeNull();
  });

  it('refuses a move under the person’s own report', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    card(root, 'ceo').dispatchEvent(new Event('dragstart'));
    card(root, 'a').dispatchEvent(new Event('drop'));
    fixture.detectChanges();
    expect(service.setManager).not.toHaveBeenCalled();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('salesOrgChart.loop');
  });

  it('mirrors in Arabic and lists the unplaced', () => {
    current.set('ar');
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="oc"]')?.getAttribute('dir')).toBe('rtl');
    expect(root.querySelector('[data-testid="oc-unplaced"]')?.textContent).toContain('Unplaced');
  });
});
