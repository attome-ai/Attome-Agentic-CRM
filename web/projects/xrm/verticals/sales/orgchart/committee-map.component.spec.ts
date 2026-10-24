import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CommitteeMapComponent, committeeRoots, influenceLines } from './committee-map.component';
import { layoutChart } from './org-chart.component';
import { DealMap, OrgChartService, OrgNode } from './orgchart.service';

const person = (id: string, name: string, children: OrgNode[] = []): OrgNode => ({
  id, full_name: name, is_former_employee: false, children,
});

const dealMap = (overrides: Partial<DealMap> = {}): DealMap => ({
  opportunity_id: 'opp',
  account_id: 'acc',
  chart: { roots: [person('ceo', 'Ceo', [person('a', 'Amal'), person('b', 'Badr')])], unplaced: [], companies: [] },
  contacts: [
    { contact_id: 'a', full_name: 'Amal', role: 'champion', is_primary: true, influence: 'high', attitude: 'supporter', met_recently: true },
    { contact_id: 'b', full_name: 'Badr', role: 'technical_buyer', is_primary: false, influence: null, attitude: null, met_recently: false },
  ],
  influences: [{ from_contact: 'a', to_contact: 'b' }],
  required_roles: ['economic_buyer', 'champion'],
  gaps: [{ kind: 'missing_role', role: 'economic_buyer' }],
  gaps_computed_at: null,
  ...overrides,
});

describe('committee map helpers (D23-T12)', () => {
  it('adds deal contacts missing from the chart as roots', () => {
    const roots = committeeRoots(dealMap({
      chart: null,
      contacts: [{ contact_id: 'x', full_name: 'Xena', is_primary: false, met_recently: false }],
    }));
    expect(roots.map(r => r.id)).toEqual(['x']);
  });

  it('draws an influence line only between placed cards', () => {
    const map = dealMap({ influences: [{ from_contact: 'a', to_contact: 'b' }, { from_contact: 'a', to_contact: 'gone' }] });
    const lines = influenceLines(layoutChart(committeeRoots(map), false), map.influences);
    expect(lines.map(l => l.to)).toEqual(['b']);
    expect(lines[0].path.startsWith('M')).toBe(true);
  });
});

describe('CommitteeMapComponent (D23-T12)', () => {
  const current = signal('en');
  let service: { committeeMap: ReturnType<typeof vi.fn>; addInfluence: ReturnType<typeof vi.fn> };
  let map: DealMap;

  beforeEach(() => {
    current.set('en');
    map = dealMap();
    service = { committeeMap: vi.fn(() => of(map)), addInfluence: vi.fn(() => of({ id: 'rel' })) };
    TestBed.configureTestingModule({
      imports: [CommitteeMapComponent],
      providers: [
        provideRouter([]),
        { provide: OrgChartService, useValue: service },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => (k === 'salesCommittee.roles.economic_buyer' ? 'Economic buyer' : k),
            current, errorText: () => 'failed', isRtl: () => current() === 'ar',
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(CommitteeMapComponent);
    fixture.componentRef.setInput('id', 'opp');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  function card(root: HTMLElement, id: string): HTMLElement {
    return root.querySelector(`[data-testid="cm-card"][data-id="${id}"]`) as HTMLElement;
  }

  it('gap list shows missing economic buyer', () => {
    const root: HTMLElement = render().nativeElement;
    expect(service.committeeMap).toHaveBeenCalledWith('opp');
    const gaps = root.querySelectorAll('[data-testid="cm-gap"]');
    expect(gaps.length).toBe(1);
    expect(gaps[0].textContent).toContain('Economic buyer');
    expect(gaps[0].querySelector('[data-testid="cm-add-role"]')).not.toBeNull();
  });

  it('shows badges, hides attitude the API left out, and draws influence lines', () => {
    const root: HTMLElement = render().nativeElement;
    expect(card(root, 'a').querySelector('[data-testid="cm-attitude"]')?.textContent).toContain('supporter');
    expect(card(root, 'a').querySelector('[data-testid="cm-influence-badge"]')).not.toBeNull();
    expect(card(root, 'b').querySelector('[data-testid="cm-attitude"]')).toBeNull();
    expect(card(root, 'b').querySelector('[data-testid="cm-influence-badge"]')).toBeNull();
    expect(card(root, 'ceo').querySelector('[data-testid="cm-handle"]')).toBeNull();
    expect(root.querySelectorAll('[data-testid="cm-influence"]').length).toBe(1);
    // O7 strength appears only when the API returns it.
    expect(root.querySelector('[data-testid="cm-strength"]')).toBeNull();
  });

  it('shows strength when present', () => {
    map = dealMap({ contacts: [{ contact_id: 'a', full_name: 'Amal', is_primary: false, met_recently: false, strength: 72 }] });
    const root: HTMLElement = render().nativeElement;
    expect(card(root, 'a').querySelector('[data-testid="cm-strength"]')?.textContent).toContain('72');
  });

  it('drag from a handle records an influence', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (card(root, 'b').querySelector('[data-testid="cm-handle"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    card(root, 'a').dispatchEvent(new Event('drop'));
    fixture.detectChanges();
    expect(service.addInfluence).toHaveBeenCalledWith('b', 'a');
    expect(service.committeeMap).toHaveBeenCalledTimes(2);
  });

  it('does not record a link twice or onto a non-member', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const handle = card(root, 'a').querySelector('[data-testid="cm-handle"]') as HTMLElement;
    handle.dispatchEvent(new Event('dragstart'));
    card(root, 'b').dispatchEvent(new Event('drop'));
    handle.dispatchEvent(new Event('dragstart'));
    card(root, 'ceo').dispatchEvent(new Event('drop'));
    expect(service.addInfluence).not.toHaveBeenCalled();
  });

  it('mirrors in Arabic', () => {
    current.set('ar');
    const root: HTMLElement = render().nativeElement;
    expect(root.querySelector('[data-testid="cm"]')?.getAttribute('dir')).toBe('rtl');
  });
});
