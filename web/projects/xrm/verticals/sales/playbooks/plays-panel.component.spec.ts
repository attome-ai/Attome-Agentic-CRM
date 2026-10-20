import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { PlaysPanelComponent, SalesPlay } from './plays-panel.component';

const DEAL = '0190a000-0000-7000-8000-000000000001';

const PROPOSAL_PLAY: SalesPlay = {
  playbook_id: 'p1',
  name: 'Proposal play',
  name_ar: 'خطة العرض',
  steps: [
    { id: 's2', title: 'Book the review call', guidance: 'Bring the finance lead.', step_order: 2,
      due_after_days: 3, activity_kind: 'meeting' },
    { id: 's1', title: 'Send the proposal', guidance: null, step_order: 1, due_after_days: null,
      activity_kind: 'email' },
  ],
};

/** Looks a key up in a catalogue, the way the real `LangService` does. */
function lookup(catalog: object, key: string): string {
  const value = key.split('.').reduce<unknown>(
    (node, part) => (node as Record<string, unknown> | undefined)?.[part], catalog);
  return typeof value === 'string' ? value : key;
}

function mount(options: { plays?: SalesPlay[] | 'missing'; arabic?: boolean; stage?: string } = {}) {
  const plays = options.plays ?? [PROPOSAL_PLAY];
  const get = vi.fn(() => plays === 'missing'
    ? throwError(() => ({ status: 404, message: 'not found' }))
    : of({ items: plays, total: plays.length, page: 1, page_size: Math.max(plays.length, 1) }));
  const translate = options.arabic ? (key: string) => lookup(xrmAr, key) : (key: string) => key;
  TestBed.configureTestingModule({
    imports: [PlaysPanelComponent],
    providers: [
      { provide: ApiService, useValue: { get } },
      { provide: LangService, useValue: { translate, current: signal(options.arabic ? 'ar' : 'en') } },
    ],
  });
  const fixture = TestBed.createComponent(PlaysPanelComponent);
  fixture.componentRef.setInput('opportunityId', DEAL);
  fixture.componentRef.setInput('stage', options.stage ?? 'proposal');
  fixture.detectChanges();
  return { fixture, get };
}

describe('PlaysPanelComponent (D26-T2)', () => {
  it('shows the plays the server says apply to the deal, steps in the server order', () => {
    const { fixture, get } = mount();
    expect(get).toHaveBeenCalledWith(`/api/v1/sales/opportunities/${DEAL}/plays`);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-play="p1"]')?.textContent).toContain('Proposal play');
    const steps = [...el.querySelectorAll('[data-step]')].map(s => s.getAttribute('data-step'));
    expect(steps).toEqual(['s2', 's1']);
    expect(el.textContent).toContain('Bring the finance lead.');
  });

  it('reloads when the deal moves to another stage', () => {
    const { fixture, get } = mount();
    fixture.componentRef.setInput('stage', 'negotiation');
    fixture.detectChanges();
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('stays hidden when no play applies or playbooks are not installed', () => {
    for (const plays of [[], 'missing'] as const) {
      TestBed.resetTestingModule();
      const { fixture } = mount({ plays: plays === 'missing' ? 'missing' : [] });
      expect((fixture.nativeElement as HTMLElement).querySelector('section')).toBeNull();
    }
  });

  it('uses the Arabic name and catalogue in Arabic', () => {
    const { fixture } = mount({ arabic: true });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('خطة العرض');
    expect(el.textContent).toContain('الخطط المناسبة لهذه الصفقة');
    expect(el.textContent).toContain('اجتماع');
  });
});
