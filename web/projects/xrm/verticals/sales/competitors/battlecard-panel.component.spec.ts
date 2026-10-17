import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { BattlecardPanelComponent, CompetitorCard, SalesBattlecard } from './battlecard-panel.component';

const DEAL = '0190a000-0000-7000-8000-000000000001';
const RIVAL = '0190a000-0000-7000-8000-0000000000c1';

const CARDS: SalesBattlecard[] = [
  { competitor_id: RIVAL, name: 'Rival', status: 'primary', threat_level: 'high', battlecard_ref: 'a1' },
];

const CARD: CompetitorCard = {
  competitor_id: RIVAL,
  competitor: { name: 'Rival', strengths: 'Cheap licences', weaknesses: 'No Arabic support', price_position: 'lower' },
  article: { title: 'Beating Rival', body: 'Lead with the Arabic demo.' },
};

/** Looks a key up in a catalogue, the way the real `LangService` does. */
function lookup(catalog: object, key: string): string {
  const value = key.split('.').reduce<unknown>(
    (node, part) => (node as Record<string, unknown> | undefined)?.[part], catalog);
  return typeof value === 'string' ? value : key;
}

function mount(options: { cards?: SalesBattlecard[] | 'missing'; arabic?: boolean } = {}) {
  const cards = options.cards ?? CARDS;
  const get = vi.fn((path: string) => {
    if (path.endsWith('/battlecards')) {
      return cards === 'missing'
        ? throwError(() => ({ status: 404, message: 'not found' }))
        : of({ items: cards, total: cards.length, page: 1, page_size: cards.length });
    }
    return of(CARD);
  });
  const list = vi.fn((entity: string) => of({
    data: entity === 'competitor_mention'
      ? [{ id: 'm1', entity_id: '', created_at: '', updated_at: '', row_version: 3,
           data: { competitor_ref: RIVAL, snippet: 'we also talk to Rival' } }]
      : [],
    meta: { total: 0, limit: 20, offset: 0 },
  }));
  const post = vi.fn(() => of({}));
  const translate = options.arabic ? (key: string) => lookup(xrmAr, key) : (key: string) => key;
  TestBed.configureTestingModule({
    imports: [BattlecardPanelComponent],
    providers: [
      provideRouter([]),
      { provide: ApiService, useValue: { get, post } },
      { provide: EntityService, useValue: { list, get: vi.fn(() => of({ data: { name: 'Rival' } })) } },
      { provide: LangService, useValue: { translate, current: signal(options.arabic ? 'ar' : 'en') } },
    ],
  });
  const fixture = TestBed.createComponent(BattlecardPanelComponent);
  fixture.componentRef.setInput('opportunityId', DEAL);
  fixture.detectChanges();
  return { fixture, get, post };
}

describe('BattlecardPanelComponent (D25-T9)', () => {
  it('opens battlecard when competitor present', () => {
    const { fixture, get } = mount();
    expect(get).toHaveBeenCalledWith(`/api/v1/sales/opportunities/${DEAL}/battlecards`);
    expect(get).toHaveBeenCalledWith(`/api/v1/sales/competitors/${RIVAL}/card`);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector(`[data-competitor="${RIVAL}"]`)?.getAttribute('aria-selected')).toBe('true');
    expect(el.textContent).toContain('Cheap licences');
    expect(el.textContent).toContain('Lead with the Arabic demo.');
    expect(el.querySelector('[data-mention="m1"]')).not.toBeNull();
  });

  it('stays hidden when competitors are not installed', () => {
    const { fixture } = mount({ cards: 'missing' });
    expect((fixture.nativeElement as HTMLElement).querySelector('section')).toBeNull();
  });

  it('confirms a proposed mention with its row version', () => {
    const { fixture, post } = mount();
    const component = fixture.componentInstance;
    component.decide(component.mentions()[0], true);
    expect(post).toHaveBeenCalledWith('/api/v1/sales/competitor-mentions/m1/confirm', {}, { ifMatch: 3 });
  });

  it('renders right to left', () => {
    const { fixture } = mount({ arabic: true });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('المنافسون وبطاقات المنافسة');
    expect(el.textContent).toContain('تهديد مرتفع');
    expect(el.textContent).toContain('أقل من سعرنا');
    // Mirroring comes from logical properties: no physical sides in the styles.
    const css = Array.from(document.querySelectorAll('style'))
      .map(s => s.textContent ?? '')
      .filter(t => t.includes('.bcp'))
      .join('\n');
    expect(css).toContain('.bcp');
    expect(css).not.toMatch(/(margin|padding|border)-(left|right)|(^|[\s;{])(left|right)\s*:|text-align:\s*(left|right)/);
  });
});
