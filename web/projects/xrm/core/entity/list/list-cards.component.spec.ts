import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { beforeEach, describe, expect, it } from 'vitest';
import { ListCardsComponent, MobileListOptions, SWIPE_DISTANCE, mobileOptions, swipeSide } from './list-cards.component';

function record(id: string, data: Record<string, unknown>): EntityRecord {
  return { id, entity_id: 'e', data, created_at: '', updated_at: '', row_version: 1 } as EntityRecord;
}

const ROWS = [
  record('r1', { subject: 'Call Acme', due_date: '2026-10-20', owner_name: 'Sara', status: 'open' }),
  record('r2', { subject: 'Send quote', due_date: '2026-10-21', owner_name: 'Omar', status: 'open' }),
];

describe('ListCardsComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ListCardsComponent],
      providers: [{ provide: LangService, useValue: { translate: (k: string) => k } }],
    });
  });

  function render(options: MobileListOptions | null, rtl = false) {
    const fixture = TestBed.createComponent(ListCardsComponent);
    fixture.componentRef.setInput('records', ROWS);
    fixture.componentRef.setInput('columns', ['subject', 'due_date', 'owner_name', 'status']);
    fixture.componentRef.setInput('options', options);
    fixture.componentRef.setInput('rtl', rtl);
    const fired: { action: string; id: string }[] = [];
    fixture.componentInstance.activate.subscribe(e => fired.push({ action: e.action, id: e.record.id }));
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const cards = () => el.querySelectorAll<HTMLElement>('[data-testid="list-card"]');
    // MouseEvent carries clientX everywhere; not every test DOM has PointerEvent.
    const swipe = (card: HTMLElement, dx: number) => {
      card.dispatchEvent(new MouseEvent('pointerdown', { clientX: 200 }));
      card.dispatchEvent(new MouseEvent('pointermove', { clientX: 200 + dx }));
      card.dispatchEvent(new MouseEvent('pointerup', { clientX: 200 + dx }));
      fixture.detectChanges();
    };
    return { fixture, cards, fired, swipe };
  }

  it('renders cards under 600px', () => {
    const { cards } = render({ card_title: 'subject', card_lines: ['due_date'] });
    expect(cards().length).toBe(2);
    expect(cards()[0].textContent).toContain('Call Acme');
    expect(cards()[0].textContent).toContain('2026-10-20');
    expect(cards()[0].textContent).not.toContain('Sara');
    // Without settings: the first column, then the next two.
    const plain = render(null).cards()[1].textContent ?? '';
    expect(plain).toContain('Send quote');
    expect(plain).toContain('Omar');
  });

  it('swipe end runs action', () => {
    const { cards, fired, swipe } = render({ swipe_start: 'call', swipe_end: 'complete' });
    swipe(cards()[0], SWIPE_DISTANCE + 10);
    expect(fired).toEqual([{ action: 'complete', id: 'r1' }]);
    swipe(cards()[1], -(SWIPE_DISTANCE + 10));
    expect(fired[1]).toEqual({ action: 'call', id: 'r2' });
    swipe(cards()[0], 10);
    expect(fired.length).toBe(2);
  });

  it('swipe mirrors in rtl', () => {
    expect(swipeSide(100, false)).toBe('end');
    expect(swipeSide(100, true)).toBe('start');
    expect(swipeSide(-100, true)).toBe('end');
    expect(swipeSide(20, false)).toBeNull();
    const { cards, fired, swipe } = render({ swipe_start: 'call', swipe_end: 'complete' }, true);
    swipe(cards()[0], -(SWIPE_DISTANCE + 10));
    expect(fired).toEqual([{ action: 'complete', id: 'r1' }]);
  });

  it('reads only valid phone settings from a view', () => {
    expect(mobileOptions({ mobile: { card_title: 'subject', swipe_end: 'delete' } }))
      .toEqual({ card_title: 'subject', card_lines: undefined, swipe_start: null, swipe_end: null });
    expect(mobileOptions({})).toBeNull();
    expect(mobileOptions(undefined)).toBeNull();
  });
});
