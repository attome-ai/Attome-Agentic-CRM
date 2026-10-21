import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ServiceHandoffCardComponent } from './service-handoff-card.component';
import { ServiceHandoff, canHandBack, partyIcon } from './service-handoff.service';

const FROM_AGENT: ServiceHandoff = {
  id: 'h1', ticket_id: 't1', from_kind: 'agent', from_ref: 'a1', to_kind: 'user', to_ref: 'u1',
  summary: 'العميل يطلب استرداداً فوق الحد', reasoning: 'Refunds above 1,000 need a supervisor',
  agent_session_ref: 's1', status: 'accepted', created_at: '2027-03-01T08:00:00Z',
  accepted_at: '2027-03-01T08:10:00Z', returned_at: null, row_version: 2,
};

describe('ServiceHandoffCardComponent (AI7-T6)', () => {
  function create(handoff: ServiceHandoff = FROM_AGENT) {
    const get = vi.fn((path: string) => path.includes('/user_account/')
      ? of({ data: { user_name: 'sara' } })
      : of({ items: [handoff], total: 1, page: 1, page_size: 20 }));
    const post = vi.fn((_: string, __: unknown, ___?: unknown) => of({ ...handoff, status: 'returned' }));
    TestBed.configureTestingModule({
      imports: [ServiceHandoffCardComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(ServiceHandoffCardComponent);
    fixture.componentRef.setInput('ticketId', 't1');
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('shows who handed it to whom, the agent apart from the person', () => {
    const { fixture, get } = create();
    fixture.detectChanges();
    expect(get).toHaveBeenCalledWith('/api/v1/service/tickets/t1/handoffs?page=1&page_size=20');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-from] i')?.className).toContain('la-robot');
    expect(el.querySelector('[data-from]')?.textContent).toContain('serviceHandoff.agent');
    expect(el.querySelector('[data-to]')?.textContent).toContain('sara');
    expect(el.textContent).toContain('Refunds above 1,000 need a supervisor');
  });

  it('hand back requires a note and sends If-Match', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.backOpen.set(true);
    c.note = '   ';
    c.handBack(FROM_AGENT);
    expect(post).not.toHaveBeenCalled();
    expect(c.noteMissing()).toBe(true);
    c.note = ' Approved, refund it ';
    c.handBack(FROM_AGENT);
    expect(post).toHaveBeenCalledWith(
      '/api/v1/service/handoffs/h1/return',
      { note: 'Approved, refund it' },
      { ifMatch: 2 },
    );
  });

  it('offers hand back only for an open agent hand-off', () => {
    expect(canHandBack(FROM_AGENT)).toBe(true);
    expect(canHandBack({ ...FROM_AGENT, from_kind: 'user' })).toBe(false);
    expect(canHandBack({ ...FROM_AGENT, status: 'returned' })).toBe(false);
    expect(partyIcon('queue')).toContain('la-users');
  });
});
