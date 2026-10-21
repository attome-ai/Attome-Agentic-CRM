import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ServiceHandoffsListComponent } from './service-handoffs-list.component';
import type { ServiceHandoff } from './service-handoff.service';

const H1: ServiceHandoff = {
    id: 'h1', ticket_id: 't1', from_kind: 'agent', from_ref: 'a1', to_kind: 'queue', to_ref: 'q1',
    summary: 'Billing dispute', reasoning: 'Needs finance', agent_session_ref: 's1', status: 'pending',
    created_at: '2027-03-01T08:00:00Z', accepted_at: null, returned_at: null, row_version: 1,
};
const H2: ServiceHandoff = {
    id: 'h2', ticket_id: 't2', from_kind: 'user', from_ref: 'u9', to_kind: 'user', to_ref: 'u1',
    summary: 'VIP follow-up', reasoning: 'Account owner is away', agent_session_ref: null, status: 'pending',
    created_at: '2027-03-01T09:00:00Z', accepted_at: null, returned_at: null, row_version: 4,
};
const PENDING: ServiceHandoff[] = [H1, H2];

describe('ServiceHandoffsListComponent (AI7-T6)', () => {
  function create(items: ServiceHandoff[] = PENDING) {
    const get = vi.fn((_: string) => of({ items, total: items.length, page: 1, page_size: 100 }));
    const post = vi.fn((_: string, __: unknown, ___?: unknown) => of(items[0]));
    TestBed.configureTestingModule({
      imports: [ServiceHandoffsListComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(ServiceHandoffsListComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('renders the pending hand-offs', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/service/handoffs?page=1&page_size=100');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('li[data-handoff]').length).toBe(2);
    expect(el.querySelector('li[data-handoff="h1"]')?.textContent).toContain('serviceHandoff.agent');
    expect(el.querySelector('li[data-handoff="h2"]')?.textContent).toContain('serviceHandoff.person');
    expect(el.querySelector('li[data-handoff="h1"] a')?.getAttribute('href')).toContain('id=t1');
  });

  it('accepts with If-Match and shows the empty state', () => {
    const { fixture, post } = create();
    fixture.componentInstance.accept(H2);
    expect(post).toHaveBeenCalledWith('/api/v1/service/handoffs/h2/accept', {}, { ifMatch: 4 });
    TestBed.resetTestingModule();
    const empty = create([]);
    expect((empty.fixture.nativeElement as HTMLElement).querySelector('[data-none]')).not.toBeNull();
  });
});
