import { Component, input, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, AuthService, LangService } from '@attome/base';
import { EntityService, NotesPanelComponent } from '@attome/xrm/core/entity';
import { PresenceComponent } from '@attome/xrm/service/workspace';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { InboxComponent, InboxRow, filterRows, toRow } from './inbox.component';

@Component({ selector: 'xrm-service-presence', standalone: true, template: '' })
class FakePresence {
  readonly entity = input<string | null>(null);
  readonly recordId = input<string | null>(null);
}

@Component({ selector: 'xrm-notes-panel', standalone: true, template: '' })
class FakeNotes {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();
}

const row = (over: Partial<InboxRow>): InboxRow => ({
  entity: 'service_ticket', id: 't1', title: 'Broken login', status: 'open', assignee: null,
  messages: 2, last: '2026-10-20T10:00:00Z', rowVersion: 3, ...over,
});

describe('inbox helpers (C8-T1)', () => {
  it('filters open, mine and all', () => {
    const rows = [
      row({ id: 'a' }),
      row({ id: 'b', status: 'closed', assignee: 'u1' }),
      row({ id: 'c', entity: 'lead', status: null }),
    ];
    expect(filterRows(rows, 'open', 'u1').map(r => r.id)).toEqual(['a', 'c']);
    expect(filterRows(rows, 'mine', 'u1').map(r => r.id)).toEqual(['b']);
    expect(filterRows(rows, 'all', null)).toHaveLength(3);
  });

  it('titles a row from the record', () => {
    const c = { entity_name: 'lead', record_id: 'l1', messages: 1, last_message_at: 'x' };
    expect(toRow(c, { name: 'Sara' }, 1).title).toBe('Sara');
    expect(toRow(c, {}, 1).title).toBe('l1');
  });
});

describe('InboxComponent (C8-T1)', () => {
  const api = { get: vi.fn() };
  const entities = { get: vi.fn(), update: vi.fn(), create: vi.fn() };

  beforeEach(() => {
    vi.resetAllMocks();
    api.get.mockImplementation((path: string) => path.endsWith('/mailboxes')
      ? of({ items: [{ id: 'm1', name: 'support@' }], total: 1 })
      : of({ items: [
          { entity_name: 'service_ticket', record_id: 't1', messages: 2, last_message_at: '2026-10-20T10:00:00Z' },
          { entity_name: 'service_ticket', record_id: 'hidden', messages: 1, last_message_at: '2026-10-19T10:00:00Z' },
          { entity_name: 'lead', record_id: 'l1', messages: 1, last_message_at: '2026-10-18T10:00:00Z' },
        ], total: 3 }));
    entities.get.mockImplementation((entity: string, id: string) => {
      if (id === 'hidden') return throwError(() => ({ kind: 'not_found', status: 404, message: '' }));
      return of(entity === 'lead'
        ? { id, row_version: 1, data: { name: 'New prospect' } }
        : { id, row_version: 3, data: { title: 'Broken login', status: 'open' } });
    });
    TestBed.configureTestingModule({
      imports: [InboxComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: EntityService, useValue: entities },
        { provide: AuthService, useValue: { userId: signal('u1') } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'failed' } },
      ],
    });
    TestBed.overrideComponent(InboxComponent, {
      remove: { imports: [PresenceComponent, NotesPanelComponent] },
      add: { imports: [FakePresence, FakeNotes] },
    });
  });

  function render() {
    const fixture = TestBed.createComponent(InboxComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('lists the readable conversations of the first mailbox', () => {
    const fixture = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/service/inbox', { mailbox: 'm1', page_size: '50' });
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="ib-row"]');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('Broken login');
  });

  it('assigns a ticket to the agent at its row version', () => {
    entities.update.mockReturnValue(of({ id: 't1', row_version: 4, data: { title: 'Broken login', status: 'open', assignee_id: 'u1' } }));
    const fixture = render();
    (fixture.nativeElement.querySelector('[data-testid="ib-row"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="ib-assign"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(entities.update).toHaveBeenCalledWith('service_ticket', 't1', { assignee_id: 'u1' }, 3);
    expect(fixture.componentInstance.selected()?.assignee).toBe('u1');
    fixture.componentInstance.filter.set('mine');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('[data-testid="ib-row"]').length).toBe(1);
  });

  it('opens a ticket from a lead conversation', () => {
    entities.create.mockReturnValue(of({ id: 't9', row_version: 1, data: {} }));
    const fixture = render();
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="ib-row"]');
    (rows[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="ib-convert"]') as HTMLButtonElement).click();
    expect(entities.create).toHaveBeenCalledWith('service_ticket', expect.objectContaining({
      title: 'New prospect', channel: 'email', status: 'new', requester_id: 'u1',
    }));
  });
});
