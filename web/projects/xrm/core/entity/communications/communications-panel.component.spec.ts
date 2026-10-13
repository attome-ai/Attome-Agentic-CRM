import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LangService } from '@attome/base';
import { EntityService } from '../services/entity.service';
import { CommunicationsPanelComponent, toRow } from './communications-panel.component';

describe('CommunicationsPanelComponent', () => {
  it('maps a message to the few fields a reader scans for', () => {
    const row = toRow('c1', {
      channel: 'email', direction: 'outbound', subject: '  Quote  ', body: 'ignored',
      to_addresses: 'ada@example.com', status: 'sent', sent_at: '2026-09-01T08:00:00Z',
      entity_name: 'account', record_id: 'r1', thread_id: 't1', message_id: '<m1>',
    });
    expect(row).toEqual({
      id: 'c1', channel: 'email', direction: 'outbound', title: 'Quote',
      to: 'ada@example.com', status: 'sent', sentAt: '2026-09-01T08:00:00Z',
    });
  });

  it('falls back to a one-line body preview and keeps the receiver', () => {
    const row = toRow('c2', {
      channel: 'web_chat', direction: 'inbound', body: 'Hello\n\nthere', to_addresses: 'desk@x',
    });
    expect(row.title).toBe('Hello there');
    expect(row.to).toBe('desk@x');
  });

  it('lists this record\'s messages newest first, without the repeated link columns', () => {
    const entities = {
      list: vi.fn().mockReturnValue(of({
        data: [{ id: 'c1', data: { channel: 'call', subject: 'Follow-up', entity_name: 'acct', record_id: 'r1' } }],
        meta: { total: 1, limit: 25, offset: 0 },
      })),
    };
    TestBed.configureTestingModule({
      imports: [CommunicationsPanelComponent],
      providers: [
        provideRouter([]),
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en' } },
      ],
    });
    const f = TestBed.createComponent(CommunicationsPanelComponent);
    f.componentRef.setInput('entityName', 'acct');
    f.componentRef.setInput('recordId', 'r1');
    f.detectChanges();

    expect(entities.list).toHaveBeenCalledWith('communication', expect.objectContaining({
      filters: [
        { field: 'entity_name', op: 'eq', value: 'acct' },
        { field: 'record_id', op: 'eq', value: 'r1' },
      ],
      sorts: [{ field: 'sent_at', dir: 'desc' }],
    }));
    const text = (f.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('Follow-up');
    expect(text).not.toContain('acct');
    expect((f.nativeElement as HTMLElement).querySelectorAll('[data-testid="communication-row"]').length).toBe(1);
  });

  it('keeps the list frame, with its headers, when there are no messages', () => {
    const entities = { list: vi.fn().mockReturnValue(of({ data: [], meta: { total: 0, limit: 25, offset: 0 } })) };
    TestBed.configureTestingModule({
      imports: [CommunicationsPanelComponent],
      providers: [
        provideRouter([]),
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en' } },
      ],
    });
    const f = TestBed.createComponent(CommunicationsPanelComponent);
    f.componentRef.setInput('entityName', 'acct');
    f.componentRef.setInput('recordId', 'r1');
    f.detectChanges();
    const root = f.nativeElement as HTMLElement;
    expect(root.querySelector('.xcp-table .xcp-head')?.textContent).toContain('communications.colSubject');
    expect(root.querySelector('.xcp-table [data-testid="communications-empty"]')).not.toBeNull();
  });

  it('renders nothing on the communication entity\'s own form', () => {
    const entities = { list: vi.fn() };
    TestBed.configureTestingModule({
      imports: [CommunicationsPanelComponent],
      providers: [provideRouter([]), { provide: EntityService, useValue: entities }],
    });
    const f = TestBed.createComponent(CommunicationsPanelComponent);
    f.componentRef.setInput('entityName', 'communication');
    f.componentRef.setInput('recordId', 'c1');
    f.detectChanges();
    expect(entities.list).not.toHaveBeenCalled();
  });
});
