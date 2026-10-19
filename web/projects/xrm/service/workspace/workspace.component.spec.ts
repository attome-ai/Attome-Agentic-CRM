import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { WorkspaceComponent } from './workspace.component';
import { MAX_SESSIONS, SessionTab, WorkspaceService, openSession } from './workspace.service';

describe('openSession', () => {
  it('adds a new session, keeps an open one, and drops the oldest past the limit', () => {
    let tabs: SessionTab[] = openSession([], 'service_ticket', 't1', 'Printer');
    tabs = [{ ...tabs[0], draft: 'half a reply' }];
    tabs = openSession(tabs, 'service_ticket', 't1', 'Printer');
    expect(tabs).toHaveLength(1);
    expect(tabs[0].draft).toBe('half a reply');
    for (let i = 2; i <= MAX_SESSIONS + 1; i++) tabs = openSession(tabs, 'service_ticket', `t${i}`, `T${i}`);
    expect(tabs).toHaveLength(MAX_SESSIONS);
    expect(tabs[0].recordId).toBe('t2');
  });
});

describe('WorkspaceComponent', () => {
  const svc = {
    myWork: vi.fn(),
    queues: vi.fn(),
    conversations: vi.fn(),
    record: vi.fn(),
  };

  beforeEach(() => {
    vi.resetAllMocks();
    sessionStorage.clear();
    svc.myWork.mockReturnValue(of([
      { provider: 'service', source_entity: 'service_ticket', record_id: 't1', title: 'Printer down', state: 'open' },
      { provider: 'service', source_entity: 'service_ticket', record_id: 't2', title: 'VPN', state: 'new' },
    ]));
    svc.queues.mockReturnValue(of([{ id: 'q1', name: 'IT' }]));
    svc.conversations.mockReturnValue(of([{ id: 'w1', title: 'Chat', reference: 'REQ-1', created_at: null }]));
    svc.record.mockImplementation((entity: string, id: string) =>
      of({ id, row_version: 1, data: { title: `Record ${id}`, status: 'open', priority: 'high' } }));
    TestBed.configureTestingModule({
      imports: [WorkspaceComponent],
      providers: [
        provideRouter([]),
        { provide: WorkspaceService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' },
        },
        { provide: UserPreferencesService, useValue: { timezone: signal<string | null>('UTC'), calendar: () => null, digits: () => null } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(WorkspaceComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('lists my work, conversations and queues at home', () => {
    const el: HTMLElement = render().nativeElement;
    expect(el.querySelectorAll('[data-testid="ws-work"]').length).toBe(2);
    expect(el.querySelectorAll('[data-testid="ws-conversation"]').length).toBe(1);
    expect(el.textContent).toContain('IT');
  });

  it('opens each case in its own tab and keeps its unsent note across tabs', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    (el.querySelectorAll('[data-testid="ws-work"]')[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="ws-session"]')).not.toBeNull();
    const draft = el.querySelector('[data-testid="ws-draft"]') as HTMLTextAreaElement;
    draft.value = 'Restarted the spooler';
    draft.dispatchEvent(new Event('input'));

    (el.querySelector('[data-testid="ws-home"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    (el.querySelectorAll('[data-testid="ws-work"]')[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid="ws-tab"]').length).toBe(2);

    (el.querySelectorAll('[data-testid="ws-tab"]')[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect((el.querySelector('[data-testid="ws-draft"]') as HTMLTextAreaElement).value).toBe('Restarted the spooler');
    expect(svc.record).toHaveBeenCalledTimes(2);
  });

  it('closes a tab and goes home', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    (el.querySelectorAll('[data-testid="ws-work"]')[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    (el.querySelector('[data-testid="ws-close"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid="ws-tab"]').length).toBe(0);
    expect(el.querySelector('[data-testid="ws-home-panel"]')).not.toBeNull();
  });
});
