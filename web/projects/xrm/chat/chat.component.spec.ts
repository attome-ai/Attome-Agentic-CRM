import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, AuthService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatChannel, ChatComponent, ChatMessage, messageParts } from './chat.component';

const ME = '01900000-0000-7000-8000-00000000000a';

const RECORD_CHANNEL: ChatChannel = {
  id: 'c1', kind: 'record', name: 'Acme renewal', entity_name: 'account', record_id: 'r1',
  retention_days: null, role: 'owner', members: [ME], last_message_at: null, unread: 2,
};

function message(over: Partial<ChatMessage>): ChatMessage {
  return {
    id: 'm1', channel_id: 'c1', thread_root_id: null, author_id: ME, body: 'hi', file_id: null,
    created_at: '2026-10-19T09:00:00Z', deleted: false, reply_count: 0, ...over,
  };
}

describe('ChatComponent', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = { get: vi.fn(), post: vi.fn() };
    TestBed.configureTestingModule({
      imports: [ChatComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: { userId: signal<string | null>(ME) } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, intlLocale: () => 'en-US', current: signal('en') },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ChatComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(id: string) =>
      el.querySelector<T>(`[data-testid="${id}"]`);
    const all = (id: string) => el.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`);
    return { fixture, el, q, all };
  }

  it('splits messages into text, mentions and record cards', () => {
    expect(messageParts('Ask @[user:u1] about @[record:account/r9] now')).toEqual([
      { kind: 'text', text: 'Ask ' },
      { kind: 'mention', target: 'user', id: 'u1' },
      { kind: 'text', text: ' about ' },
      { kind: 'record', entity: 'account', id: 'r9' },
      { kind: 'text', text: ' now' },
    ]);
    expect(messageParts('@[record:broken]')).toEqual([{ kind: 'text', text: '@[record:broken]' }]);
    expect(messageParts('')).toEqual([]);
  });

  it('lists channels, opens one oldest-first and marks it read', () => {
    api.get.mockImplementation((path: string) => path === '/api/v1/chat/channels'
      ? of({ items: [RECORD_CHANNEL], total: 1, page: 1, page_size: 100 })
      : of({ items: [message({ id: 'm2', body: 'second' }), message({ id: 'm1', body: 'see @[record:account/r1]' })] }));
    api.post.mockReturnValue(of(undefined));
    const { fixture, q, all } = render();
    expect(all('chat-channel').length).toBe(1);
    q('chat-channel')!.click();
    fixture.detectChanges();
    const shown = all('chat-message');
    expect(shown.length).toBe(2);
    expect(shown[0].textContent).toContain('account');
    expect(q('chat-record-card')).not.toBeNull();
    expect(api.post).toHaveBeenCalledWith('/api/v1/chat/channels/c1/read', {});
  });

  it('sends a message and saves one to the channel\'s record', () => {
    api.get.mockImplementation((path: string) => path === '/api/v1/chat/channels'
      ? of({ items: [{ ...RECORD_CHANNEL, unread: 0 }] })
      : of({ items: [message({ body: 'decision: renew' })] }));
    api.post.mockImplementation((path: string) =>
      path.endsWith('/messages') ? of(message({ id: 'm3', body: 'ok' })) : of({ id: 'n1' }));
    const { fixture, q, all } = render();
    q('chat-channel')!.click();
    fixture.detectChanges();

    const draft = q<HTMLTextAreaElement>('chat-draft')!;
    draft.value = '  ok  ';
    draft.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('chat-send')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/chat/channels/c1/messages', { body: 'ok' });
    expect(all('chat-message').length).toBe(2);

    q('chat-save')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/note', {
      entity_name: 'account', record_id: 'r1', title: 'chat.noteTitle', note_text: 'decision: renew',
    });
    expect(q('chat-notice')?.textContent).toContain('chat.saved');
  });

  it('says when channels cannot be loaded', () => {
    api.get.mockReturnValue(throwError(() => ({ kind: 'internal_error' })));
    const { q } = render();
    expect(q('chat-error')?.textContent).toContain('chat.loadFailed');
  });
});
