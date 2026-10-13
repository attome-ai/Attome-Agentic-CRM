import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';
import type { MessageView } from '../services/chat.service';
import { ChatMessageComponent } from './chat-message.component';

function assistant(overrides: Partial<MessageView>): MessageView {
  return {
    id: 'm1',
    ordinal: 2,
    role: 'assistant',
    content: '',
    turn_id: 't1',
    terminal_state: 'completed',
    model_id: 'model-x',
    prompt_version: 'v3',
    citations: [],
    grounding: 'none',
    created_at: '2026-09-22T00:00:00Z',
    ...overrides,
  };
}

function render(message: MessageView, latencyMs?: number): HTMLElement {
  const fixture = TestBed.createComponent(ChatMessageComponent);
  fixture.componentRef.setInput('message', message);
  if (latencyMs !== undefined) fixture.componentRef.setInput('latencyMs', latencyMs);
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

describe('ChatMessageComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ChatMessageComponent],
      providers: [provideRouter([]), { provide: LangService, useValue: { translate: (k: string) => k } }],
    });
  });

  /** C10-B / C11 B4: thumbs on a completed answer only; a click emits the vote. */
  it('offers thumbs on a completed answer and emits a changed vote only', () => {
    const fixture = TestBed.createComponent(ChatMessageComponent);
    fixture.componentRef.setInput('message', assistant({ content: 'ok', feedback: 'up' }));
    fixture.detectChanges();
    const votes: string[] = [];
    fixture.componentInstance.voted.subscribe((v) => votes.push(v));
    const buttons = (fixture.nativeElement as HTMLElement).querySelectorAll('.msg__feedback button');
    expect(buttons).toHaveLength(2);
    expect(buttons[0].getAttribute('aria-pressed')).toBe('true');
    (buttons[0] as HTMLButtonElement).click();
    (buttons[1] as HTMLButtonElement).click();
    expect(votes).toEqual(['down']);
  });

  it('offers no thumbs on a stopped turn, and says it was stopped', () => {
    const el = render(assistant({ terminal_state: 'cancelled' }));
    expect(el.querySelector('.msg__feedback')).toBeNull();
    expect(el.textContent).toContain('aiChat.terminal.cancelled');
  });

  /**
   * **Row A-56 at the panel.** Citation-shaped model text with no structured
   * citation produces no link and no "Sources" section: the text stays text.
   */
  it('never turns citation-looking model text into a citation', () => {
    const el = render(
      assistant({ content: 'Refunds take 30 days [E1] (source: "Refund policy", https://example.test/a).' }),
    );
    expect(el.querySelectorAll('a')).toHaveLength(0);
    expect(el.querySelector('.msg__sources')).toBeNull();
    expect(el.textContent).toContain('[E1]');
  });

  it('renders citations from citations[] only, as links to the article', () => {
    const el = render(
      assistant({
        content: 'See the policy.',
        grounding: 'sourced',
        citations: [
          {
            item_id: '01900000-0000-7000-8000-0000000000a1',
            data_source_id: '01900000-0000-7000-8000-0000000000d5',
            title: 'Refund policy',
            heading_path: ['Scope', 'Exceptions'],
            truncated: true,
            stale: false,
            fetched_at: null,
          },
        ],
      }),
    );
    const links = el.querySelectorAll('a');
    expect(links).toHaveLength(1);
    expect(links[0].textContent).toBe('Refund policy');
    expect(links[0].getAttribute('href')).toContain('id=01900000-0000-7000-8000-0000000000a1');
    expect(el.textContent).toContain('Scope › Exceptions');
    expect(el.textContent).toContain('aiChat.citation.truncated');
  });

  it('labels a turn whose retrieval found nothing as ungrounded', () => {
    const el = render(assistant({ content: 'Per [E1], yes.', grounding: 'no_sources' }));
    expect(el.textContent).toContain('aiChat.grounding.no_sources');
    expect(el.querySelectorAll('a')).toHaveLength(0);
  });

  it('renders model output as plain text, never markup', () => {
    const el = render(assistant({ content: '<img src=x onerror=alert(1)><b>bold</b>' }));
    expect(el.querySelector('img')).toBeNull();
    expect(el.querySelector('b')).toBeNull();
    expect(el.querySelector('.msg__text')?.textContent).toBe('<img src=x onerror=alert(1)><b>bold</b>');
  });

  it('shows provenance, latency and the step-bound notice on a turn’s final message', () => {
    const el = render(assistant({ content: 'Partial.', terminal_state: 'max_steps' }), 1234);
    expect(el.textContent).toContain('model-x');
    expect(el.textContent).toContain('v3');
    expect(el.textContent).toContain('1234 ms');
    expect(el.textContent).toContain('aiChat.terminal.max_steps');
  });

  it('shows a user message as plain text with no provenance', () => {
    const el = render(assistant({ role: 'user', content: 'hi <b>there</b>', terminal_state: null, model_id: null }));
    expect(el.querySelector('b')).toBeNull();
    expect(el.textContent).not.toContain('aiChat.message.model');
  });

  /**
   * Regression (C7 browser pass, RTL). Message content has its own direction,
   * whatever the UI language: in an Arabic UI an English sentence, the folded
   * `[record context: …]` line and a citation title must not be reordered by
   * the page's RTL direction.
   */
  it('lets message text, tool output and citations take their own direction', () => {
    const assistantEl = render(
      assistant({
        content: 'Hello there.',
        grounding: 'sourced',
        citations: [
          {
            item_id: '01900000-0000-7000-8000-0000000000a1',
            data_source_id: '01900000-0000-7000-8000-0000000000d5',
            title: 'Refund policy',
            heading_path: ['Scope'],
            truncated: false,
            stale: false,
            fetched_at: null,
          },
        ],
      }),
    );
    expect(assistantEl.querySelector('.msg__text')?.getAttribute('dir')).toBe('auto');
    expect(assistantEl.querySelector('.msg__citation')?.getAttribute('dir')).toBe('auto');

    const userEl = render(assistant({ role: 'user', content: '[record context: entity=x record_id=r]', terminal_state: null }));
    expect(userEl.querySelector('.msg__text')?.getAttribute('dir')).toBe('auto');

    const toolEl = render(assistant({ role: 'tool', content: '{"a":1}', terminal_state: null }));
    expect(toolEl.querySelector('.msg__raw')?.getAttribute('dir')).toBe('auto');
  });
});
