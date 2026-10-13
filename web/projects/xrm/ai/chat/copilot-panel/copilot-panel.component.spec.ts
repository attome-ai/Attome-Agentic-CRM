import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { LangService } from '@attome/base';
import { NEVER, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatService } from '../services/chat.service';
import { CHAT_EVENT_SOURCE } from '../services/chat-stream';
import type { EventSourceLike } from '../services/chat-stream';
import { CopilotPanelComponent } from './copilot-panel.component';

/** A stand-in `EventSource` the test drives by hand. */
class FakeSource implements EventSourceLike {
  readonly listeners = new Map<string, (e: MessageEvent<string>) => void>();
  closed = false;
  addEventListener(type: string, listener: (e: MessageEvent<string>) => void): void {
    this.listeners.set(type, listener);
  }
  close(): void {
    this.closed = true;
  }
  emit(type: string, data: unknown): void {
    this.listeners.get(type)?.({ data: JSON.stringify(data) } as MessageEvent<string>);
  }
}

const RECORD = '01900000-0000-7000-8000-0000000000a1';
const CONV = { conversation: { id: 'conv-1' }, governance: {} };

describe('CopilotPanelComponent', () => {
  let chat: Record<string, ReturnType<typeof vi.fn>>;
  let sources: FakeSource[];

  beforeEach(() => {
    chat = {
      listAgents: vi.fn().mockReturnValue(of([{ id: 'agent-1', name: 'Helper' }])),
      start: vi.fn().mockReturnValue(of(CONV)),
      send: vi.fn().mockReturnValue(
        of({ turn_id: 't1', terminal_state: 'completed', text: 'ok', citations: [], grounding: 'none' }),
      ),
      messages: vi.fn().mockReturnValue(of({ items: [], total: 0, page: 1, page_size: 100 })),
      toolCalls: vi.fn().mockReturnValue(of({ items: [], total: 0, page: 1, page_size: 100 })),
      end: vi.fn().mockReturnValue(of(undefined)),
      streamUrl: vi.fn((id: string) => `/stream/${id}`),
      cancel: vi.fn().mockReturnValue(of({ turn_id: 't1', state: 'requested' })),
      feedback: vi.fn().mockReturnValue(of({ message_id: 'm1', vote: 'up', updated_at: 'x' })),
    };
    sources = [];
    TestBed.configureTestingModule({
      imports: [CopilotPanelComponent],
      providers: [
        { provide: ChatService, useValue: chat },
        { provide: Router, useValue: { url: `/xrm/contact/form?id=${RECORD}`, events: NEVER } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
        {
          provide: CHAT_EVENT_SOURCE,
          useValue: () => {
            const source = new FakeSource();
            sources.push(source);
            return source;
          },
        },
      ],
    });
    TestBed.overrideComponent(CopilotPanelComponent, { set: { template: '' } });
  });

  function create() {
    const fixture = TestBed.createComponent(CopilotPanelComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  /**
   * **Row A-66 at the panel.** The record in the URL is sent as `context` — a
   * navigation hint in its own field. The client makes no access decision
   * about it and never folds it into the text; the server decides everything.
   */
  it('sends the viewed record as context, separate from the text', () => {
    const panel = create();
    panel.draft.set('who is this?');
    panel.send();
    expect(chat['start']).toHaveBeenCalledWith('agent-1', 'reversible');
    expect(chat['send']).toHaveBeenCalledWith('conv-1', 'who is this?', {
      entity: 'contact',
      record_id: RECORD,
    });
  });

  it('sends no context when the user switches sharing off', () => {
    const panel = create();
    panel.shareContext.set(false);
    panel.draft.set('hello');
    panel.send();
    expect(chat['send']).toHaveBeenCalledWith('conv-1', 'hello', null);
  });

  it('reuses the conversation for the next message and measures latency per turn', () => {
    const panel = create();
    panel.draft.set('one');
    panel.send();
    panel.draft.set('two');
    panel.send();
    expect(chat['start']).toHaveBeenCalledTimes(1);
    expect(chat['send']).toHaveBeenCalledTimes(2);
    expect(panel.latencyFor({ turn_id: 't1' } as never)).toBeTypeOf('number');
  });

  it('turns proposals into cards and approvals into pending notices, from the tool-call projection', () => {
    chat['toolCalls'].mockReturnValue(
      of({
        items: [
          { tool_call_id: 'a', turn_id: 't1', action_id: 'record.update', status: 'proposed' },
          { tool_call_id: 'b', turn_id: 't1', action_id: 'record.delete', status: 'approval_pending' },
          { tool_call_id: 'c', turn_id: 't1', action_id: 'search.records', status: 'executed' },
        ],
        total: 3,
        page: 1,
        page_size: 100,
      }),
    );
    const panel = create();
    panel.draft.set('go');
    panel.send();
    expect(panel.proposals().map((c) => c.tool_call_id)).toEqual(['a']);
    expect(panel.awaitingApproval().map((c) => c.tool_call_id)).toEqual(['b']);
  });

  /**
   * C11 B1: the ledger records the assistant message that asked for tools, so
   * the model can replay its own calls. With no text it has nothing for a
   * person to read, and the panel does not render an empty bubble for it.
   */
  it('hides an assistant message that only asked for tools', () => {
    const panel = create();
    const row = (role: string, content: string, terminal_state: string | null) =>
      ({ role, content, terminal_state }) as never;
    expect(panel.isShown(row('assistant', '', null))).toBe(false);
    expect(panel.isShown(row('assistant', 'Let me look that up.', null))).toBe(true);
    expect(panel.isShown(row('assistant', '', 'awaiting_confirmation'))).toBe(true);
    expect(panel.isShown(row('user', 'hi', null))).toBe(true);
    expect(panel.isShown(row('tool', '{}', null))).toBe(true);
  });

  /**
   * C11 B4 / row A-79. While the POST is outstanding the panel follows the
   * stream: a delta — which can arrive before `turn.started` — shows as
   * provisional text for that turn, and the answer's `message.completed`
   * clears it; a late delta for the finished turn is ignored.
   */
  it('shows the answer forming from deltas and drops it for the answer', () => {
    chat['send'].mockReturnValue(NEVER);
    const panel = create();
    panel.draft.set('tell me');
    panel.send();
    expect(sources).toHaveLength(1);
    expect(chat['streamUrl']).toHaveBeenCalledWith('conv-1');
    const stream = sources[0];

    stream.emit('message.delta', { turn_id: 't1', text: 'Hel' });
    expect(panel.runningTurnId()).toBe('t1');
    stream.emit('turn.started', { ordinal: 1, turn_id: 't1', type: 'turn.started', payload: {} });
    stream.emit('message.delta', { turn_id: 't1', text: 'lo' });
    expect(panel.streamingText()).toBe('Hello');

    stream.emit('message.completed', { ordinal: 2, turn_id: 't1', type: 'message.completed', payload: {} });
    expect(panel.streamingText()).toBe('');
    stream.emit('message.delta', { turn_id: 't1', text: ' late' });
    expect(panel.streamingText()).toBe('');
  });

  /** A step that calls a tool supersedes its text; the next step starts empty. */
  it("does not carry one step's streamed text into the next", () => {
    chat['send'].mockReturnValue(NEVER);
    const panel = create();
    panel.draft.set('look it up');
    panel.send();
    const stream = sources[0];
    stream.emit('turn.started', { ordinal: 1, turn_id: 't3', type: 'turn.started', payload: {} });
    stream.emit('message.delta', { turn_id: 't3', text: 'Let me look that up.' });
    expect(panel.streamingText()).toBe('Let me look that up.');
    stream.emit('tool.call.proposed', { ordinal: 2, turn_id: 't3', type: 'tool.call.proposed', payload: {} });
    expect(panel.streamingText()).toBe('');
    stream.emit('message.delta', { turn_id: 't3', text: 'Here it is.' });
    expect(panel.streamingText()).toBe('Here it is.');
  });

  /** C11 B4 / row A-84. Stop sends the running turn's id, once. */
  it('stops the running turn, once', () => {
    chat['send'].mockReturnValue(NEVER);
    const panel = create();
    panel.draft.set('do something long');
    panel.send();
    expect(panel.canStop()).toBe(false);
    sources[0].emit('turn.started', { ordinal: 1, turn_id: 't9', type: 'turn.started', payload: {} });
    expect(panel.canStop()).toBe(true);
    panel.stop();
    panel.stop();
    expect(chat['cancel']).toHaveBeenCalledTimes(1);
    expect(chat['cancel']).toHaveBeenCalledWith('conv-1', 't9');
    expect(panel.stopping()).toBe(true);
    sources[0].emit('turn.completed', {
      ordinal: 2, turn_id: 't9', type: 'turn.completed', payload: { terminal_state: 'cancelled' },
    });
    expect(panel.runningTurnId()).toBeNull();
    expect(panel.stopping()).toBe(false);
  });

  it('records a vote and shows the recorded one', () => {
    const panel = create();
    panel.draft.set('hi');
    panel.send();
    panel.messages.set([{ id: 'm1', role: 'assistant', content: 'ok', terminal_state: 'completed' } as never]);
    panel.onVote({ id: 'm1' } as never, 'up');
    expect(chat['feedback']).toHaveBeenCalledWith('conv-1', 'm1', 'up');
    expect((panel.messages()[0] as { feedback?: string }).feedback).toBe('up');
  });

  it('closes the stream for a new conversation', () => {
    const panel = create();
    panel.draft.set('hi');
    panel.send();
    panel.newConversation();
    expect(sources[0].closed).toBe(true);
  });

  it('maps a refused start to a clear message', () => {
    chat['start'].mockReturnValue(throwError(() => ({ status: 403, kind: 'forbidden', message: 'x' })));
    const panel = create();
    panel.draft.set('hi');
    panel.send();
    expect(panel.errorKey()).toBe('aiChat.error.notAllowed');
  });
});
