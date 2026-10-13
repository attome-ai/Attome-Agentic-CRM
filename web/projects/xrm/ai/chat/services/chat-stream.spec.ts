import { describe, expect, it, vi } from 'vitest';
import { ChatStream, DURABLE_EVENTS, DeltaBuffer } from './chat-stream';
import type { EventSourceLike } from './chat-stream';

class FakeSource implements EventSourceLike {
  readonly listeners = new Map<string, (e: MessageEvent<string>) => void>();
  closed = false;
  readyState = 0;
  addEventListener(type: string, listener: (e: MessageEvent<string>) => void): void {
    this.listeners.set(type, listener);
  }
  close(): void {
    this.closed = true;
  }
  emit(type: string, data: unknown): void {
    this.listeners.get(type)?.({ data: typeof data === 'string' ? data : JSON.stringify(data) } as MessageEvent<string>);
  }
}

describe('ChatStream', () => {
  it('routes durable events and deltas to their own handlers', () => {
    const source = new FakeSource();
    const event = vi.fn();
    const delta = vi.fn();
    const stream = new ChatStream('/stream', { event, delta }, () => source);
    stream.open();

    expect([...source.listeners.keys()].sort()).toEqual([...DURABLE_EVENTS, 'message.delta', 'error'].sort());
    source.emit('turn.started', { ordinal: 1, turn_id: 't1', type: 'turn.started', payload: {} });
    source.emit('message.delta', { turn_id: 't1', text: 'Hel' });
    expect(event).toHaveBeenCalledWith(expect.objectContaining({ type: 'turn.started', ordinal: 1 }));
    expect(delta).toHaveBeenCalledWith({ turn_id: 't1', text: 'Hel' });
  });

  it('reports a stream the browser gave up on, and lets it be reopened', () => {
    const sources: FakeSource[] = [];
    const closed = vi.fn();
    const stream = new ChatStream('/stream', { event: vi.fn(), delta: vi.fn(), closed }, () => {
      sources.push(new FakeSource());
      return sources[sources.length - 1];
    });
    stream.open();
    // A transient drop: the browser is reconnecting on its own.
    sources[0].emit('error', '');
    expect(closed).not.toHaveBeenCalled();
    // Given up for good.
    sources[0].readyState = 2;
    sources[0].emit('error', '');
    expect(closed).toHaveBeenCalledTimes(1);
    stream.open();
    expect(sources).toHaveLength(2);
  });

  it('skips a frame it cannot parse instead of throwing', () => {
    const source = new FakeSource();
    const event = vi.fn();
    new ChatStream('/stream', { event, delta: vi.fn() }, () => source).open();
    expect(() => source.emit('turn.started', '{not json')).not.toThrow();
    expect(event).not.toHaveBeenCalled();
  });

  it('opens once and closes the source', () => {
    const factory = vi.fn(() => new FakeSource());
    const stream = new ChatStream('/stream', { event: vi.fn(), delta: vi.fn() }, factory);
    stream.open();
    stream.open();
    expect(factory).toHaveBeenCalledTimes(1);
    const source = factory.mock.results[0].value as FakeSource;
    stream.close();
    expect(source.closed).toBe(true);
  });
});

/** Row A-79: provisional text never outlives its turn's answer. */
describe('DeltaBuffer', () => {
  it('accumulates per turn and discards on finish, ignoring late deltas', () => {
    const buffer = new DeltaBuffer();
    buffer.add('t1', 'Hel');
    buffer.add('t1', 'lo');
    buffer.add('t2', 'other');
    expect(buffer.get('t1')).toBe('Hello');
    buffer.finish('t1');
    expect(buffer.get('t1')).toBe('');
    // A delta after the answer is ignored.
    buffer.add('t1', ' late');
    expect(buffer.get('t1')).toBe('');
    expect(buffer.get('t2')).toBe('other');
  });
});
