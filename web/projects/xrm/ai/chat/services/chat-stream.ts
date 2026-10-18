import { InjectionToken } from '@angular/core';

/**
 * The conversation's live stream (C10-A, C11 B3/B4): `GET …/stream` as
 * Server-Sent Events.
 *
 * Two kinds of frame arrive, and they are handled differently on purpose:
 *
 * - **Durable events** (`turn.started`, `tool.call.*`, `approval.*`,
 *   `message.completed`, `turn.completed`) carry an `id` — the ordinal the
 *   browser's `EventSource` sends back as `Last-Event-ID` when it reconnects,
 *   so a dropped connection resumes with nothing missed and nothing repeated.
 * - **`message.delta`** carries text a model is producing right now, with no
 *   `id`. It is provisional: the turn's `message.completed` replaces it, and a
 *   turn that ends any other way discards it ({@link DeltaBuffer}).
 *
 * The server authorizes the stream before its first frame (I-20); nothing
 * here decides who may see what.
 */

/** The durable event types, in the server's contract (`01` § "C10-A"). */
export const DURABLE_EVENTS = [
  'turn.started',
  'tool.call.proposed',
  'tool.call.started',
  'tool.call.completed',
  'tool.call.failed',
  'approval.required',
  'approval.resolved',
  'message.completed',
  'turn.completed',
] as const;

export type DurableEventType = (typeof DURABLE_EVENTS)[number];

/** One durable frame's `data` (the server's `StreamEventView`). */
export interface StreamEvent {
  ordinal: number;
  turn_id: string | null;
  type: DurableEventType;
  payload: Record<string, unknown>;
  created_at: string;
  /** `message.completed` only: the answer, read from the ledger. */
  content?: string;
}

/**
 * The `reconnect` frame's `data` (AB7-T5): the node serving the stream is
 * draining; reopen after `retry_ms` from the last durable ordinal.
 */
export interface StreamReconnect {
  retry_ms: number;
}

/** The longest a client waits on a `reconnect` frame, whatever it says. */
const MAX_RECONNECT_MS = 10_000;

/** `url` with `after` set to `ordinal`, the stream's resume cursor. */
export function resumeUrl(url: string, ordinal: number | null): string {
  if (ordinal === null) return url;
  const base = url.replace(/([?&])after=[^&]*&?/, '$1').replace(/[?&]$/, '');
  return `${base}${base.includes('?') ? '&' : '?'}after=${ordinal}`;
}

/** One `message.delta` frame's `data` (the server's `MessageDeltaView`). */
export interface StreamDelta {
  turn_id: string;
  text: string;
}

export interface StreamHandlers {
  event(e: StreamEvent): void;
  delta(d: StreamDelta): void;
  /**
   * The browser gave up on the stream for good (a 401/403/404, or a
   * non-SSE response) and will not reconnect by itself.
   */
  closed?(): void;
}

/** `EventSource.CLOSED`, without referencing the browser global in tests. */
const EVENT_SOURCE_CLOSED = 2;

/** The part of `EventSource` this uses — so a test can supply its own. */
export interface EventSourceLike {
  addEventListener(type: string, listener: (e: MessageEvent<string>) => void): void;
  close(): void;
  readonly readyState?: number;
}

export type EventSourceFactory = (url: string) => EventSourceLike;

const browserEventSource: EventSourceFactory = (url) =>
  new EventSource(url, { withCredentials: true }) as unknown as EventSourceLike;

/** How the panel opens a stream: the browser's `EventSource`, or a test's fake. */
export const CHAT_EVENT_SOURCE = new InjectionToken<EventSourceFactory>('CHAT_EVENT_SOURCE', {
  providedIn: 'root',
  factory: () => browserEventSource,
});

/**
 * An open conversation stream. The browser's `EventSource` reconnects on its
 * own and resumes from the last durable `id`; {@link close} ends it for good.
 * A `reconnect` frame (the server is draining, AB7-T5) closes this source and
 * opens a new one after the delay it names, from the last durable ordinal.
 */
export class ChatStream {
  private source: EventSourceLike | null = null;
  /** The ordinal of the last durable event received. */
  private lastOrdinal: number | null = null;
  private reopenTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly url: string,
    private readonly handlers: StreamHandlers,
    private readonly factory: EventSourceFactory = browserEventSource,
  ) {}

  open(): void {
    if (this.source || this.reopenTimer !== null) return;
    const source = this.factory(resumeUrl(this.url, this.lastOrdinal));
    for (const type of DURABLE_EVENTS) {
      source.addEventListener(type, (e) => {
        const parsed = parse<StreamEvent>(e.data);
        if (!parsed) return;
        if (typeof parsed.ordinal === 'number') this.lastOrdinal = parsed.ordinal;
        this.handlers.event(parsed);
      });
    }
    source.addEventListener('reconnect', (e) => {
      if (this.source !== source) return;
      const asked = parse<StreamReconnect>(e.data)?.retry_ms;
      const wait = Math.min(MAX_RECONNECT_MS, Math.max(0, typeof asked === 'number' ? asked : 1000));
      this.source = null;
      source.close();
      this.reopenTimer = setTimeout(() => {
        this.reopenTimer = null;
        this.open();
      }, wait);
    });
    source.addEventListener('message.delta', (e) => {
      const parsed = parse<StreamDelta>(e.data);
      if (parsed && typeof parsed.text === 'string') this.handlers.delta(parsed);
    });
    // A transient drop reconnects by itself (readyState CONNECTING). CLOSED
    // means the browser has given up: release the source so the next send
    // can open a fresh one, and say so.
    source.addEventListener('error', () => {
      if (source.readyState !== EVENT_SOURCE_CLOSED || this.source !== source) return;
      this.source = null;
      this.handlers.closed?.();
    });
    this.source = source;
  }

  close(): void {
    if (this.reopenTimer !== null) clearTimeout(this.reopenTimer);
    this.reopenTimer = null;
    this.source?.close();
    this.source = null;
  }
}

function parse<T>(data: string): T | null {
  try {
    return JSON.parse(data) as T;
  } catch {
    // A frame the client cannot read is skipped; the durable ones are
    // recovered by the next refresh of the transcript.
    return null;
  }
}

/**
 * Provisional text per turn. Deltas append; the turn's `message.completed`
 * or `turn.completed` ends it, after which late deltas for that turn are
 * ignored — the answer the ledger holds is the only one shown (row A-79).
 */
export class DeltaBuffer {
  private readonly text = new Map<string, string>();
  private readonly finished = new Set<string>();

  add(turnId: string, text: string): void {
    if (this.finished.has(turnId)) return;
    this.text.set(turnId, (this.text.get(turnId) ?? '') + text);
  }

  finish(turnId: string): void {
    this.finished.add(turnId);
    this.text.delete(turnId);
  }

  /**
   * Drops a running turn's text without finishing it: the step that streamed
   * it called a tool, so the next step's text replaces it rather than
   * continuing it.
   */
  restart(turnId: string): void {
    this.text.delete(turnId);
  }

  get(turnId: string): string {
    return this.text.get(turnId) ?? '';
  }
}
