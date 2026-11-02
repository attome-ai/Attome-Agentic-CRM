import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ChatService } from './chat.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('ChatService', () => {
  let service: ChatService;
  let http: HttpTestingController;
  const API = 'http://localhost:7865';
  const CONV = '01900000-0000-7000-8000-00000000c0c0';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(ChatService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  /** I-13 / row A-08 on the client: a confirmation carries the hash and nothing else. */
  it('confirms with the arguments hash only', async () => {
    service.confirm(CONV, 'call/1', 'abc123').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/tool-calls/call%2F1/confirm`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ arguments_hash: 'abc123' });
    req.flush({ outcome: 'executed', result: {} });
    await tick();
  });

  it('starts a background run with a task and an optional step budget (N7-T1)', async () => {
    service.startRun(CONV, 'triage the new cases').subscribe();
    await tick();
    const plain = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/runs`);
    expect(plain.request.method).toBe('POST');
    expect(plain.request.body).toEqual({ task: 'triage the new cases' });
    plain.flush({ conversation_id: CONV, status: 'running' });
    await tick();

    service.startRun(CONV, 'again', 5).subscribe();
    await tick();
    const bounded = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/runs`);
    expect(bounded.request.body).toEqual({ task: 'again', max_steps: 5 });
    bounded.flush({ conversation_id: CONV, status: 'running' });
    await tick();
  });

  /** I-19: record context travels in its own field, only when there is one. */
  it('sends record context in `context`, never folded into the text by the client', async () => {
    const context = { entity: 'contact', record_id: '01900000-0000-7000-8000-0000000000a1' };
    service.send(CONV, 'who is this?', context).subscribe();
    await tick();
    const withContext = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages`);
    expect(withContext.request.body).toEqual({ text: 'who is this?', context });
    withContext.flush({});
    await tick();

    service.send(CONV, 'hello', null).subscribe();
    await tick();
    const without = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages`);
    expect(without.request.body).toEqual({ text: 'hello' });
    without.flush({});
    await tick();
  });

  it('reads the tool-call projection with paging', async () => {
    service.toolCalls(CONV).subscribe();
    await tick();
    const req = http.expectOne(
      (r) => r.url === `${API}/api/v1/ai/conversations/${CONV}/tool-calls`,
    );
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    req.flush({ items: [], total: 0, page: 1, page_size: 100 });
    await tick();
  });

  it('starts a conversation with an explicit ceiling', async () => {
    service.start('agent-1', 'reversible').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/ai/conversations`);
    expect(req.request.body).toEqual({ agent_definition_id: 'agent-1', risk_ceiling: 'reversible' });
    req.flush({});
    await tick();
  });

  it('stops a turn by id, with nothing in the body', async () => {
    service.cancel(CONV, 'turn-1').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/turns/turn-1/cancel`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});
    req.flush({ turn_id: 'turn-1', state: 'requested' });
    await tick();
  });

  it('records a thumbs vote on one answer', async () => {
    service.feedback(CONV, 'msg-1', 'down').subscribe();
    await tick();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages/msg-1/feedback`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ vote: 'down' });
    req.flush({ message_id: 'msg-1', vote: 'down', updated_at: '2026-09-23T00:00:00Z' });
    await tick();
  });

  it('builds the stream URL from the configured API origin and a cursor', () => {
    expect(service.streamUrl(CONV, 7)).toBe(`${API}/api/v1/ai/conversations/${CONV}/stream?after=7`);
    // No cursor by default, so a reconnect resumes from Last-Event-ID.
    expect(service.streamUrl(CONV)).toBe(`${API}/api/v1/ai/conversations/${CONV}/stream`);
  });

  it('computes the newest page of a transcript', () => {
    expect(ChatService.lastPage(0)).toBe(1);
    expect(ChatService.lastPage(100)).toBe(1);
    expect(ChatService.lastPage(101)).toBe(2);
  });
});
