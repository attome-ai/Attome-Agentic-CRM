import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ChatService } from './chat.service';

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
  it('confirms with the arguments hash only', () => {
    service.confirm(CONV, 'call/1', 'abc123').subscribe();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/tool-calls/call%2F1/confirm`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ arguments_hash: 'abc123' });
    req.flush({ outcome: 'executed', result: {} });
  });

  it('starts a background run with a task and an optional step budget (N7-T1)', () => {
    service.startRun(CONV, 'triage the new cases').subscribe();
    const plain = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/runs`);
    expect(plain.request.method).toBe('POST');
    expect(plain.request.body).toEqual({ task: 'triage the new cases' });
    plain.flush({ conversation_id: CONV, status: 'running' });

    service.startRun(CONV, 'again', 5).subscribe();
    const bounded = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/runs`);
    expect(bounded.request.body).toEqual({ task: 'again', max_steps: 5 });
    bounded.flush({ conversation_id: CONV, status: 'running' });
  });

  /** I-19: record context travels in its own field, only when there is one. */
  it('sends record context in `context`, never folded into the text by the client', () => {
    const context = { entity: 'contact', record_id: '01900000-0000-7000-8000-0000000000a1' };
    service.send(CONV, 'who is this?', context).subscribe();
    const withContext = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages`);
    expect(withContext.request.body).toEqual({ text: 'who is this?', context });
    withContext.flush({});

    service.send(CONV, 'hello', null).subscribe();
    const without = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages`);
    expect(without.request.body).toEqual({ text: 'hello' });
    without.flush({});
  });

  it('reads the tool-call projection with paging', () => {
    service.toolCalls(CONV).subscribe();
    const req = http.expectOne(
      (r) => r.url === `${API}/api/v1/ai/conversations/${CONV}/tool-calls`,
    );
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    req.flush({ items: [], total: 0, page: 1, page_size: 100 });
  });

  it('starts a conversation with an explicit ceiling', () => {
    service.start('agent-1', 'reversible').subscribe();
    const req = http.expectOne(`${API}/api/v1/ai/conversations`);
    expect(req.request.body).toEqual({ agent_definition_id: 'agent-1', risk_ceiling: 'reversible' });
    req.flush({});
  });

  it('stops a turn by id, with nothing in the body', () => {
    service.cancel(CONV, 'turn-1').subscribe();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/turns/turn-1/cancel`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});
    req.flush({ turn_id: 'turn-1', state: 'requested' });
  });

  it('records a thumbs vote on one answer', () => {
    service.feedback(CONV, 'msg-1', 'down').subscribe();
    const req = http.expectOne(`${API}/api/v1/ai/conversations/${CONV}/messages/msg-1/feedback`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ vote: 'down' });
    req.flush({ message_id: 'msg-1', vote: 'down', updated_at: '2026-09-23T00:00:00Z' });
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
