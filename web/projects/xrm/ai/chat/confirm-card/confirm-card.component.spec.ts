import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatService } from '../services/chat.service';
import type { ToolCallView } from '../services/chat.service';
import { ConfirmCardComponent } from './confirm-card.component';
import type { ConfirmCardResult } from './confirm-card.component';

const CONV = 'conv-1';
const CALL: ToolCallView = {
  tool_call_id: 'call-1',
  turn_id: 't1',
  action_id: 'record.update',
  status: 'proposed',
  arguments: { entity: 'support_case', record_id: 'r1', values: { status: 'closed' }, row_version: 4 },
  arguments_hash: 'hash-abc',
  approval_request_id: null,
  created_at: '2026-09-22T00:00:00Z',
  resolved_at: null,
};

describe('ConfirmCardComponent', () => {
  let confirm: ReturnType<typeof vi.fn>;
  let currentRecord: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    confirm = vi.fn().mockReturnValue(of({ outcome: 'executed', result: {} }));
    currentRecord = vi.fn().mockReturnValue(of({ status: 'open' }));
    TestBed.configureTestingModule({
      imports: [ConfirmCardComponent],
      providers: [
        { provide: ChatService, useValue: { confirm, currentRecord, reject: vi.fn().mockReturnValue(of(undefined)) } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
  });

  function create() {
    const fixture = TestBed.createComponent(ConfirmCardComponent);
    fixture.componentRef.setInput('conversationId', CONV);
    fixture.componentRef.setInput('toolCall', CALL);
    const results: ConfirmCardResult[] = [];
    fixture.componentInstance.resolved.subscribe((r) => results.push(r));
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement, results };
  }

  it('shows the concrete diff: current beside proposed', () => {
    const { el } = create();
    expect(currentRecord).toHaveBeenCalledWith('support_case', 'r1');
    const cells = [...el.querySelectorAll('tbody td')].map((td) => td.textContent?.trim());
    expect(cells).toEqual(['open', 'closed']);
  });

  /** I-13 / A-08: confirming sends the hash — the displayed arguments never go back. */
  it('confirms with the stored hash and nothing else', () => {
    const { el, results } = create();
    (el.querySelector('.btn--primary') as HTMLButtonElement).click();
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm.mock.calls[0]).toEqual([CONV, 'call-1', 'hash-abc']);
    expect(results).toEqual([{ kind: 'executed' }]);
  });

  it('reports an approval request instead of an execution', () => {
    confirm.mockReturnValue(of({ outcome: 'approval_requested', approval_request_id: 'appr-1' }));
    const { el, results } = create();
    (el.querySelector('.btn--primary') as HTMLButtonElement).click();
    expect(results).toEqual([{ kind: 'approval_requested', approvalRequestId: 'appr-1' }]);
  });

  it('still works without a diff when the record cannot be read', () => {
    currentRecord.mockReturnValue(throwError(() => ({ status: 404, kind: 'not_found', message: 'x' })));
    const { el } = create();
    expect(el.textContent).toContain('aiChat.confirm.currentUnavailable');
    expect([...el.querySelectorAll('tbody td')].map((td) => td.textContent?.trim())).toEqual(['closed']);
  });

  /** Regression (C7 browser pass, RTL): record values keep their own direction. */
  it('lets diff values take their own direction', () => {
    const { el } = create();
    const cells = [...el.querySelectorAll('tbody td')];
    expect(cells.length).toBeGreaterThan(0);
    for (const td of cells) expect(td.getAttribute('dir')).toBe('auto');
  });
});
