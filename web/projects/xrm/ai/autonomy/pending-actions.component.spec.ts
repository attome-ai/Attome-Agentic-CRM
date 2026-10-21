import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiPendingActionsComponent } from './pending-actions.component';

describe('AiPendingActionsComponent (AH8)', () => {
  it('lists held actions and cancels a pending one', () => {
    const api = {
      get: vi.fn().mockReturnValue(of({ items: [
        { id: 'd1', action_id: 'email.send', initiator: 'agent', agent_session_id: 's1', acting_user_id: 'u1',
          run_at: '2026-10-21T10:05:00Z', status: 'pending', reason: null, approval_id: null, created_at: '2026-10-21T10:00:00Z' },
        { id: 'd2', action_id: 'record.delete', initiator: 'user', agent_session_id: null, acting_user_id: 'u1',
          run_at: '2026-10-21T09:05:00Z', status: 'executed', reason: null, approval_id: null, created_at: '2026-10-21T09:00:00Z' },
      ], total: 2, page: 1, page_size: 50 })),
      post: vi.fn().mockReturnValue(of({})),
    };
    TestBed.configureTestingModule({
      imports: [AiPendingActionsComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(AiPendingActionsComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-id="d1"] button')).not.toBeNull();
    expect(el.querySelector('[data-id="d2"] button')).toBeNull();

    fixture.componentInstance.cancel(fixture.componentInstance.actions()[0]);
    expect(api.post).toHaveBeenCalledWith('/api/v1/ai/deferred-actions/d1/cancel', {});
  });
});
