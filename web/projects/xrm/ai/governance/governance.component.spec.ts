import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiGovernanceComponent, approvedShare } from './governance.component';

describe('AiGovernanceComponent (N30-T5, T9)', () => {
  it('computes the share approved', () => {
    expect(approvedShare({ decisions: 20, approved: 19 })).toBe(95);
    expect(approvedShare({ decisions: 0, approved: 0 })).toBe(0);
  });

  it('lists policies, offers write actions and flags a rubber stamp', () => {
    const get = vi.fn((url: string) => {
      if (url === '/api/v1/admin/ai/write-policies') {
        return of({ items: [{ id: 'p1', action_id: 'record.update', entity: 'invoice', reason: null, created_at: '2026-10-14T00:00:00Z' }] });
      }
      if (url === '/api/v1/actions') {
        return of({ items: [{ id: 'record.get', risk: 'Read' }, { id: 'record.update', risk: 'Reversible' }] });
      }
      return of({
        days: 30,
        approvers: [{ approver_id: 'u1', decisions: 20, approved: 20, median_seconds: 5, warning: true }],
        backlog: [{ action_type: 'attome-ai/invoke', pending: 3, oldest: null }],
        rejection_words: [],
      });
    });
    const api = { get, post: vi.fn().mockReturnValue(of({})), delete: vi.fn().mockReturnValue(of(undefined)) };
    TestBed.configureTestingModule({
      imports: [AiGovernanceComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(AiGovernanceComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-policy="record.update"]')?.textContent).toContain('invoice');
    expect(fixture.componentInstance.writeActions()).toEqual(['record.update']);
    expect(el.querySelector('[data-approver="u1"]')?.textContent).toContain('aiGovernance.rubberStamp');
    fixture.componentInstance.newAction.set('record.delete');
    fixture.componentInstance.addPolicy();
    expect(api.post).toHaveBeenCalledWith('/api/v1/admin/ai/write-policies', { action_id: 'record.delete' });
  });
});
