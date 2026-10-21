import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiAgentAutonomyComponent, raisesConsequential, type AutonomyEntry } from './agent-autonomy.component';

const send: AutonomyEntry = {
  action_id: 'email.send', risk: 'Consequential', effect: 'Write',
  default_level: 'ask_first', level: 'act_with_undo', locked: false,
  row: {
    id: 'r1', level: 2, undo_seconds: 300, daily_limit: 20, money_cap_minor: null, currency: null,
    owned_records_only: false, hours_start: null, hours_end: null, time_zone: null, row_version: 3,
  },
};
const remember: AutonomyEntry = {
  action_id: 'memory.remember', risk: 'Reversible', effect: 'Write',
  default_level: 'automatic', level: null, locked: true, row: null,
};

function setup() {
  const api = {
    get: vi.fn((url: string) => of(url.endsWith('/proposals')
      ? { items: [{ id: 'p1', action_id: 'record.update', from_level: null, to_level: 5, agreement: 0.99,
          cases: 240, expires_at: '2026-11-04T00:00:00Z' }], total: 1, page: 1, page_size: 500 }
      : { items: [send, remember], total: 2, page: 1, page_size: 500 })),
    post: vi.fn().mockReturnValue(of({})),
    put: vi.fn().mockReturnValue(of({})),
    delete: vi.fn().mockReturnValue(of(undefined)),
  };
  TestBed.configureTestingModule({
    imports: [AiAgentAutonomyComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(AiAgentAutonomyComponent);
  fixture.componentRef.setInput('agentId', 'a1');
  fixture.detectChanges();
  return { api, fixture };
}

describe('AiAgentAutonomyComponent (AH8)', () => {
  it('lists each action, warns on a consequential raise and offers no level for a locked one', () => {
    const { api, fixture } = setup();
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/autonomy');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-action="email.send"] .au-warning')).not.toBeNull();
    const locked = el.querySelector('[data-action="memory.remember"]');
    expect(locked?.querySelector('select')).toBeNull();
    expect(locked?.textContent).toContain('aiAutonomy.locked');
  });

  it('saves a level keeping the row limits, and clears it', () => {
    const { api, fixture } = setup();
    const cmp = fixture.componentInstance;
    cmp.save(send, 'automatic');
    expect(api.put).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/autonomy/email.send', expect.objectContaining({
      level: 'automatic', undo_seconds: 300, daily_limit: 20, row_version: 3,
    }));
    cmp.save(send, 'act_with_undo', 120, null);
    expect(api.put).toHaveBeenLastCalledWith('/api/v1/admin/ai/agents/a1/autonomy/email.send', expect.objectContaining({
      level: 'act_with_undo', undo_seconds: 120, daily_limit: null,
    }));
    cmp.clear(send);
    expect(api.delete).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/autonomy/email.send');
  });

  it('lists a proposal and accepts it', () => {
    const { api, fixture } = setup();
    expect(fixture.nativeElement.querySelector('[data-proposal="p1"]')).not.toBeNull();
    fixture.componentInstance.decideProposal(fixture.componentInstance.proposals()[0], true);
    expect(api.post).toHaveBeenCalledWith('/api/v1/admin/ai/autonomy/proposals/p1/accept', {});
  });

  it('only a level above ask first on a consequential action raises it', () => {
    expect(raisesConsequential(send, 'ask_first')).toBe(false);
    expect(raisesConsequential(send, 'act_with_undo')).toBe(true);
    expect(raisesConsequential(remember, 'automatic')).toBe(false);
  });
});
