import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiAgentPermissionsComponent, type PermissionReport } from './agent-permissions.component';

const REPORT: PermissionReport = {
  run_id: 'r1', agent_ref: 'a1', passed: false, cases: 12,
  failures: [{ action_id: 'email.send', entity: null, expect: 'refused', got: 'allowed', reason: 'outside the allow-list' }],
  failures_truncated: false, over_restricted: 0,
  summary: { cannot_do: ['record.delete'], unreadable_entities: ['salary'], needs_approval: ['email.send'] },
};

function setup() {
  const api = {
    get: vi.fn().mockReturnValue(of({ items: [] })),
    post: vi.fn().mockReturnValue(of(REPORT)),
  };
  TestBed.configureTestingModule({
    imports: [AiAgentPermissionsComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(AiAgentPermissionsComponent);
  fixture.componentRef.setInput('agentId', 'a1');
  fixture.detectChanges();
  return { api, fixture };
}

describe('AiAgentPermissionsComponent (AH7-T5)', () => {
  it('lists failures first', () => {
    const { api, fixture } = setup();
    const button: HTMLButtonElement = fixture.nativeElement.querySelector('button');
    button.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/permission-test', {});
    const lists: HTMLElement[] = Array.from(fixture.nativeElement.querySelectorAll('ul'));
    expect(lists[0].hasAttribute('data-failures')).toBe(true);
    expect(lists[0].textContent).toContain('email.send');
    expect(fixture.nativeElement.querySelector('[data-cannot]').textContent).toContain('salary');
    expect(fixture.nativeElement.querySelector('[data-approval]').textContent).toContain('email.send');
  });

  it('reads the last run when it opens', () => {
    const { api } = setup();
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/permission-tests?page=1&page_size=1');
  });
});
