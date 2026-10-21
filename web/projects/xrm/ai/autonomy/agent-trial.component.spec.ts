import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiAgentTrialComponent, percent, type TrialReport } from './agent-trial.component';

function report(same: number, different: number): TrialReport {
  return {
    same, different, none: 2, pending: 1, agreement: same + different ? same / (same + different) : null,
    per_action: [{ action_id: 'record.update', same, different, none: 2, pending: 1 }],
    different_sample: [], min_compared: 30,
  };
}

function setup(r: TrialReport) {
  const api = {
    get: vi.fn((url: string) => of(url.includes('trial-report') ? r : { row_version: 7 })),
    post: vi.fn().mockReturnValue(of(r)),
  };
  TestBed.configureTestingModule({
    imports: [AiAgentTrialComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(AiAgentTrialComponent);
  fixture.componentRef.setInput('agentId', 'a1');
  fixture.detectChanges();
  return { api, fixture };
}

describe('AiAgentTrialComponent (AH6)', () => {
  it('disables go live below 30 compared decisions', () => {
    const { fixture } = setup(report(20, 2));
    const button: HTMLButtonElement = fixture.nativeElement.querySelector('button[type="submit"]');
    expect(button.disabled).toBe(true);
    expect(fixture.componentInstance.enoughCompared()).toBe(false);
  });

  it('goes live with the record version and the threshold', () => {
    const { api, fixture } = setup(report(29, 1));
    expect(fixture.componentInstance.enoughCompared()).toBe(true);
    fixture.componentInstance.goLive();
    expect(api.post).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/go-live', { row_version: 7, min_agreement: 0.9 });
    expect(fixture.componentInstance.wentLive()).toBe(true);
  });

  it('shows agreement as a whole percent', () => {
    expect(percent(null)).toBeNull();
    expect(percent(0.966)).toBe(97);
  });
});
