import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AiAgentSessionsComponent } from './ai-agent-sessions.component';
import { AdminAiService } from '../../services/admin-ai.service';
import type { AgentSessionSummary } from '../../services/admin-ai.service';
import { AiActionsService } from '../../services/ai-actions.service';

/**
 * D-561 §5 on the supervisor screen: a session's knowledge retrieval mode is
 * the one stored when it started. The agent's current configured mode is
 * shown beside it for comparison and, when the two differ, the screen says the
 * difference applies to new sessions only — it never shows the configured
 * mode as the session's.
 */
describe('AiAgentSessionsComponent — retrieval mode', () => {
  let fixture: ComponentFixture<AiAgentSessionsComponent>;

  const session = (over: Partial<AgentSessionSummary>): AgentSessionSummary => ({
    id: 's-1-aaaaaaaa',
    owner_user_id: 'u-1-bbbbbbbb',
    risk_ceiling: 'reversible',
    allowed_action_ids: null,
    capability_pack_refs: null,
    surface: 'chat',
    agent_definition_ref: 'a-1-cccccccc',
    started_at: '2026-09-22T08:00:00Z',
    status: 'active',
    tainted: false,
    retrieval_mode: 'pre_retrieved',
    agent_retrieval_mode: 'pre_retrieved',
    ...over,
  });

  async function render(items: AgentSessionSummary[]) {
    await TestBed.configureTestingModule({
      imports: [AiAgentSessionsComponent],
      providers: [
        {
          provide: AdminAiService,
          useValue: {
            listAgentSessions: vi.fn().mockReturnValue(of({ items, total: items.length, page: 1, page_size: 50 })),
            // The embedded runtime-switch card (C11 B5) hides itself for a
            // non-administrator; this suite is about the sessions table.
            runtimeSwitch: vi.fn().mockReturnValue(throwError(() => ({ status: 403 }))),
            // Likewise the analytics card (C10 B2b).
            botAnalytics: vi.fn().mockReturnValue(throwError(() => ({ status: 403 }))),
            sessionTrace: vi.fn().mockReturnValue(of({
              items: [{ id: 't1', action_id: 'record.get', outcome: 'completed', tool_call_id: null,
                        acting_user_id: 'u1', created_at: '2026-10-14T00:00:00Z' }],
              total: 1, page: 1, page_size: 1000,
            })),
          },
        },
        { provide: AiActionsService, useValue: { invoke: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(AiAgentSessionsComponent);
    fixture.detectChanges();
  }

  const text = () => (fixture.nativeElement as HTMLElement).textContent ?? '';

  beforeEach(() => TestBed.resetTestingModule());

  it('states that editing the agent changes new sessions only', async () => {
    await render([session({})]);
    expect(text()).toContain('agentSessions.retrievalModeNotice');
  });

  it('shows the stored mode, and no difference when the agent still holds it', async () => {
    await render([session({})]);
    expect(text()).toContain('agentSessions.modePreRetrieved');
    expect(text()).toContain('agentSessions.modeStored');
    expect(text()).not.toContain('agentSessions.modeDiffers');
  });

  it('keeps the stored mode as the session\'s and flags a changed definition', async () => {
    await render([session({ retrieval_mode: 'pre_retrieved', agent_retrieval_mode: 'tool_invoked' })]);
    const cell = (fixture.nativeElement as HTMLElement).querySelector('tbody .as__cellstack .as__ceiling');
    expect(cell?.textContent?.trim()).toBe('agentSessions.modePreRetrieved');
    expect(text()).toContain('agentSessions.modeDiffers');
  });

  it('shows the steps of a session on request and hides them again (N29-T2)', async () => {
    await render([session({})]);
    const cmp = fixture.componentInstance;
    cmp.toggleTrace(cmp.sessions()[0]);
    fixture.detectChanges();
    const step = (fixture.nativeElement as HTMLElement).querySelector('[data-step="record.get"]');
    expect(step?.textContent).toContain('completed');
    cmp.toggleTrace(cmp.sessions()[0]);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.as__trace')).toBeNull();
  });

  it('shows no configured mode for a session without a definition', async () => {
    await render([session({ agent_definition_ref: null, agent_retrieval_mode: null, retrieval_mode: 'tool_invoked' })]);
    expect(text()).toContain('agentSessions.modeToolInvoked');
    expect(text()).not.toContain('agentSessions.modeConfigured');
    expect(text()).not.toContain('agentSessions.modeDiffers');
  });
});
