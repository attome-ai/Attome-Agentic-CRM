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
            sessionChildren: vi.fn().mockReturnValue(of({
              items: [{ id: 'c1', agent_object_ref: 'a9', surface: 'delegate',
                        started_at: '2026-10-14T00:00:00Z', revoked_at: '2026-10-14T00:01:00Z' }],
              total: 1, page: 1, page_size: 200,
            })),
            // AH1-T6: one record put back, one a person changed, one email sent.
            undoPreview: vi.fn().mockReturnValue(of({
              items: [
                { step: 'revert_fields', entity: 'deal', record_id: 'r1', expected_row_version: 3, set: { stage: 'open' } },
                { step: 'skip', entity: 'deal', record_id: 'r2', reason: 'changed', changed_attributes: ['amount'] },
                { step: 'not_undoable', entity: 'action_invocation', record_id: 'i1', action_id: 'email.send',
                  reason: 'the message was already sent' },
              ],
              total: 3, page: 1, page_size: 3,
            })),
            startUndo: vi.fn().mockReturnValue(of({ undo_run_id: 'u1' })),
            undoRun: vi.fn().mockReturnValue(of({
              id: 'u1', status: 'done', created_at: '2026-10-21T00:00:00Z', finished_at: '2026-10-21T00:00:05Z',
              summary: { restored: 1, skipped_changed: 1, not_undoable: 1 },
              items: { items: [], total: 3, page: 1, page_size: 200 },
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

  it('shows the sessions a supervisor delegated to and their steps (N29-T3)', async () => {
    await render([session({})]);
    const cmp = fixture.componentInstance;
    cmp.toggleTrace(cmp.sessions()[0]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-child="c1"]')?.textContent).toContain('a9');
    cmp.toggleChild('c1');
    fixture.detectChanges();
    expect(el.querySelector('[data-child-step="record.get"]')).not.toBeNull();
    cmp.toggleChild('c1');
    fixture.detectChanges();
    expect(el.querySelector('[data-child-step="record.get"]')).toBeNull();
  });

  it('shows not-undoable items separately in the undo preview', async () => {
    await render([session({})]);
    const cmp = fixture.componentInstance;
    cmp.previewUndo(cmp.sessions()[0]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="undo-restore"]')?.textContent).toContain('r1');
    expect(el.querySelector('[data-testid="undo-skipped"]')?.textContent).toContain('amount');
    const impossible = el.querySelector('[data-testid="undo-impossible"]');
    expect(impossible?.textContent).toContain('email.send');
    expect(impossible?.textContent).toContain('the message was already sent');
    expect(el.querySelector('[data-testid="undo-restore"]')?.textContent).not.toContain('email.send');
  });

  it('starts the undo and shows its finished run', async () => {
    await render([session({})]);
    const cmp = fixture.componentInstance;
    cmp.previewUndo(cmp.sessions()[0]);
    cmp.confirmUndo();
    // The run is read on a timer; let its first tick fire.
    await new Promise(resolve => setTimeout(resolve, 0));
    fixture.detectChanges();
    const progress = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="undo-progress"]');
    expect(progress?.textContent).toContain('agentSessions.undo.status.done');
    expect(cmp.undoBusy()).toBe(false);
  });

  it('shows no configured mode for a session without a definition', async () => {
    await render([session({ agent_definition_ref: null, agent_retrieval_mode: null, retrieval_mode: 'tool_invoked' })]);
    expect(text()).toContain('agentSessions.modeToolInvoked');
    expect(text()).not.toContain('agentSessions.modeConfigured');
    expect(text()).not.toContain('agentSessions.modeDiffers');
  });
});
