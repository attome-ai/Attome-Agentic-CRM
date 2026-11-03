import { TestBed } from '@angular/core/testing';
import { AuthService, LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { type AgentPrincipal, AgentPrincipalsComponent, movesFor, scopeOf } from './agent-principals.component';

const agent = (state: AgentPrincipal['lifecycle_state']): AgentPrincipal => ({
  id: 'a1', name: 'Collections', sponsor_user_ref: 'u1', lifecycle_state: state,
  state_reason: state === 'paused' ? 'sponsor_lost' : null, entity_scope: ['account'], row_version: 3,
});

describe('agent principals (AH3-T8)', () => {
  it('reads a scope and offers the moves a state allows', () => {
    expect(scopeOf(' account, sales_order ,account ')).toEqual(['account', 'sales_order']);
    expect(scopeOf('  ')).toBeUndefined();
    expect(movesFor('active')).toEqual(['pause', 'suspend', 'revoke']);
    expect(movesFor('paused')).toContain('resume');
    expect(movesFor('revoked')).toEqual([]);
  });

  function setup(state: AgentPrincipal['lifecycle_state'] = 'active') {
    const get = vi.fn(() => of({ items: [agent(state)] }));
    const post = vi.fn((path: string, _opts?: unknown, _write?: unknown) =>
      path.endsWith('/keys')
        ? of({ id: 'k1', name: 'Collections', public_key: 'atk_pub_x', secret: 'atk_sec_once' })
        : of(agent('paused')));
    const put = vi.fn(() => of(agent(state)));
    TestBed.configureTestingModule({
      imports: [AgentPrincipalsComponent],
      providers: [
        { provide: SdkService, useValue: { get, post, put } },
        { provide: AuthService, useValue: { userId: () => 'me' } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(AgentPrincipalsComponent);
    fixture.detectChanges();
    return { fixture, get, post, put };
  }

  it('creates an agent sponsored by the signed-in person by default', () => {
    const { fixture, post } = setup();
    fixture.componentInstance.name.set('Renewals');
    fixture.componentInstance.scope.set('account');
    fixture.componentInstance.create();
    expect(post.mock.calls[0][0]).toBe('/api/v1/admin/agents');
    expect(post.mock.calls[0][1]).toEqual({ body: { name: 'Renewals', sponsor: 'me', entity_scope: ['account'] } });
  });

  it('moves an agent under If-Match and shows its state with the reason', () => {
    const { fixture, post } = setup();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[data-state="active"]')).not.toBeNull();
    fixture.componentInstance.move(agent('active'), 'pause');
    expect(post.mock.calls[0][0]).toBe('/api/v1/admin/agents/a1/pause');
    expect(post.mock.calls[0][2]).toEqual({ ifMatch: 3 });
  });

  it('shows the key secret only once', () => {
    const { fixture } = setup();
    const root = fixture.nativeElement as HTMLElement;
    fixture.componentInstance.issueKey(agent('active'));
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="ap-secret"]')?.textContent).toContain('atk_sec_once');
    fixture.componentInstance.closeKey();
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="ap-secret"]')).toBeNull();
    expect(root.textContent).not.toContain('atk_sec_once');
  });
});
