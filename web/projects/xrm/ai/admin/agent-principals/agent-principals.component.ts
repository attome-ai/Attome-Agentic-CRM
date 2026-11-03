import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, AuthService, SdkService, TranslatePipe } from '@attome/base';
import type { Observable } from 'rxjs';

/** One agent principal (`GET /api/v1/admin/agents`, AH3-T4). */
export interface AgentPrincipal {
  id: string;
  name: string;
  sponsor_user_ref: string;
  lifecycle_state: 'active' | 'paused' | 'suspended' | 'revoked';
  state_reason: string | null;
  entity_scope: string[] | null;
  row_version: number;
}

interface Page<T> {
  items: T[];
}

/** A key just issued: its secret is in this answer only. */
export interface IssuedKey {
  id: string;
  name: string;
  public_key: string;
  secret: string;
}

/** `account, sales_order` as an entity scope; absent when blank. Pure. */
export function scopeOf(text: string): string[] | undefined {
  const entities = text.split(',').map(e => e.trim()).filter(e => e.length > 0);
  return entities.length ? [...new Set(entities)] : undefined;
}

/** The lifecycle moves an agent in `state` offers. Pure. */
export function movesFor(state: AgentPrincipal['lifecycle_state']): ('pause' | 'suspend' | 'resume' | 'revoke')[] {
  switch (state) {
    case 'active': return ['pause', 'suspend', 'revoke'];
    case 'paused': return ['resume', 'suspend', 'revoke'];
    case 'suspended': return ['resume', 'revoke'];
    default: return [];
  }
}

const AGENTS = '/api/v1/admin/agents';

/**
 * AH3-T8 — Admin > AI > Agents: the deployment's agent principals. Make one
 * (the sponsor is the signed-in person unless another is named), see its
 * state and why, move it (pause, suspend, resume, revoke), name another
 * sponsor, and issue keys whose secret is shown once.
 */
@Component({
  selector: 'xrm-agent-principals',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css'],
  styles: [`
    .ap-grid { display: grid; gap: 1rem; }
    .ap-card { border: 1px solid var(--color-border, currentColor); border-radius: 8px; padding: 1rem; display: grid; gap: .5rem; }
    .ap-row { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .ap-badge { border-radius: 999px; padding-inline: .5rem; border: 1px solid currentColor; font-size: .85em; }
    .ap-secret { font-family: monospace; word-break: break-all; }
  `],
  template: `
    <section>
      <header class="page-header">
        <div>
          <h2>{{ 'agentPrincipals.title' | translate }}</h2>
          <p class="subtitle">{{ 'agentPrincipals.subtitle' | translate }}</p>
        </div>
      </header>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      <div class="ap-grid">
        <article class="ap-card" data-testid="ap-create">
          <h3>{{ 'agentPrincipals.create' | translate }}</h3>
          <label>{{ 'agentPrincipals.name' | translate }}
            <input data-testid="ap-name" [ngModel]="name()" (ngModelChange)="name.set($event)" maxlength="200" />
          </label>
          <label>{{ 'agentPrincipals.sponsor' | translate }}
            <input data-testid="ap-sponsor" [ngModel]="sponsor()" (ngModelChange)="sponsor.set($event)"
                   [placeholder]="'agentPrincipals.sponsorDefault' | translate" />
          </label>
          <label>{{ 'agentPrincipals.scope' | translate }}
            <input data-testid="ap-scope" [ngModel]="scope()" (ngModelChange)="scope.set($event)"
                   [placeholder]="'agentPrincipals.scopeHint' | translate" />
          </label>
          <button type="button" data-testid="ap-create-button" (click)="create()" [disabled]="busy() || !name().trim()">
            {{ 'agentPrincipals.createButton' | translate }}</button>
        </article>

        @if (issued(); as key) {
          <article class="ap-card" data-testid="ap-secret" role="dialog" aria-modal="true">
            <h3>{{ 'agentPrincipals.keyTitle' | translate }}</h3>
            <p role="alert">{{ 'agentPrincipals.keyOnce' | translate }}</p>
            <p class="ap-secret"><bdi dir="ltr">{{ key.secret }}</bdi></p>
            <div class="ap-row">
              <button type="button" data-testid="ap-copy" (click)="copy(key.secret)">{{ 'agentPrincipals.copy' | translate }}</button>
              <button type="button" data-testid="ap-close" (click)="closeKey()">{{ 'agentPrincipals.close' | translate }}</button>
            </div>
          </article>
        }

        @for (a of agents(); track a.id) {
          <article class="ap-card" [attr.data-agent]="a.id">
            <div class="ap-row">
              <h3>{{ a.name }}</h3>
              <span class="ap-badge" [attr.data-state]="a.lifecycle_state">{{ 'agentPrincipals.state_' + a.lifecycle_state | translate }}</span>
              @if (a.state_reason) { <span>{{ a.state_reason }}</span> }
            </div>
            <p>{{ 'agentPrincipals.sponsoredBy' | translate }} <bdi dir="ltr">{{ a.sponsor_user_ref }}</bdi></p>
            @if (a.entity_scope?.length) {
              <p>{{ 'agentPrincipals.scopeIs' | translate }} <bdi dir="ltr">{{ a.entity_scope?.join(', ') }}</bdi></p>
            }
            <div class="ap-row">
              @for (m of moves(a); track m) {
                <button type="button" [attr.data-move]="m" (click)="move(a, m)" [disabled]="busy()">{{ 'agentPrincipals.move_' + m | translate }}</button>
              }
              @if (a.lifecycle_state === 'active') {
                <button type="button" data-testid="ap-key" (click)="issueKey(a)" [disabled]="busy()">{{ 'agentPrincipals.issueKey' | translate }}</button>
              }
            </div>
            @if (a.lifecycle_state !== 'revoked') {
              <div class="ap-row">
                <label>{{ 'agentPrincipals.newSponsor' | translate }}
                  <input [attr.data-sponsor-for]="a.id" #newSponsor />
                </label>
                <button type="button" (click)="reassign(a, newSponsor.value)" [disabled]="busy() || !newSponsor.value.trim()">
                  {{ 'agentPrincipals.reassign' | translate }}</button>
              </div>
            }
          </article>
        }
        @if (!agents().length) { <p>{{ 'agentPrincipals.none' | translate }}</p> }
      </div>
    </section>
  `,
})
export class AgentPrincipalsComponent {
  private readonly sdk = inject(SdkService);
  private readonly auth = inject(AuthService);

  readonly agents = signal<AgentPrincipal[]>([]);
  readonly name = signal('');
  readonly sponsor = signal('');
  readonly scope = signal('');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  /** The key just issued; cleared when the dialog closes, never shown again. */
  readonly issued = signal<IssuedKey | null>(null);

  constructor() {
    this.load();
  }

  moves(agent: AgentPrincipal) {
    return movesFor(agent.lifecycle_state);
  }

  load(): void {
    this.sdk.get<Page<AgentPrincipal>>(AGENTS, { query: { page_size: 100 } }).subscribe({
      next: page => this.agents.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  create(): void {
    const name = this.name().trim();
    if (!name) return;
    const sponsor = this.sponsor().trim() || this.auth.userId() || undefined;
    this.run(this.sdk.post<AgentPrincipal>(AGENTS, {
      body: { name, sponsor, entity_scope: scopeOf(this.scope()) },
    }), () => {
      this.name.set('');
      this.scope.set('');
    });
  }

  move(agent: AgentPrincipal, action: string): void {
    this.run(this.sdk.post<AgentPrincipal>(`${AGENTS}/${agent.id}/${action}`, { body: {} }, { ifMatch: agent.row_version }));
  }

  reassign(agent: AgentPrincipal, sponsor: string): void {
    this.run(this.sdk.put<AgentPrincipal>(`${AGENTS}/${agent.id}/sponsor`, { body: { sponsor: sponsor.trim() } }, { ifMatch: agent.row_version }));
  }

  issueKey(agent: AgentPrincipal): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<IssuedKey>(`${AGENTS}/${agent.id}/keys`, { body: { name: agent.name } }).subscribe({
      next: key => {
        this.busy.set(false);
        this.issued.set(key);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }

  copy(secret: string): void {
    void navigator.clipboard?.writeText(secret).catch(() => undefined);
  }

  /** Closing forgets the secret: it is not kept anywhere on the page. */
  closeKey(): void {
    this.issued.set(null);
  }

  private run<T>(call: Observable<T>, after?: () => void): void {
    this.busy.set(true);
    this.error.set(null);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        after?.();
        this.load();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }
}
