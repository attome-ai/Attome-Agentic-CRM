import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** One session about me (`GET /api/v1/me/impersonation-sessions`). */
export interface SessionAboutMe {
  id: string;
  actor_id: string;
  mode: string;
  reason: string;
  started_at: string;
  expires_at: string;
  ended_at?: string | null;
}

/** One consent (`GET /api/v1/me/impersonation-consents`). */
export interface MyConsent {
  id: string;
  actor_id: string;
  granted_at: string;
  expires_at: string;
  revoked_at?: string | null;
}

const CONSENTS = '/api/v1/me/impersonation-consents';

/**
 * Q13-T2 — who has seen or acted as me, and who may act as me: every
 * view-as or act-as session about the signed-in person, and their consents,
 * which they give one administrator (by email) for up to 72 hours and
 * withdraw at any time.
 */
@Component({
  selector: 'xrm-impersonation-access-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <section class="admin-page">
      <header class="page-header">
        <h1>{{ 'impersonationAccess.title' | translate }}</h1>
        <p class="page-subtitle">{{ 'impersonationAccess.subtitle' | translate }}</p>
      </header>
      @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }

      <h2>{{ 'impersonationAccess.consents' | translate }}</h2>
      <div class="form-row-3">
        <div class="field">
          <label for="ia-email">{{ 'impersonationAccess.adminEmail' | translate }}</label>
          <input id="ia-email" type="email" dir="ltr" [(ngModel)]="email">
        </div>
        <div class="field">
          <label for="ia-hours">{{ 'impersonationAccess.hours' | translate }}</label>
          <input id="ia-hours" type="number" min="1" max="72" [(ngModel)]="hours">
        </div>
        <div class="btn-row">
          <button class="btn-primary" (click)="grant()" [disabled]="busy()">{{ 'impersonationAccess.allow' | translate }}</button>
        </div>
      </div>
      @if (consents().length === 0) {
        <p class="state-msg">{{ 'impersonationAccess.noConsents' | translate }}</p>
      } @else {
        <table>
          <thead><tr>
            <th>{{ 'impersonationAccess.admin' | translate }}</th>
            <th>{{ 'impersonationAccess.until' | translate }}</th>
            <th></th>
          </tr></thead>
          <tbody>
            @for (c of consents(); track c.id) {
              <tr>
                <td class="cell-mono">{{ c.actor_id }}</td>
                <td>
                  @if (c.revoked_at) { {{ 'impersonationAccess.withdrawn' | translate }} }
                  @else { {{ c.expires_at | localDate }} }
                </td>
                <td class="actions">
                  @if (!c.revoked_at) {
                    <button class="btn-sm btn-sm-danger" (click)="withdraw(c)" [disabled]="busy()">
                      {{ 'impersonationAccess.withdraw' | translate }}
                    </button>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }

      <h2>{{ 'impersonationAccess.sessions' | translate }}</h2>
      @if (sessions().length === 0) {
        <p class="state-msg">{{ 'impersonationAccess.noSessions' | translate }}</p>
      } @else {
        <table>
          <thead><tr>
            <th>{{ 'impersonationAccess.admin' | translate }}</th>
            <th>{{ 'impersonationAccess.mode' | translate }}</th>
            <th>{{ 'impersonationAccess.reason' | translate }}</th>
            <th>{{ 'impersonationAccess.started' | translate }}</th>
          </tr></thead>
          <tbody>
            @for (s of sessions(); track s.id) {
              <tr>
                <td class="cell-mono">{{ s.actor_id }}</td>
                <td>{{ ('impersonationAccess.mode_' + s.mode) | translate }}</td>
                <td>{{ s.reason }}</td>
                <td>{{ s.started_at | localDate }}</td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>
  `,
})
export class ImpersonationAccessPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly sessions = signal<SessionAboutMe[]>([]);
  readonly consents = signal<MyConsent[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  email = '';
  hours = 4;

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.getAllPages<SessionAboutMe>('/api/v1/me/impersonation-sessions').subscribe({
      next: rows => this.sessions.set(rows),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.api.getAllPages<MyConsent>(CONSENTS).subscribe({
      next: rows => this.consents.set(rows),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  grant(): void {
    const email = this.email.trim();
    if (!email) {
      this.error.set(this.lang.translate('impersonationAccess.emailRequired'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.api.post<MyConsent>(CONSENTS, { actor_email: email, hours: Number(this.hours) }).subscribe({
      next: c => {
        this.busy.set(false);
        this.email = '';
        this.consents.update(list => [c, ...list]);
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  withdraw(c: MyConsent): void {
    this.busy.set(true);
    this.api.delete(`${CONSENTS}/${c.id}`).subscribe({
      next: () => {
        this.busy.set(false);
        this.consents.update(list => list.map(x => x.id === c.id ? { ...x, revoked_at: new Date().toISOString() } : x));
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
