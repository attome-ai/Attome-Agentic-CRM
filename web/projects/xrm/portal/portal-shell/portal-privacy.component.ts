import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { PortalSiteService } from './portal-site.service';

/** One of the person's privacy requests (`GET /{keyword}/api/v1/me/privacy-requests`). */
export interface PortalPrivacyRequest {
  id: string;
  request_type: string;
  status: string;
  requested_at: string;
  due_at: string | null;
  fulfilled_at: string | null;
}

/** The kinds of request a person may make about their own data. */
export const PRIVACY_REQUEST_TYPES = ['access', 'portability', 'rectification', 'restriction', 'objection', 'erasure'] as const;

/**
 * R1-T2 — `/p/:keyword/privacy`: the signed-in person asks about their own
 * personal data (a copy, portability, correction, restriction, objection or
 * erasure), giving their password again to prove it is them, and follows
 * each request's status and deadline. Staff work the requests with every
 * other data subject request.
 */
@Component({
  selector: 'xrm-portal-privacy',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="pv" data-testid="portal-privacy">
      <h1>{{ 'portalSite.privacy' | translate }}</h1>
      <form class="pv-form" (submit)="$event.preventDefault(); submit()">
        <label for="pv-type">{{ 'portalSite.privacyType' | translate }}</label>
        <select id="pv-type" [value]="type()" (change)="type.set($any($event.target).value)">
          @for (t of types; track t) { <option [value]="t">{{ 'portalSite.privacyTypes.' + t | translate }}</option> }
        </select>
        <label for="pv-password">{{ 'portalSite.password' | translate }}</label>
        <input id="pv-password" type="password" autocomplete="current-password" dir="ltr"
               [value]="password()" (input)="password.set($any($event.target).value)" />
        <button type="submit" [disabled]="busy() || !password()" data-request>{{ 'portalSite.privacySend' | translate }}</button>
        @if (sent()) { <p role="status">{{ 'portalSite.privacySent' | translate }}</p> }
        @if (error(); as message) { <p role="alert" class="pv-error">{{ message }}</p> }
      </form>
      <h2>{{ 'portalSite.privacyMine' | translate }}</h2>
      @if (requests().length) {
        <ul class="pv-list">
          @for (r of requests(); track r.id) {
            <li [attr.data-request-id]="r.id">
              {{ 'portalSite.privacyTypes.' + r.request_type | translate }} ·
              {{ 'portalSite.privacyStatus.' + r.status | translate }} ·
              {{ r.requested_at | localDate: { dateStyle: 'medium' } }}
              @if (r.due_at && r.status === 'pending') { · {{ 'portalSite.privacyDue' | translate }} {{ r.due_at | localDate: { dateStyle: 'medium' } }} }
            </li>
          }
        </ul>
      } @else {
        <p class="pv-muted">{{ 'portalSite.privacyNone' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .pv { display: grid; gap: .75rem; max-inline-size: 36rem; }
    .pv-form { display: grid; gap: .5rem; }
    .pv-form button { justify-self: start; }
    .pv-list { margin: 0; padding-inline-start: 1.25rem; }
    .pv-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .pv-error { color: var(--color-danger, #c53030); }
  `],
})
export class PortalPrivacyComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly site = inject(PortalSiteService);
  private readonly lang = inject(LangService);

  readonly types = PRIVACY_REQUEST_TYPES;
  readonly type = signal<string>('access');
  readonly password = signal('');
  readonly requests = signal<PortalPrivacyRequest[]>([]);
  readonly busy = signal(false);
  readonly sent = signal(false);
  readonly error = signal<string | null>(null);

  private path(): string | null {
    const keyword = this.site.keyword();
    return keyword ? `/${encodeURIComponent(keyword)}/api/v1/me/privacy-requests` : null;
  }

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    const path = this.path();
    if (!path) return;
    this.api.get<PortalPrivacyRequest[]>(path).subscribe({
      next: list => this.requests.set(list),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  submit(): void {
    const path = this.path();
    if (!path || !this.password()) return;
    this.busy.set(true);
    this.sent.set(false);
    this.error.set(null);
    this.api.post<PortalPrivacyRequest>(path, { request_type: this.type(), password: this.password() }).subscribe({
      next: created => {
        this.busy.set(false);
        this.password.set('');
        this.sent.set(true);
        this.requests.update(list => [created, ...list]);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
