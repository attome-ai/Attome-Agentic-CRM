import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** A pending device grant, as `GET /api/v1/oauth/device` returns it. */
interface PendingGrant {
  client_id: string;
  client_name: string;
  user_code: string;
  created_at: string;
  expires_at: string;
}

/** `user_code` as the server stores it: letters only, upper case. Pure. */
export function normaliseUserCode(code: string): string {
  return code.replace(/[^a-z0-9]/gi, '').toUpperCase();
}

/**
 * C7-T1 / T4-T1 — a device (the CLI, the Outlook add-in, the Gmail add-on)
 * shows a code; the signed-in person enters it here, sees which application
 * asks, and approves or denies it. Routed at `/xrm/device`, with
 * `?user_code=` filled in from the device's link.
 */
@Component({
  selector: 'xrm-device-approval',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <main class="da" data-testid="device-approval">
      <h1>{{ 'deviceApproval.title' | translate }}</h1>
      @switch (state()) {
        @case ('done') {
          <p class="da-done" role="status" data-done>
            {{ (approved() ? 'deviceApproval.approved' : 'deviceApproval.denied') | translate }}
          </p>
        }
        @case ('found') {
          @if (grant(); as g) {
            <p data-client>{{ 'deviceApproval.asks' | translate: { name: g.client_name } }}</p>
            <p class="da-muted">{{ 'deviceApproval.code' | translate }} <strong dir="ltr">{{ g.user_code }}</strong>
              · {{ 'deviceApproval.expires' | translate }} {{ g.expires_at | localDate: { timeStyle: 'short' } }}</p>
            <p class="da-warn">{{ 'deviceApproval.warning' | translate }}</p>
            <div class="da-actions">
              <button type="button" class="primary" data-approve [disabled]="busy()" (click)="decide(true)">
                {{ 'deviceApproval.approve' | translate }}
              </button>
              <button type="button" data-deny [disabled]="busy()" (click)="decide(false)">
                {{ 'deviceApproval.deny' | translate }}
              </button>
            </div>
          }
        }
        @default {
          <form class="da-form" (submit)="$event.preventDefault(); find()">
            <label for="da-code">{{ 'deviceApproval.enterCode' | translate }}</label>
            <input id="da-code" dir="ltr" autocomplete="off" autocapitalize="characters" maxlength="12"
                   [value]="code()" (input)="code.set($any($event.target).value)" />
            <button type="submit" [disabled]="busy() || !code()">{{ 'deviceApproval.continue' | translate }}</button>
          </form>
        }
      }
      @if (error(); as message) { <p class="da-error" role="alert">{{ message }}</p> }
    </main>
  `,
  styles: [`
    :host { display: block; }
    .da { max-inline-size: 32rem; margin-inline: auto; padding: var(--space-4, 1rem); display: grid; gap: .75rem; }
    .da-form { display: grid; gap: .5rem; }
    .da-form input { font-size: 1.5rem; letter-spacing: .2em; text-transform: uppercase; }
    .da-actions { display: flex; gap: .5rem; flex-wrap: wrap; }
    .da-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .da-warn { color: var(--color-warning, #8a5300); margin: 0; }
    .da-error { color: var(--color-danger, #c53030); margin: 0; }
  `],
})
export class DeviceApprovalComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly route = inject(ActivatedRoute);

  readonly code = signal('');
  readonly grant = signal<PendingGrant | null>(null);
  readonly state = signal<'enter' | 'found' | 'done'>('enter');
  readonly approved = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    // The device's link carries the code as `?user_code=`.
    const given = this.route.snapshot.queryParamMap.get('user_code');
    if (given) {
      this.code.set(given);
      this.find();
    }
  }

  /** Looks the code up: which application asks. */
  find(): void {
    const code = normaliseUserCode(this.code());
    if (!code) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.get<PendingGrant>('/api/v1/oauth/device', { user_code: code }).subscribe({
      next: grant => { this.busy.set(false); this.grant.set(grant); this.state.set('found'); },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 404 ? this.lang.translate('deviceApproval.notFound') : this.lang.errorText(e));
      },
    });
  }

  /** Approves or denies the grant. */
  decide(approve: boolean): void {
    const grant = this.grant();
    if (!grant) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.post('/api/v1/oauth/device/approve', { user_code: normaliseUserCode(grant.user_code), approve }).subscribe({
      next: () => { this.busy.set(false); this.approved.set(approve); this.state.set('done'); },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 404 ? this.lang.translate('deviceApproval.notFound') : this.lang.errorText(e));
      },
    });
  }
}
