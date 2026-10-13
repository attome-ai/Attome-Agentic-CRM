import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { Ack, ApiError, AuthService, MfaRecoveryCodes } from '@attome/base';

type PendingAction = 'disable' | 'regenerate' | null;

@Component({
  selector:   'xrm-mfa-settings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls:  ['../../../styles/admin-page.css', './mfa-settings.component.css'],
  templateUrl: './mfa-settings.component.html',
})
export class MfaSettingsComponent implements OnInit {
  private readonly auth = inject(AuthService);

  readonly loading    = signal(true);
  readonly submitting = signal(false);
  readonly error      = signal<string | null>(null);
  readonly status     = signal<{ enrolled: boolean } | null>(null);

  readonly enrolling      = signal<{ secret_base32: string; otpauth_uri: string } | null>(null);
  readonly recoveryCodes  = signal<string[] | null>(null);
  readonly pendingAction  = signal<PendingAction>(null);
  readonly codeInput      = signal('');

  ngOnInit(): void {
    this.refreshStatus();
  }

  private refreshStatus(): void {
    this.loading.set(true);
    this.auth.getMfaStatus().subscribe({
      next:  s => { this.status.set(s); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  startEnrollment(): void {
    this.error.set(null);
    this.auth.enrollMfa().subscribe({
      next:  info => this.enrolling.set(info),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  cancelEnrollment(): void {
    this.enrolling.set(null);
    this.codeInput.set('');
    this.error.set(null);
  }

  confirmEnrollment(): void {
    if (!this.codeInput()) return;
    this.submitting.set(true);
    this.error.set(null);
    this.auth.confirmMfa(this.codeInput()).subscribe({
      next: res => {
        this.submitting.set(false);
        this.enrolling.set(null);
        this.codeInput.set('');
        this.recoveryCodes.set(res.recovery_codes);
      },
      error: (e: ApiError) => {
        this.submitting.set(false);
        this.error.set(e.status === 401 ? 'Invalid code. Please try again.' : e.message);
      },
    });
  }

  acknowledgeRecoveryCodes(): void {
    this.recoveryCodes.set(null);
    this.refreshStatus();
  }

  startPendingAction(action: PendingAction): void {
    this.pendingAction.set(action);
    this.codeInput.set('');
    this.error.set(null);
  }

  cancelPendingAction(): void {
    this.pendingAction.set(null);
    this.codeInput.set('');
    this.error.set(null);
  }

  confirmPendingAction(): void {
    const action = this.pendingAction();
    if (!action || !this.codeInput()) return;
    this.submitting.set(true);
    this.error.set(null);

    const req$: Observable<Ack | MfaRecoveryCodes> = action === 'disable'
      ? this.auth.disableMfa(this.codeInput())
      : this.auth.regenerateMfaRecoveryCodes(this.codeInput());

    req$.subscribe({
      next: res => {
        this.submitting.set(false);
        this.pendingAction.set(null);
        this.codeInput.set('');
        if (action === 'regenerate' && 'recovery_codes' in res) {
          this.recoveryCodes.set(res.recovery_codes);
        } else {
          this.refreshStatus();
        }
      },
      error: (e: ApiError) => {
        this.submitting.set(false);
        this.error.set(e.status === 401 ? 'Invalid code. Please try again.' : e.message);
      },
    });
  }
}
