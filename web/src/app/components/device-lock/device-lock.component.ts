import { ChangeDetectionStrategy, Component, effect, inject } from '@angular/core';
import { AuthService, TranslatePipe } from '@attome/base';
import { DEFAULT_LOCK_MS, DeviceSecurityService, ManagedConfigService, NativeService } from '@attome/base/native';

/**
 * B17-T5 — the phone app's device security, started once in the host app.
 * Inside the Capacitor shell it follows pause and resume with the lock
 * timeout (the MDM's `lock_timeout_minutes`, B17-T9, or five minutes),
 * registers the phone once a person is signed in (`POST /api/v1/devices`)
 * and checks for a wipe straight away, then on every resume. While an
 * unlock is refused, the app's content is covered and the person can ask
 * again. In a browser it does nothing and renders nothing.
 */
@Component({
  selector: 'app-device-lock',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (security.locked()) {
      <div class="device-lock" role="alertdialog" aria-modal="true"
           aria-labelledby="device-lock-title" data-device-lock>
        <p id="device-lock-title">{{ 'deviceLock.title' | translate }}</p>
        <button type="button" (click)="security.unlock()" data-device-unlock>
          {{ 'deviceLock.unlock' | translate }}
        </button>
      </div>
    }
  `,
  styles: `
    .device-lock {
      position: fixed;
      inset: 0;
      z-index: 2000;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 16px;
      background: var(--color-surface, #fff);
      color: var(--color-text-primary, #111827);
      font-size: 16px;
    }
    .device-lock button {
      border: 0;
      border-radius: 6px;
      padding-block: 10px;
      padding-inline: 20px;
      background: var(--color-primary, #1d4ed8);
      color: #fff;
      font-size: 15px;
      cursor: pointer;
    }
  `,
})
export class DeviceLockComponent {
  protected readonly security = inject(DeviceSecurityService);
  private readonly managed = inject(ManagedConfigService);
  private readonly auth = inject(AuthService);
  private readonly native = inject(NativeService);
  private registered = false;

  constructor() {
    // A browser has no lock, no privacy screen and no wipe to act on, and
    // is not registered as a device.
    if (!this.native.isNative()) return;
    void this.managed.get().then(config =>
      this.security.start(
        config.lock_timeout_minutes ? config.lock_timeout_minutes * 60_000 : DEFAULT_LOCK_MS,
      ),
    );
    // Register once per app run, after sign-in; a failure is tried again at
    // the next sign-in. The wipe check runs at once, so a phone wiped while
    // the app was closed is cleared on opening, not only on a resume.
    effect(() => {
      if (!this.auth.isLoggedIn() || this.registered) return;
      this.registered = true;
      void this.security
        .appVersion()
        .then(version => this.security.register(version))
        .then(() => this.security.checkWipe())
        .catch(() => {
          this.registered = false;
        });
    });
  }
}
