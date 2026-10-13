import {
  ChangeDetectionStrategy, Component, effect, inject, signal,
} from '@angular/core';
import { AuthService, ApiError, LangService, initGoogleIdentityOnce, type GoogleIdentityGlobal } from '@attome/base';
import { AuthModalService } from '../../services/auth-modal.service';

declare const google: GoogleIdentityGlobal;

@Component({
  selector: 'app-auth-modal',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [],
  host: { '(document:keydown.escape)': 'onEscape()' },
  templateUrl: './auth-modal.component.html',
  styleUrl: './auth-modal.component.css',
})
export class AuthModalComponent {
  private readonly auth     = inject(AuthService);
  private readonly modalSvc = inject(AuthModalService);
  private readonly lang     = inject(LangService);

  readonly isOpen  = this.modalSvc.isOpen;
  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  readonly googleClientId = signal<string | null>(null);

  private scriptLoaded = false;
  private configRequested = false;
  readonly googleBtnId = 'attome-google-btn';

  constructor() {
    effect(() => {
      if (!this.isOpen()) return;
      this.error.set(null);
      this.loadGoogleConfigOnce();
      setTimeout(() => this.initGoogle(), 80);
    });
  }

  /**
   * Was `ngAfterViewInit`, which meant every page load fetched the Google
   * client id and appended the GSI script for a dialog most visitors never
   * open — this component is rendered on every route by AppComponent, even
   * though its whole template sits inside `@if (isOpen())`.
   *
   * Moving it here rather than wrapping the component in `@defer` is
   * deliberate: `@defer` costs 6,458 B of `@angular/core` deferred-block
   * runtime on first use in the app (measured), against the 6,541 B this
   * component contributes — a wash in bytes that still leaves the request on
   * the open path. This removes the request with no byte cost at all.
   *
   * The first open is no slower to become usable than the deferred version
   * would have been, and the button still renders: `initGoogle()` no-ops until
   * the client id lands, and `loadGoogleScript()`'s own load callbacks
   * re-invoke it once the script is ready.
   */
  private loadGoogleConfigOnce(): void {
    if (this.configRequested) return;
    this.configRequested = true;
    this.auth.getGoogleConfig().subscribe({
      next: cfg => {
        this.googleClientId.set(cfg.client_id);
        if (cfg.client_id) this.loadGoogleScript();
      },
      error: () => this.googleClientId.set(null),
    });
  }

  close(): void { this.modalSvc.close(); }

  // Keyboard-equivalent to the backdrop's click-to-dismiss (accessibility
  // remediation) — without this, a keyboard-only user had no way to close
  // the modal at all short of tabbing to the explicit close button.
  onEscape(): void {
    if (this.isOpen()) this.close();
  }

  closeOnBackdrop(event: MouseEvent): void {
    if ((event.target as HTMLElement).classList.contains('modal-backdrop')) this.close();
  }

  closeOnBackdropKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') this.close();
  }

  renderGoogleButton(): void {
    if (!this.scriptLoaded || typeof google === 'undefined') return;
    const el = document.getElementById(this.googleBtnId);
    if (!el) return;
    el.innerHTML = '';
    google.accounts.id.renderButton(el, {
      theme: 'filled_black', size: 'large',
      width: el.offsetWidth || 308, type: 'standard',
      shape: 'rectangular', text: 'signin_with', logo_alignment: 'left',
    });
  }

  private loadGoogleScript(): void {
    if (typeof google !== 'undefined') {
      this.scriptLoaded = true;
      // Cached script path runs synchronously, ahead of Angular flushing the
      // button div into the DOM — defer a tick (see login-page.component.ts).
      if (this.isOpen()) setTimeout(() => this.initGoogle(), 0);
      return;
    }
    const s = document.createElement('script');
    s.src = 'https://accounts.google.com/gsi/client';
    s.async = true; s.defer = true;
    s.onload = () => {
      this.scriptLoaded = true;
      if (this.isOpen()) this.initGoogle();
    };
    document.head.appendChild(s);
  }

  private initGoogle(): void {
    const clientId = this.googleClientId();
    if (typeof google === 'undefined' || !clientId) return;
    initGoogleIdentityOnce({
      client_id: clientId,
      callback: (r: { credential: string }) => this.handleCredential(r),
      auto_select: false,
      cancel_on_tap_outside: false,
    });
    this.renderGoogleButton();
  }

  private handleCredential(r: { credential: string }): void {
    if (!r.credential) return;
    this.loading.set(true);
    this.error.set(null);
    this.auth.loginWithGoogle({ credential: r.credential }).subscribe({
      // Public-site authentication remains on the website. XRM has a
      // separate, explicit authentication entry at /xrm/login.
      next: () => { this.loading.set(false); this.close(); },
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(err.status === 401 ? this.lang.translate('authModal.googleError') : this.lang.errorText(err));
      },
    });
  }
}
