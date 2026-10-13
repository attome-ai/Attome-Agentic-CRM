// Minimal shape of the Google Identity Services global actually used across
// this library (this module's `initialize` plus the `renderButton` call every
// consumer makes) — not a full GSI type surface, just enough to avoid `any`.
// Exported so a consumer shares this declaration instead of re-declaring the
// same global `google` const with a conflicting type.
export interface GoogleIdentityGlobal {
  accounts: {
    id: {
      initialize(config: {
        client_id: string;
        callback: (response: { credential: string }) => void;
        auto_select?: boolean;
        cancel_on_tap_outside?: boolean;
      }): void;
      renderButton(
        parent: HTMLElement,
        options: {
          theme?: 'outline' | 'filled_blue' | 'filled_black';
          size?: 'large' | 'medium' | 'small';
          width?: number;
          type?: 'standard' | 'icon';
          shape?: 'rectangular' | 'pill' | 'circle' | 'square';
          text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
          logo_alignment?: 'left' | 'center';
        },
      ): void;
    };
  };
}
declare const google: GoogleIdentityGlobal;

// google.accounts.id.initialize() must only ever run once per page, no matter
// how many components want a Google Sign-In button (login page, the
// always-mounted auth modal, and the security-settings linking button all
// do). GSI itself warns "called multiple times ... only the last initialized
// instance will be used" and in practice drops the button/origin check
// intermittently when re-invoked, so the real `initialize()` call happens at
// most once per page (`gsiInitialized`).
//
// That one real callback is a stable indirection (`activeCallback`), not any
// single consumer's closure — needed once a consumer's callback does
// something other than log in (P-federation-linking-policy §4.3(a) extended
// to Google: security-settings's callback links the credential to the
// caller's own already-authenticated account instead of starting a session).
// Every call to `initGoogleIdentityOnce` updates `activeCallback`, even after
// the real `initialize()` already ran elsewhere, so whichever component last
// registered — always the one currently rendering its own button, per each
// component's own script-load/init/render sequence in `ngAfterViewInit`/
// equivalent — is the one a click actually reaches. Safe in practice because
// this app never shows two Google buttons whose actions should differ at the
// same time: the sign-in buttons only ever render for a logged-out visitor,
// the security-settings linking button only for an already logged-in one
// (`authGuard`).
let gsiInitialized = false;
let activeCallback: ((response: { credential: string }) => void) | null = null;

export function initGoogleIdentityOnce(config: {
  client_id: string;
  callback: (response: { credential: string }) => void;
  auto_select?: boolean;
  cancel_on_tap_outside?: boolean;
}): void {
  activeCallback = config.callback;
  if (gsiInitialized) return;
  google.accounts.id.initialize({
    ...config,
    callback: response => activeCallback?.(response),
  });
  gsiInitialized = true;
}
