import type { AuthProvider, AuthRequestContext } from './types';

/** Browser session-cookie auth. There is no secret for this SDK to hold —
 * the browser attaches the `session`/refresh cookies automatically once the
 * transport is configured with `credentials: 'include'` (this provider sets
 * that via `credentialsMode`), after a normal `POST /api/v1/auth/login`
 * (outside this SDK's scope — use `fetch`/the host app's own login flow,
 * then point `AttomeClient` at this provider for subsequent calls).
 *
 * **Mutating requests need real browser context.** `attome-server`'s CSRF
 * check (`middleware/csrf.rs`) allows a cookie-authenticated unsafe-method
 * request only when the browser's own `Origin`/`Sec-Fetch-Site` metadata
 * shows it originated from an allow-listed origin — a same-origin `fetch`
 * from a page served by this deployment satisfies that automatically. A
 * non-browser environment (Node, a CLI, a server-to-server script) sending a
 * session cookie for a `POST`/`PATCH`/`DELETE` gets a 403: the server's own
 * rejection message is "non-browser clients carrying a cookie should use an
 * API key instead" — use `ApiKeyAuth` or `S2sAuth` there. Plain `GET`s work
 * from anywhere a valid cookie can reach the server. */
export class SessionAuth implements AuthProvider {
  readonly credentialsMode: RequestCredentials = 'include';

  applyAuth(_ctx: AuthRequestContext): void {
    // No-op by design: the credential is the cookie the browser attaches via
    // `credentials: 'include'`, not anything this class holds or computes.
  }
}
