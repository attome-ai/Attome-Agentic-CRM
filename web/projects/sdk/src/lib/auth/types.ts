/** Everything an `AuthProvider` needs to attach credentials to one outgoing
 * request. `pathAndQuery` and `body` are exposed (not just `headers`)
 * because `S2sAuth` signs over them — they must be exactly what goes out on
 * the wire. */
export interface AuthRequestContext {
  /** Upper-case HTTP method, e.g. `"POST"`. */
  method: string;
  /** Path + query string only — no scheme/host, e.g. `"/api/v1/contact?page=2"`. */
  pathAndQuery: string;
  /** Mutate this to add/replace headers. */
  headers: Headers;
  /** The exact bytes that will be sent as the request body, or `null` for none. */
  body: Uint8Array | null;
}

/** An authentication scheme the SDK's transport delegates to. `applyAuth`
 * may be async (S2S signing hashes the body and computes an HMAC via Web
 * Crypto, both async APIs). */
export interface AuthProvider {
  applyAuth(ctx: AuthRequestContext): Promise<void> | void;
  /** `fetch`'s `credentials` mode to use for every request under this
   * provider. Only `SessionAuth` sets this (`'include'`, so the browser
   * attaches the session/refresh cookies); API-key and S2S auth carry their
   * own credential in a header and need no cookie. */
  readonly credentialsMode?: RequestCredentials;
}
