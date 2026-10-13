import type { AuthProvider, AuthRequestContext } from './types';

/** API-key auth: `Authorization: ApiKey <public>:<secret>`
 * (`attome-server/src/middleware/auth.rs`'s `parse_api_key_header` — matched
 * byte-for-byte, including the single space after `ApiKey` and the `:`
 * separator with no surrounding spaces).
 *
 * `publicKey`/`secret` are the `atk_pub_…`/`atk_sec_…` values from
 * `POST /api/v1/admin/api-keys` — the secret is shown once at creation and
 * cannot be recovered afterwards; store it in a secret manager, not in
 * source control. */
export class ApiKeyAuth implements AuthProvider {
  /** No cookie involved in this scheme — `undefined` leaves `fetch`'s
   * default `credentials` mode (`'same-origin'`) untouched. Declared
   * explicitly (not just left off the class) so the optional property on
   * `AuthProvider` is still readable off a concrete `ApiKeyAuth` instance,
   * not only through the interface type. */
  readonly credentialsMode = undefined;

  constructor(
    private readonly publicKey: string,
    private readonly secret: string,
  ) {
    if (!publicKey || !secret) {
      throw new Error('ApiKeyAuth requires both a non-empty publicKey and secret');
    }
  }

  applyAuth(ctx: AuthRequestContext): void {
    ctx.headers.set('authorization', `ApiKey ${this.publicKey}:${this.secret}`);
  }
}
