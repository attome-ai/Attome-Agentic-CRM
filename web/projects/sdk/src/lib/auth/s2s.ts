import type { AuthProvider, AuthRequestContext } from './types';

export interface S2sAuthOptions {
  /** `x-s2s-client-id` — the calling system's registered S2S client id. */
  clientId: string;
  /** `x-s2s-key-id` — which of that client's keys is signing this request
   * (S2S keys are rotatable; the server looks up the secret by this id). */
  keyId: string;
  /** Hex-encoded shared secret for `keyId`, as issued by
   * `/api/v1/admin/s2s/...` (see `.claude/commands/attome-s2s-admin.md`).
   * Treat this like any other credential: a secret store, never source
   * control or a log line. */
  secretHex: string;
  /** Override for `Date.now()` — testing only. */
  now?: () => number;
  /** Override for the nonce generator — testing only. Must be unique per
   * request within the server's replay window; defaults to a random UUID. */
  nonce?: () => string;
}

/** Reference implementation of the platform's S2S HMAC request-signing
 * scheme. This is NOT a "similar" scheme — it reproduces
 * `crates/engine/attome-s2s/src/crypto.rs` (`canonical_message` + `verify_hmac`,
 * headers from `middleware.rs`) byte-for-byte:
 *
 * - Canonical message: `"{METHOD}\n{path+query}\n{sha256(body)_hex}\n{timestamp_ms}\n{nonce}"`
 *   (`\n`-joined, exactly 5 fields, body hash of the *empty* byte string for
 *   a bodyless request).
 * - Signature: HMAC-SHA256 over that message, keyed by the hex-decoded
 *   secret, hex-encoded.
 * - Headers: `x-s2s-client-id`, `x-s2s-key-id`, `x-s2s-timestamp`
 *   (milliseconds since epoch, as a decimal string), `x-s2s-nonce`,
 *   `x-s2s-signature`.
 *
 * Do not "improve" or re-derive this scheme independently — a similar-but-
 * different construction (different delimiter, different field order, a
 * base64 instead of hex secret) fails verification silently as an
 * unauthenticated-looking request, not with a helpful diagnostic. */
export class S2sAuth implements AuthProvider {
  /** No cookie involved in this scheme either — see `ApiKeyAuth`'s same
   * field for why this is declared explicitly rather than left off. */
  readonly credentialsMode = undefined;

  constructor(private readonly opts: S2sAuthOptions) {
    if (!opts.clientId || !opts.keyId || !opts.secretHex) {
      throw new Error('S2sAuth requires clientId, keyId and secretHex');
    }
  }

  async applyAuth(ctx: AuthRequestContext): Promise<void> {
    const timestamp = String(Math.trunc((this.opts.now ?? Date.now)()));
    const nonce = (this.opts.nonce ?? randomNonce)();
    const bodyHashHex = await sha256Hex(ctx.body ?? new Uint8Array(0));
    const canonical = `${ctx.method}\n${ctx.pathAndQuery}\n${bodyHashHex}\n${timestamp}\n${nonce}`;
    const signature = await hmacSha256Hex(this.opts.secretHex, canonical);

    ctx.headers.set('x-s2s-client-id', this.opts.clientId);
    ctx.headers.set('x-s2s-key-id', this.opts.keyId);
    ctx.headers.set('x-s2s-timestamp', timestamp);
    ctx.headers.set('x-s2s-nonce', nonce);
    ctx.headers.set('x-s2s-signature', signature);
  }
}

function randomNonce(): string {
  const c = globalThis.crypto;
  if (!c?.randomUUID) {
    throw new Error('S2sAuth needs globalThis.crypto.randomUUID() — Node 19+ or a modern browser');
  }
  return c.randomUUID();
}

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error(
      'S2sAuth needs globalThis.crypto.subtle (Web Crypto) — Node 19+ or a modern browser',
    );
  }
  return c.subtle;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Decodes a lowercase/uppercase hex secret into raw bytes — matches
 * `hex::decode` on the server side (`attome-s2s/src/crypto.rs::verify_hmac`). */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('S2sAuth: secretHex must be an even-length hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await subtle().digest('SHA-256', toArrayBuffer(data));
  return bytesToHex(new Uint8Array(digest));
}

async function hmacSha256Hex(secretHex: string, message: string): Promise<string> {
  const keyBytes = hexToBytes(secretHex);
  const key = await subtle().importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await subtle().sign('HMAC', key, toArrayBuffer(new TextEncoder().encode(message)));
  return bytesToHex(new Uint8Array(sig));
}
