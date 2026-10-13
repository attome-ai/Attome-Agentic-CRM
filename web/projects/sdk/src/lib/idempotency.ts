// Idempotency-key helper matching `attome_server`'s existing gate
// (crates/foundation/attome-server/src/middleware/idempotency.rs) exactly.

/** The header the server's idempotency gate reads (`const HEADER` in
 * `middleware/idempotency.rs`). A completed mutating request replays its
 * cached response when retried with the same key + method + route + body;
 * reusing the key for a materially different request is a 409
 * `idempotency_conflict`, not a silent overwrite. */
export const IDEMPOTENCY_KEY_HEADER = 'x-idempotency-key';

/** Generates a fresh idempotency key (a v4 UUID via `crypto.randomUUID()`).
 * Call this ONCE per logical operation and reuse the same value across
 * retries of that operation — a new key per retry defeats the point. */
export function generateIdempotencyKey(): string {
  const c = globalThis.crypto;
  if (!c?.randomUUID) {
    throw new Error(
      'generateIdempotencyKey() needs globalThis.crypto.randomUUID() — Node 19+ or a modern browser',
    );
  }
  return c.randomUUID();
}
