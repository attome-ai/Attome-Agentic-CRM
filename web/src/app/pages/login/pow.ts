/**
 * Q20-T3: the browser half of the self-hosted proof-of-work challenge
 * (`attome_auth::pow` on the server). Find an answer such that SHA-256 of
 * the challenge's nonce followed by the answer starts with `difficulty`
 * zero bits. `pow.worker.ts` runs this off the page's thread.
 */

/** The leading zero bits of `digest`. */
export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/** The first decimal answer that meets `difficulty`, trying at most `limit`. */
export async function solvePow(nonce: string, difficulty: number, limit = 1 << 26): Promise<string> {
  const encoder = new TextEncoder();
  for (let n = 0; n < limit; n++) {
    const answer = String(n);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(nonce + answer)));
    if (leadingZeroBits(digest) >= difficulty) return answer;
  }
  throw new Error('no proof-of-work answer within the limit');
}
