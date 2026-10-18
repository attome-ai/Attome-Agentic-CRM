import { describe, expect, it } from 'vitest';
import { leadingZeroBits, solvePow } from './pow';

describe('proof-of-work solver (Q20-T3)', () => {
  it('counts leading zero bits across bytes', () => {
    expect(leadingZeroBits(new Uint8Array([0, 0, 0b0001_0000]))).toBe(19);
    expect(leadingZeroBits(new Uint8Array([0xff]))).toBe(0);
    expect(leadingZeroBits(new Uint8Array([0, 0x80]))).toBe(8);
  });

  it('finds an answer whose hash meets the difficulty', async () => {
    const answer = await solvePow('00ff', 8);
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('00ff' + answer)),
    );
    expect(leadingZeroBits(digest)).toBeGreaterThanOrEqual(8);
  });

  it('gives up past its limit', async () => {
    await expect(solvePow('00ff', 32, 4)).rejects.toThrow();
  });
});
