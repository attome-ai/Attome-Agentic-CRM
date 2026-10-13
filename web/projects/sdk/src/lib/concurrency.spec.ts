import { describe, expect, it } from 'vitest';
import { IF_MATCH_HEADER, IF_NONE_MATCH_HEADER, ifMatchValue, rowVersionFromETag } from './concurrency';

describe('concurrency', () => {
  it('uses the header names the server row_version contract reads', () => {
    expect(IF_MATCH_HEADER).toBe('If-Match');
    expect(IF_NONE_MATCH_HEADER).toBe('If-None-Match');
  });

  it('formats a row_version as a quoted value, matching @attome/base ApiService', () => {
    expect(ifMatchValue(3)).toBe('"3"');
    expect(ifMatchValue('7')).toBe('"7"');
  });

  describe('rowVersionFromETag', () => {
    it('parses the weak ETag the server emits (row_version_etag: W/"n")', () => {
      expect(rowVersionFromETag('W/"3"')).toBe(3);
    });

    it('parses a bare quoted or unquoted value too', () => {
      expect(rowVersionFromETag('"42"')).toBe(42);
      expect(rowVersionFromETag('42')).toBe(42);
    });

    it('returns undefined rather than throwing on a missing or unparseable header', () => {
      expect(rowVersionFromETag(null)).toBeUndefined();
      expect(rowVersionFromETag(undefined)).toBeUndefined();
      expect(rowVersionFromETag('')).toBeUndefined();
      expect(rowVersionFromETag('W/"not-a-number"')).toBeUndefined();
    });
  });
});
