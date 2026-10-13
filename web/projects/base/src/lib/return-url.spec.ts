import { convertToParamMap } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { consumeReturnUrl, isSafeReturnUrl } from './return-url';

/**
 * NGB-1.3 / NGB-F3. The guard and the interceptor both write `?returnUrl=`;
 * this is the module that reads it, and the only shape it accepts is a
 * same-origin relative path — otherwise the first consumer of that parameter
 * is an open redirect.
 */
describe('isSafeReturnUrl', () => {
  it('accepts a same-origin relative path, with query and fragment', () => {
    expect(isSafeReturnUrl('/xrm/entity/x?id=1')).toBe(true);
    expect(isSafeReturnUrl('/settings/security?tab=keys#top')).toBe(true);
    expect(isSafeReturnUrl('/')).toBe(true);
  });

  it('rejects anything that leaves the origin', () => {
    for (const url of ['//evil.example/x', 'https://evil.example', 'http://evil.example/']) {
      expect(isSafeReturnUrl(url), url).toBe(false);
    }
  });

  it('rejects the backslash normalisation trick and control characters', () => {
    expect(isSafeReturnUrl('/\\evil.example')).toBe(false);
    expect(isSafeReturnUrl('/a\\b')).toBe(false);
    expect(isSafeReturnUrl('/a\nb')).toBe(false);
    expect(isSafeReturnUrl('/a\rb')).toBe(false);
    expect(isSafeReturnUrl('/a\u0000b')).toBe(false);
    expect(isSafeReturnUrl('/a\u007fb')).toBe(false);
  });

  it('rejects relative paths without a leading slash and non-strings', () => {
    for (const url of ['settings', 'evil.example', '', null, undefined, 42, {}, []]) {
      expect(isSafeReturnUrl(url), String(url)).toBe(false);
    }
  });
});

describe('consumeReturnUrl (NGB-1.3 / OD-5)', () => {
  function route(returnUrl?: string) {
    return {
      snapshot: {
        queryParamMap: convertToParamMap(returnUrl === undefined ? {} : { returnUrl }),
      },
    } as never;
  }

  it('honours a safe deep link, query string included', () => {
    expect(consumeReturnUrl(route('/xrm/entity/x?id=1'), '/home')).toBe('/xrm/entity/x?id=1');
  });

  it('falls back when the parameter is absent', () => {
    expect(consumeReturnUrl(route(), '/home')).toBe('/home');
  });

  it('falls back for every unsafe value instead of navigating off-origin', () => {
    for (const unsafe of ['//evil', 'https://evil', '/\\evil', '/a\\nb', 'relative']) {
      expect(consumeReturnUrl(route(unsafe), '/home'), unsafe).toBe('/home');
    }
  });

  it('falls back when there is no route at all', () => {
    expect(consumeReturnUrl(null, '/home')).toBe('/home');
    expect(consumeReturnUrl(undefined, '/home')).toBe('/home');
  });
});
