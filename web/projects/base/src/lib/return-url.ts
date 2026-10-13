import type { ActivatedRoute } from '@angular/router';

/**
 * NGB-F3 / OD-5. Both `authGuard` and `authInterceptor` write a `returnUrl`
 * query param; before this module nothing read it (a deep link to a guarded
 * route landed on the dashboard instead), and the obvious first consumer —
 * `router.navigateByUrl(route.snapshot.queryParamMap.get('returnUrl'))` —
 * would have been an open redirect: `//evil.example` and `https://evil.example`
 * both navigate off-origin.
 *
 * Every reader goes through `consumeReturnUrl`. There is one accepted shape:
 * a same-origin relative path.
 */

/**
 * A same-origin relative path: starts with exactly one `/`, is not
 * protocol-relative (`//`), contains no backslash (browsers normalise `/\` to
 * `//`), and carries no control characters (a bare CR/LF is enough to smuggle
 * a second header into some intermediaries).
 */
export function isSafeReturnUrl(url: unknown): url is string {
  if (typeof url !== 'string' || !url.startsWith('/') || url.startsWith('//') || url.includes('\\')) {
    return false;
  }
  for (let i = 0; i < url.length; i++) {
    const c = url.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

/**
 * The one sanctioned reader of `?returnUrl=`. Returns the validated path, or
 * `fallback` when the parameter is absent, external, or otherwise unsafe.
 *
 * `fallback` is the caller's own route: a login page falls back to the home
 * route, a settings page to itself.
 */
export function consumeReturnUrl(route: ActivatedRoute | null | undefined, fallback: string): string {
  const raw = route?.snapshot?.queryParamMap?.get('returnUrl') ?? null;
  return isSafeReturnUrl(raw) ? raw : fallback;
}
