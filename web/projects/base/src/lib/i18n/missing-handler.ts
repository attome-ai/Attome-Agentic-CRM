import { Injectable } from '@angular/core';
import type { TranslocoMissingHandler } from '@jsverse/transloco';

/**
 * NGB-3.5 / OD-10. Two things a missing key must never do: render as its own
 * raw key, and disappear silently.
 *
 * `provideAttomeI18n` sets `missingHandler.useFallbackTranslation`, so Transloco
 * itself resolves an `ar`-missing key against `en` before this handler is even
 * consulted — a raw key is worse than English text. This handler is what runs
 * when the key is absent from *both* catalogs: it warns once per key (in
 * production too, where `prodMode` silences Transloco's own dev-only warning)
 * and then returns the key, which is the least-bad rendering left.
 */
@Injectable()
export class WarnOnceMissingHandler implements TranslocoMissingHandler {
  private readonly warned = new Set<string>();

  handle(key: string): string {
    if (!this.warned.has(key)) {
      this.warned.add(key);
      console.warn(`[attome] missing translation key '${key}' — no catalog defines it.`);
    }
    return key;
  }
}
