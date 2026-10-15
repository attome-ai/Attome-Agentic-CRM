import { Injectable, inject } from '@angular/core';
import { from, Observable } from 'rxjs';
import type { Translation, TranslocoLoader } from '@jsverse/transloco';
import { CATALOG_LOAD } from './catalogs';

/**
 * Bundled-at-build-time catalog loader (P-i18n-a11y §4.1) — no HTTP
 * round-trip, no assets/ folder to keep in sync with the compiled bundle.
 * Translations ship inside @attome/base's own JS, same as the inline
 * {en,ar} objects they replace, just centralized instead of per-component.
 *
 * English is in the initial bundle; Arabic is its own lazy chunk
 * (`@attome/base/i18n-ar`) — see catalogs.ts. Both still come from bundled JS.
 */
@Injectable({ providedIn: 'root' })
export class InMemoryTranslocoLoader implements TranslocoLoader {
  private readonly load = inject(CATALOG_LOAD);

  getTranslation(lang: string): Observable<Translation> {
    return from(this.load(lang));
  }
}
