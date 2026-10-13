import { inject, Pipe, PipeTransform } from '@angular/core';
import { LangService } from './lang.service';

/**
 * P-i18n-a11y §4.1 — now resolves a catalog key ('namespace.key') through
 * LangService/TranslocoService instead of indexing a {en,ar} object literal
 * passed in directly. `pure: false` is unchanged from before: this must
 * re-evaluate on every CD cycle so a language switch re-renders without an
 * async pipe/Observable subscription in every template.
 */
@Pipe({ name: 'translate', pure: false, standalone: true })
export class TranslatePipe implements PipeTransform {
  private readonly lang = inject(LangService);

  transform(key: string, params?: Record<string, unknown>): string {
    return this.lang.translate(key, params);
  }
}
