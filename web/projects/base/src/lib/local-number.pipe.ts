import { inject, Pipe, PipeTransform } from '@angular/core';
import { LangService } from './lang.service';

/**
 * P-i18n-a11y §4.2 — locale-aware number formatting (Intl.NumberFormat is
 * already locale-aware, zero new dependency). Every number in the UI should
 * go through this instead of ad hoc `.toLocaleString()`/string interpolation
 * so Arabic-Indic digit rendering etc. is consistent, not per-component luck.
 */
@Pipe({ name: 'localNumber', pure: false, standalone: true })
export class LocalNumberPipe implements PipeTransform {
  private readonly lang = inject(LangService);

  transform(value: number, options?: Intl.NumberFormatOptions): string {
    return new Intl.NumberFormat(this.lang.intlLocale(), options).format(value);
  }
}
