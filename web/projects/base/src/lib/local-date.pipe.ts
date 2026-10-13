import { inject, isDevMode, Pipe, PipeTransform } from '@angular/core';
import { LangService } from './lang.service';
import { UserPreferencesService } from './user-preferences.service';

/**
 * P-i18n-a11y §4.2 — locale-aware date formatting (Intl.DateTimeFormat).
 * Consumed across `@attome/xrm`: the record activity/timeline panels, the
 * governance change feed, data catalog and data quality screens, file
 * versions, knowledge coverage/drafts, agent sessions and the SLA badge all
 * render dates through it (in templates and through
 * `declarative-widget-renderer.component.ts`).
 *
 * D-404 / M83 Phase 1: when the viewer has a stored timezone preference
 * (`UserPreferencesService.timezone`, set from `user_account
 * .timezone`), it is used in place of the browser's implicit local
 * timezone — the platform's dates are always UTC on the wire, so which
 * timezone renders them is purely a display choice. A caller that passes
 * its own `options.timeZone` still wins (explicit beats preference beats
 * browser default); the common case of no `options` at all now renders in
 * the viewer's stored zone when they have one.
 *
 * NGB-F26 / OD-11: a pipe must never throw on data. A missing or unparseable
 * value renders `''` (matching Angular's own `DatePipe` for `null`), and an
 * `Intl` refusal — an unknown IANA zone, most often — falls back to the
 * browser's own zone rather than taking the whole view down with a
 * `RangeError`. Invalid values warn once in development only.
 */
@Pipe({ name: 'localDate', pure: false, standalone: true })
export class LocalDatePipe implements PipeTransform {
  private readonly lang  = inject(LangService);
  private readonly prefs = inject(UserPreferencesService);

  transform(value: Date | string | number | null | undefined, options?: Intl.DateTimeFormatOptions): string {
    const date = toDate(value);
    if (!date) {
      if (isDevMode()) console.warn('[attome] LocalDatePipe received an invalid date value:', value);
      return '';
    }

    const preferredZone = this.prefs.timezone();
    const resolved: Intl.DateTimeFormatOptions | undefined =
      preferredZone && !options?.timeZone ? { ...options, timeZone: preferredZone } : options;

    try {
      return new Intl.DateTimeFormat(this.lang.intlLocale(), resolved).format(date);
    } catch {
      // An unusable `timeZone` (or any other `Intl` refusal) is a display
      // problem, not a data problem: render in the browser's own zone.
      if (resolved?.timeZone) {
        const { timeZone: _unusable, ...rest } = resolved;
        try {
          return new Intl.DateTimeFormat(this.lang.intlLocale(), rest).format(date);
        } catch { /* fall through to '' */ }
      }
      return '';
    }
  }
}

/** `null` for a missing or unparseable value; a `Date` otherwise. */
function toDate(value: Date | string | number | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
