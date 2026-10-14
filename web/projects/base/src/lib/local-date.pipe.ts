import { inject, isDevMode, Pipe, PipeTransform } from '@angular/core';
import { LangService } from './lang.service';
import { DisplayCalendar, DisplayDigits, UserPreferencesService } from './user-preferences.service';

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
 *
 * AG1-T8: the viewer's calendar (`gregorian`, `hijri` = Umm al-Qura, or
 * `both`, which shows the Gregorian date then the Hijri one) and digits
 * (`latn`, `arab`) ride on the locale as Unicode extensions. An attribute's
 * own `display_calendar` is the third argument and wins over the viewer's.
 * Unset, the language's default applies.
 */
@Pipe({ name: 'localDate', pure: false, standalone: true })
export class LocalDatePipe implements PipeTransform {
  private readonly lang  = inject(LangService);
  private readonly prefs = inject(UserPreferencesService);

  transform(
    value: Date | string | number | null | undefined,
    options?: Intl.DateTimeFormatOptions,
    displayCalendar?: DisplayCalendar | null,
  ): string {
    const date = toDate(value);
    if (!date) {
      if (isDevMode()) console.warn('[attome] LocalDatePipe received an invalid date value:', value);
      return '';
    }

    const preferredZone = this.prefs.timezone();
    const resolved: Intl.DateTimeFormatOptions | undefined =
      preferredZone && !options?.timeZone ? { ...options, timeZone: preferredZone } : options;

    const calendar = displayCalendar ?? this.prefs.calendar();
    const digits = this.prefs.digits();
    const base = this.lang.intlLocale();
    try {
      if (calendar === 'both') {
        const gregorian = new Intl.DateTimeFormat(localeTag(base, 'gregorian', digits), resolved).format(date);
        const hijri = new Intl.DateTimeFormat(localeTag(base, 'hijri', digits), resolved).format(date);
        return `${gregorian} (${hijri})`;
      }
      return new Intl.DateTimeFormat(localeTag(base, calendar, digits), resolved).format(date);
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

/**
 * `locale` with the calendar and numbering-system extensions the viewer chose
 * (`en-US-u-ca-islamic-umalqura-nu-arab`); unchosen ones are left to the
 * language.
 */
export function localeTag(locale: string, calendar: DisplayCalendar | null, digits: DisplayDigits | null): string {
  const extensions: string[] = [];
  if (calendar === 'gregorian') extensions.push('ca-gregory');
  if (calendar === 'hijri') extensions.push('ca-islamic-umalqura');
  if (digits) extensions.push(`nu-${digits}`);
  const plain = locale.split('-u-')[0];
  return extensions.length ? `${plain}-u-${extensions.join('-')}` : plain;
}

/** `null` for a missing or unparseable value; a `Date` otherwise. */
function toDate(value: Date | string | number | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
