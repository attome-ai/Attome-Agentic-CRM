import { inject, isDevMode, Pipe, PipeTransform } from '@angular/core';
import { LangService } from './lang.service';
import { formatHijri, toHijri } from './hijri';
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
 * (`latn`, `arab`). An attribute's own `display_calendar` is the third
 * argument and wins over the viewer's. Hijri dates come from the same
 * Umm al-Qura table the server uses (`hijri.ts`), the day being the one the
 * viewer's time zone shows, with the time (when asked for) from `Intl`.
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
      if (calendar === 'hijri' || calendar === 'both') {
        const hijri = this.hijriText(date, base, digits, resolved);
        if (calendar === 'hijri') return hijri;
        const gregorian = new Intl.DateTimeFormat(localeTag(base, 'gregorian', digits), resolved).format(date);
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

  /**
   * The Hijri date (and the time, when `options` asks for one) from the
   * Umm al-Qura table; `Intl`'s own Umm al-Qura calendar past its ends.
   */
  private hijriText(
    date: Date,
    base: string,
    digits: DisplayDigits | null,
    options: Intl.DateTimeFormatOptions | undefined,
  ): string {
    const hijri = toHijri(localDay(date, options?.timeZone));
    if (!hijri) return new Intl.DateTimeFormat(localeTag(base, 'hijri', digits), options).format(date);
    const text = formatHijri(hijri, this.lang.current(), digits);
    const wantsTime = options?.hour !== undefined || options?.minute !== undefined || options?.timeStyle !== undefined;
    if (!wantsTime) return text;
    const { hour, minute, second, hour12, timeZone, timeStyle } = options ?? {};
    const time = new Intl.DateTimeFormat(localeTag(base, null, digits), {
      hour, minute, second, hour12, timeZone, timeStyle,
    }).format(date);
    return `${text} ${time}`;
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

/**
 * The Gregorian day `date` falls on in `timeZone` (the browser's when
 * absent), as `yyyy-mm-dd`.
 */
export function localDay(date: Date, timeZone?: string): string {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(date);
  const part = (type: string) => parts.find(p => p.type === type)?.value ?? '';
  return `${part('year')}-${part('month')}-${part('day')}`;
}

/** `null` for a missing or unparseable value; a `Date` otherwise. */
function toDate(value: Date | string | number | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
