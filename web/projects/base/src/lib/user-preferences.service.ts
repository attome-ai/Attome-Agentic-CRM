import { Injectable, signal } from '@angular/core';

/**
 * D-404 / M83 Phase 1 — a pure signal holder for the current viewer's
 * per-user preferences that a base-layer pipe needs but has no business
 * knowing how to fetch: today just `timezone` (IANA zone name, e.g.
 * "Asia/Dubai"). `@attome/base` has no XRM endpoint knowledge (see
 * `ApiService.getAllPages`'s own doc comment on that boundary), so this
 * service never calls the network itself — the XRM layer resolves the
 * current user's own `user_account.timezone` and calls
 * `setTimezone()` once it knows it (`ProfileMenuComponent` does this today).
 * Same shape as `ThemeService`/`LangService`: a signal set from outside,
 * read reactively from inside (here, by `LocalDatePipe`).
 *
 * `null` means "no preference set" — `LocalDatePipe` falls back to the
 * browser's own timezone exactly as it did before this service existed.
 */
@Injectable({ providedIn: 'root' })
export class UserPreferencesService {
  readonly timezone = signal<string | null>(null);

  /**
   * NGB-F26. An unknown IANA zone used to be stored verbatim and then thrown
   * back out of every `Intl.DateTimeFormat` that read it — one bad stored
   * value broke every date view for that user. Probe it here instead: an
   * unusable zone is the same thing as no preference.
   */
  setTimezone(tz: string | null | undefined): void {
    const trimmed = tz?.trim();
    this.timezone.set(trimmed && isValidTimeZone(trimmed) ? trimmed : null);
  }
}

/** Whether `Intl` accepts `zone` as a time zone identifier (NGB-F26). */
export function isValidTimeZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}
