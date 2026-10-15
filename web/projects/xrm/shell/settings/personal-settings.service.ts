import { DOCUMENT } from '@angular/common';
import { Injectable, computed, inject, signal } from '@angular/core';
import { ApiService, LangService, ThemeMode, ThemeService, UserPreferencesService } from '@attome/base';
import { Observable, map, tap } from 'rxjs';

/** One setting as `/api/v1/settings/me` returns it. */
export interface PersonalSetting {
  key: string;
  value: unknown;
  /** `user`, `organization`, `deployment` or `default`. */
  source: string;
  schema?: { enum?: string[] };
}

/** The personal settings the settings screen offers, in display order. */
export const PERSONAL_KEYS = [
  'core.locale', 'core.time_zone', 'core.calendar', 'core.digits', 'core.date_format',
  'core.start_page', 'core.theme', 'core.text_size', 'core.reduced_motion', 'core.simple_mode',
] as const;
export type PersonalKey = typeof PERSONAL_KEYS[number];

/** The root classes the text-size and motion settings turn on. */
export const TEXT_LARGE_CLASS = 'attome-text-large';
export const REDUCED_MOTION_CLASS = 'attome-reduced-motion';
/** AK6-T2: hides every element marked `data-advanced`. */
export const SIMPLE_MODE_CLASS = 'attome-simple-mode';

/**
 * B11-T2: the signed-in person's settings (`/api/v1/settings/me`), applied
 * to the running app at once: language, theme, time zone, calendar and
 * digits (through `UserPreferencesService`, which the date pipe reads), text
 * size and motion. A value nobody chose (`source: default`) is not applied,
 * so the language's and device's own defaults stand.
 */
@Injectable({ providedIn: 'root' })
export class PersonalSettingsService {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly theme = inject(ThemeService);
  private readonly prefs = inject(UserPreferencesService);
  private readonly document = inject(DOCUMENT);

  readonly settings = signal<PersonalSetting[]>([]);
  readonly byKey = computed(() => new Map(this.settings().map(s => [s.key, s])));

  load(): Observable<PersonalSetting[]> {
    return this.api.get<{ items: PersonalSetting[] }>('/api/v1/settings/me').pipe(
      map(doc => doc.items),
      tap(items => {
        this.settings.set(items);
        this.apply();
      }),
    );
  }

  /** Loads and applies, ignoring a failure (the defaults stay). */
  start(): void {
    this.load().subscribe({ error: () => undefined });
  }

  /** Whether someone (the person, their organization or the deployment) chose `key`. */
  isSet(key: string): boolean {
    const setting = this.byKey().get(key);
    return !!setting && setting.source !== 'default';
  }

  value(key: string): unknown {
    return this.byKey().get(key)?.value;
  }

  /** Saves the person's own value for `key` and applies it at once. */
  save(key: PersonalKey, value: unknown): Observable<PersonalSetting> {
    return this.api.put<PersonalSetting>(`/api/v1/settings/me/${key}`, { value }).pipe(
      tap(saved => {
        this.settings.update(all => {
          const rest = all.filter(s => s.key !== key);
          return [...rest, { ...saved, source: 'user' }];
        });
        this.apply();
      }),
    );
  }

  /** The page to open after signing in, when one was chosen. */
  startPage(): string | null {
    const page = this.value('core.start_page');
    return this.isSet('core.start_page') && typeof page === 'string' && page.startsWith('/') ? page : null;
  }

  private apply(): void {
    if (this.isSet('core.locale')) {
      const locale = String(this.value('core.locale') ?? '');
      void this.lang.set(locale.startsWith('ar') ? 'ar' : 'en');
    }
    if (this.isSet('core.theme')) {
      const mode = this.value('core.theme');
      if (mode === 'light' || mode === 'dark' || mode === 'auto') this.theme.setMode(mode as ThemeMode);
    }
    if (this.isSet('core.time_zone')) this.prefs.setTimezone(String(this.value('core.time_zone')));
    this.prefs.setCalendar(this.isSet('core.calendar') ? String(this.value('core.calendar')) : null);
    this.prefs.setDigits(this.isSet('core.digits') ? String(this.value('core.digits')) : null);
    const root = this.document.documentElement;
    root.classList.toggle(TEXT_LARGE_CLASS, this.value('core.text_size') === 'large');
    root.classList.toggle(REDUCED_MOTION_CLASS, this.value('core.reduced_motion') === true);
    root.classList.toggle(SIMPLE_MODE_CLASS, this.value('core.simple_mode') === true);
  }
}
