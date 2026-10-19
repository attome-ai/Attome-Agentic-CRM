import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

/** `attome_api::settings_admin::RegionPreset`. */
export interface RegionPreset {
  code: string;
  name: string;
  name_ar?: string | null;
  currency_code?: string | null;
  time_zone: string;
  /** `gregorian`, `hijri` or `both`. */
  default_date_calendar: string;
  week_start?: string | null;
}

/** `attome_api::settings_admin::RegionSetupView`. */
export interface RegionSetupView {
  country: string | null;
  pack_available: boolean;
  countries: RegionPreset[];
}

export const SETUP_URL = '/api/v1/admin/setup/region';
export const LANGUAGES = ['ar', 'en'] as const;
export const CALENDARS = ['gregorian', 'hijri', 'both'] as const;

/** The country to start on: the deployment's, else Saudi Arabia, else the first. */
export function initialCountry(view: RegionSetupView): string | null {
  const codes = view.countries.map(c => c.code);
  if (view.country && codes.includes(view.country)) return view.country;
  if (codes.includes('SA')) return 'SA';
  return codes[0] ?? null;
}

/** A country's name in the page's language. */
export function countryName(preset: RegionPreset, lang: string): string {
  return lang === 'ar' && preset.name_ar ? preset.name_ar : preset.name;
}

/**
 * The first-run wizard (roadmap X12-T3): an administrator picks the
 * deployment's country, language and calendar. Saving installs the regions
 * pack (currency, VAT rates, ID formats, business week and holidays) and sets
 * the deployment's locale, time zone and calendar through
 * `POST /api/v1/admin/setup/region`. Arabic is the default language. It can
 * be run again later to change the country. Logical CSS only.
 */
@Component({
  selector: 'xrm-first-run',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  template: `
    <section class="fr">
      <h3><i class="las la-globe" aria-hidden="true"></i> {{ 'firstRun.title' | translate }}</h3>
      <p class="fr-muted">{{ 'firstRun.intro' | translate }}</p>
      @if (error(); as message) { <p class="fr-error" role="alert">{{ message }}</p> }

      @if (view(); as v) {
        @if (!v.pack_available) {
          <p class="fr-error" role="alert" data-no-pack>{{ 'firstRun.noPack' | translate }}</p>
        } @else if (done()) {
          <div class="fr-done" role="status" data-done>
            <p><i class="las la-check-circle" aria-hidden="true"></i>
              {{ 'firstRun.done' | translate: { country: chosenName() } }}</p>
            <a routerLink="/xrm">{{ 'firstRun.start' | translate }} <i class="las la-arrow-right fr-flip" aria-hidden="true"></i></a>
          </div>
        } @else {
          <form class="fr-form" (submit)="$event.preventDefault(); save()">
            <fieldset>
              <legend>{{ 'firstRun.country' | translate }}</legend>
              <div class="fr-countries" role="radiogroup">
                @for (c of v.countries; track c.code) {
                  <label class="fr-card" [class.fr-on]="country() === c.code" [attr.data-country]="c.code">
                    <input type="radio" name="country" [value]="c.code"
                           [checked]="country() === c.code" (change)="pickCountry(c)" />
                    <span class="fr-name">{{ name(c) }}</span>
                    <small class="fr-muted" dir="ltr">{{ c.currency_code }}</small>
                    <small class="fr-muted" dir="ltr">{{ c.time_zone }}</small>
                  </label>
                }
              </div>
            </fieldset>

            <fieldset>
              <legend>{{ 'firstRun.language' | translate }}</legend>
              <div class="fr-row">
                @for (l of languages; track l) {
                  <label [attr.data-language]="l">
                    <input type="radio" name="language" [value]="l"
                           [checked]="language() === l" (change)="language.set(l)" />
                    {{ 'firstRun.lang.' + l | translate }}
                  </label>
                }
              </div>
            </fieldset>

            <fieldset>
              <legend>{{ 'firstRun.calendar' | translate }}</legend>
              <div class="fr-row">
                @for (k of calendars; track k) {
                  <label [attr.data-calendar]="k">
                    <input type="radio" name="calendar" [value]="k"
                           [checked]="calendar() === k" (change)="calendar.set(k)" />
                    {{ 'firstRun.cal.' + k | translate }}
                  </label>
                }
              </div>
            </fieldset>

            @if (preset(); as p) {
              <p class="fr-muted" data-summary>
                {{ 'firstRun.summary' | translate: { currency: p.currency_code ?? '-', zone: p.time_zone } }}
              </p>
            }
            <button type="submit" [disabled]="busy() || !country()">{{ 'firstRun.save' | translate }}</button>
          </form>
        }
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .fr { display: flex; flex-direction: column; gap: 0.75rem; max-inline-size: 48rem; }
    .fr h3 { margin-block: 0; font-size: 1rem; display: flex; gap: 0.5rem; align-items: center; }
    .fr-form { display: flex; flex-direction: column; gap: 1rem; }
    .fr fieldset { border: 1px solid var(--color-border); border-radius: 0.5rem; padding-block: 0.75rem;
      padding-inline: 1rem; margin: 0; }
    .fr legend { padding-inline: 0.25rem; font-weight: 600; }
    .fr-countries { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .fr-card { display: flex; flex-direction: column; gap: 0.25rem; min-inline-size: 12rem; cursor: pointer;
      padding-block: 0.5rem; padding-inline: 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .fr-card.fr-on { border-color: var(--color-primary); }
    .fr-card input { position: absolute; opacity: 0; inline-size: 1px; block-size: 1px; }
    .fr-card:focus-within { outline: 2px solid var(--color-primary); outline-offset: 2px; }
    .fr-name { font-weight: 600; }
    .fr-row { display: flex; flex-wrap: wrap; gap: 1rem; }
    .fr-row label { display: flex; gap: 0.375rem; align-items: center; }
    .fr-done { display: flex; flex-direction: column; gap: 0.5rem; }
    .fr-flip:dir(rtl) { transform: scaleX(-1); }
    .fr-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .fr-error { color: var(--color-danger); }
  `],
})
export class FirstRunComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly languages = LANGUAGES;
  readonly calendars = CALENDARS;

  readonly view = signal<RegionSetupView | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly done = signal(false);
  readonly country = signal<string | null>(null);
  readonly language = signal<string>('ar');
  readonly calendar = signal<string>('gregorian');

  readonly preset = computed(() =>
    this.view()?.countries.find(c => c.code === this.country()) ?? null);
  readonly chosenName = computed(() => {
    const p = this.preset();
    return p ? countryName(p, this.lang.current()) : '';
  });

  ngOnInit(): void {
    this.api.get<RegionSetupView>(SETUP_URL).subscribe({
      next: view => this.show(view),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  name(preset: RegionPreset): string {
    return countryName(preset, this.lang.current());
  }

  /** Picking a country moves the calendar to that country's default. */
  pickCountry(preset: RegionPreset): void {
    this.country.set(preset.code);
    this.calendar.set(preset.default_date_calendar);
  }

  save(): void {
    const country = this.country();
    if (!country || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    const language = this.language();
    this.api.post<RegionSetupView>(SETUP_URL, { country, language, calendar: this.calendar() }).subscribe({
      next: view => {
        this.busy.set(false);
        this.view.set(view);
        this.done.set(true);
        void this.lang.set(language);
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  private show(view: RegionSetupView): void {
    this.view.set(view);
    const code = initialCountry(view);
    const preset = view.countries.find(c => c.code === code);
    if (preset) this.pickCountry(preset);
  }
}
