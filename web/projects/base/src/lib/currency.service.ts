import { HttpClient } from '@angular/common/http';
import { inject, Injectable, PLATFORM_ID, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { ATTOME_CONFIG } from './config';

export interface CurrencyRate {
  /** ISO 4217 code, e.g. "USD". */
  code: string;
  /** Display symbol/icon, e.g. "$", "€", "ج.م". */
  icon: string;
  /** Units of this currency per 1 USD (the system base). USD's own rate is always 1. */
  rate: number;
}

// D-490 — the platform stores every `currency` field as a plain NUMERIC
// amount in USD (the system base, always 1:1); there is no backend
// exchange-rate table or conversion service. This fallback list is what a
// viewer sees before `public/currency-rates.json` has ever loaded (first
// paint, or a fetch failure with nothing cached yet) — kept intentionally
// small and hand-maintained, same posture as the rate table itself.
const FALLBACK_RATES: CurrencyRate[] = [
  { code: 'USD', icon: '$', rate: 1 },
  { code: 'EUR', icon: '€', rate: 0.92 },
  { code: 'GBP', icon: '£', rate: 0.79 },
];

/**
 * Display-only currency conversion for `currency` fields (D-490). Every
 * persisted value is USD; this service converts USD -> a viewer's preferred
 * currency (and back, for editing) against a static rate table, entirely in
 * the browser — there is no backend exchange-rate endpoint.
 *
 * **Rate table:** fetched once from `public/currency-rates.json` (a plain
 * static asset, hand-updated occasionally — not a live FX feed) and cached in
 * `localStorage` for [[RATES_TTL_MS]] (one week), mirroring `ThemeService`'s
 * per-portal `localStorage` pattern. A cache hit within the TTL never touches
 * the network. A fetch failure falls back to whatever is cached, then to
 * [[FALLBACK_RATES]] — never blocks rendering. NGB-4.2: every row is validated
 * before it is used, so one malformed entry cannot poison the table.
 *
 * **Preference:** the viewer's chosen display currency lives in `localStorage`
 * only (per browser, not synced across devices or to the user's account —
 * D-490 scoped this deliberately narrow; `user_account` carries no
 * currency column).
 *
 * **Reactivity (NGB-4.2):** signals are the state (`rates()`,
 * `preferredCurrency()`); the deprecated Observable wrappers were deleted
 * (D-790).
 */
@Injectable({ providedIn: 'root' })
export class CurrencyService {
  // Both optional: `FieldInputComponent`/`EntityListComponent` inject this
  // service unconditionally for every field/column regardless of type, so a
  // narrow component test that provides neither `HttpClient` nor
  // `ATTOME_CONFIG` (most don't — this service is a new, incidental
  // dependency for them, not something their fixtures were built around)
  // must not fail to construct it. A missing `http` just skips the rate
  // fetch (falls back to FALLBACK_RATES / whatever is cached); a missing
  // `config` just skips the portal-scoped localStorage namespace.
  private readonly http = inject(HttpClient, { optional: true });
  private readonly platformId = inject(PLATFORM_ID);
  private readonly config = inject(ATTOME_CONFIG, { optional: true });

  private readonly RATES_TTL_MS = 7 * 24 * 60 * 60 * 1000;

  private readonly keys = {
    preferred: `${this.config?.portalKey ?? 'attome'}-preferred-currency`,
    rates: `${this.config?.portalKey ?? 'attome'}-currency-rates`,
    fetchedAt: `${this.config?.portalKey ?? 'attome'}-currency-rates-fetched-at`,
  };

  private readonly ratesSignal = signal<CurrencyRate[]>(FALLBACK_RATES);
  private readonly preferredSignal = signal<string>('USD');

  readonly rates = this.ratesSignal.asReadonly();
  readonly preferredCurrency = this.preferredSignal.asReadonly();

  constructor() {
    if (!isPlatformBrowser(this.platformId)) return;
    this.loadPreferred();
    this.loadRates();
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  getRates(): CurrencyRate[] { return this.ratesSignal(); }
  getPreferredCurrency(): string { return this.preferredSignal(); }

  getRate(code: string): CurrencyRate {
    const rates = this.ratesSignal();
    return rates.find(r => r.code === code)
      ?? rates.find(r => r.code === 'USD')
      ?? FALLBACK_RATES[0];
  }

  setPreferredCurrency(code: string): void {
    this.preferredSignal.set(code);
    this.save(this.keys.preferred, code);
  }

  /** USD (the stored, system-base value) -> the display currency (default: the viewer's preference). */
  fromBase(amountUsd: number, code = this.getPreferredCurrency()): number {
    return amountUsd * this.getRate(code).rate;
  }

  /** The display currency -> USD, for writing a value back to the field. */
  toBase(amount: number, code = this.getPreferredCurrency()): number {
    const rate = this.getRate(code).rate || 1;
    return amount / rate;
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private loadPreferred(): void {
    const stored = this.read(this.keys.preferred);
    if (stored) this.preferredSignal.set(stored);
  }

  private loadRates(): void {
    const cached = this.read(this.keys.rates);
    const fetchedAt = Number(this.read(this.keys.fetchedAt) ?? 0);
    const isFresh = !!cached && Date.now() - fetchedAt < this.RATES_TTL_MS;

    if (isFresh) {
      const parsed = this.parseRates(cached);
      if (parsed) { this.ratesSignal.set(parsed); return; }
    }

    if (!this.http) return;
    this.http.get<unknown>('currency-rates.json').subscribe({
      next: (rates) => {
        const valid = this.sanitiseRates(rates);
        if (!valid) return;
        this.ratesSignal.set(valid);
        this.save(this.keys.rates, JSON.stringify(valid));
        this.save(this.keys.fetchedAt, String(Date.now()));
      },
      error: () => {
        // Network/asset failure: keep serving whatever was cached (even if
        // stale past the TTL) rather than falling all the way back to
        // FALLBACK_RATES's tiny list.
        const stale = this.parseRates(cached);
        if (stale) this.ratesSignal.set(stale);
      },
    });
  }

  private parseRates(raw: string | null): CurrencyRate[] | null {
    if (!raw) return null;
    try {
      return this.sanitiseRates(JSON.parse(raw));
    } catch { return null; }
  }

  /**
   * NGB-4.2 — the rate table is a static, hand-edited asset, so a typo is the
   * expected failure mode, not an attack. A row survives only if it has a
   * three-letter `code`, a `string` icon and a finite, strictly positive
   * `rate`; anything else is dropped. Returns `null` when nothing usable is
   * left, which the callers treat as "no table" rather than "empty table".
   */
  private sanitiseRates(raw: unknown): CurrencyRate[] | null {
    if (!Array.isArray(raw)) return null;
    const valid: CurrencyRate[] = [];
    const seen = new Set<string>();
    for (const row of raw) {
      if (typeof row !== 'object' || row === null) continue;
      const candidate = row as Partial<CurrencyRate>;
      const code = typeof candidate.code === 'string' ? candidate.code.trim() : '';
      const rate = candidate.rate;
      if (!/^[A-Za-z]{3}$/.test(code)) continue;
      if (typeof rate !== 'number' || !Number.isFinite(rate) || rate <= 0) continue;
      if (seen.has(code)) continue;
      seen.add(code);
      valid.push({
        code,
        icon: typeof candidate.icon === 'string' ? candidate.icon : code,
        rate,
      });
    }
    if (valid.length === 0) return null;
    // USD is the system base; a table that omits it would make `getRate` fall
    // back to this table's first row for every unknown code.
    if (!seen.has('USD')) valid.unshift({ code: 'USD', icon: '$', rate: 1 });
    return valid;
  }

  private read(key: string): string | null {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  private save(key: string, value: string): void {
    try { localStorage.setItem(key, value); } catch { /* SSR / private browsing */ }
  }
}
