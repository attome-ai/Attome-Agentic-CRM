import { HttpClient } from '@angular/common/http';
import { inject, Injectable, PLATFORM_ID, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { ATTOME_CONFIG } from './config';

/** One currency a money amount may carry (`GET /api/v1/currencies`). */
export interface CurrencyInfo {
  /** ISO 4217 code, e.g. "SAR". */
  code: string;
  /** The decimals an amount in it is rounded to (KWD 3, JPY 0). */
  decimals: number;
  symbol: string;
  name: string;
  /** The deployment's base currency. */
  is_base?: boolean;
}

/** Shown before the list has loaded, or when it cannot be read. */
const FALLBACK: CurrencyInfo[] = [
  { code: 'USD', decimals: 2, symbol: '$', name: 'US Dollar', is_base: true },
  { code: 'SAR', decimals: 2, symbol: '﷼', name: 'Saudi Riyal' },
  { code: 'AED', decimals: 2, symbol: 'د.إ', name: 'UAE Dirham' },
  { code: 'KWD', decimals: 3, symbol: 'د.ك', name: 'Kuwaiti Dinar' },
  { code: 'BHD', decimals: 3, symbol: '.د.ب', name: 'Bahraini Dinar' },
  { code: 'EUR', decimals: 2, symbol: '€', name: 'Euro' },
];

/**
 * A19-T5: the currencies a money field may carry. Since A19-T1 an amount is
 * stored in its own currency (the companion field `<name>_currency`) and
 * rounded to that currency's decimals; nothing is converted in the browser.
 * A field with the `fx` option also keeps its amount in the base currency
 * (`<name>_base`), which the money control shows as a hint.
 *
 * The list comes from `GET /api/v1/currencies` once per page load; until
 * it arrives (or when it cannot be read) a short built-in list is used.
 * `HttpClient` and `ATTOME_CONFIG` are optional so a component test that
 * provides neither still constructs it.
 */
@Injectable({ providedIn: 'root' })
export class CurrencyService {
  private readonly http = inject(HttpClient, { optional: true });
  private readonly platformId = inject(PLATFORM_ID);
  private readonly config = inject(ATTOME_CONFIG, { optional: true });

  private readonly listSignal = signal<CurrencyInfo[]>(FALLBACK);
  private readonly baseSignal = signal<string>('USD');

  /** Every currency, by code. */
  readonly currencies = this.listSignal.asReadonly();
  /** The deployment's base currency. */
  readonly baseCurrency = this.baseSignal.asReadonly();

  constructor() {
    if (!isPlatformBrowser(this.platformId) || !this.http || !this.config) return;
    this.http
      .get<{ items?: unknown }>(`${this.config.apiUrl}/api/v1/currencies`, { withCredentials: true })
      .subscribe({
        next: page => {
          const list = sanitiseCurrencies(page?.items);
          if (!list) return;
          this.listSignal.set(list);
          const base = list.find(c => c.is_base);
          if (base) this.baseSignal.set(base.code);
        },
        error: () => { /* keep the built-in list */ },
      });
  }

  /** The currency `code` names; an unknown code shows as itself with 2 decimals. */
  info(code: string | null | undefined): CurrencyInfo {
    const wanted = (code ?? this.baseSignal()).toUpperCase();
    return this.listSignal().find(c => c.code === wanted)
      ?? { code: wanted, decimals: 2, symbol: wanted, name: wanted };
  }

  decimals(code: string | null | undefined): number {
    return this.info(code).decimals;
  }

  /** `amount` with its currency's decimals and code, e.g. "1,250.500 KWD". */
  format(amount: number, code: string | null | undefined): string {
    const info = this.info(code);
    return `${formatAmount(amount, info.decimals)} ${info.code}`;
  }
}

/** `amount` rounded and shown with exactly `decimals` decimals. Pure. */
export function formatAmount(amount: number, decimals: number): string {
  return amount.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

/** The input step for an amount with `decimals` decimals ("0.001" for 3). Pure. */
export function amountStep(decimals: number): string {
  return decimals <= 0 ? '1' : (1 / 10 ** decimals).toFixed(decimals);
}

/**
 * The rows of a currency list that are usable: a three-letter code and a
 * decimals count from 0 to 4; `null` when none is. Pure.
 */
export function sanitiseCurrencies(raw: unknown): CurrencyInfo[] | null {
  if (!Array.isArray(raw)) return null;
  const out: CurrencyInfo[] = [];
  for (const row of raw) {
    if (typeof row !== 'object' || row === null) continue;
    const c = row as Partial<CurrencyInfo>;
    const code = typeof c.code === 'string' ? c.code.trim().toUpperCase() : '';
    if (!/^[A-Z]{3}$/.test(code)) continue;
    if (typeof c.decimals !== 'number' || !Number.isInteger(c.decimals) || c.decimals < 0 || c.decimals > 4) continue;
    out.push({
      code,
      decimals: c.decimals,
      symbol: typeof c.symbol === 'string' && c.symbol ? c.symbol : code,
      name: typeof c.name === 'string' && c.name ? c.name : code,
      is_base: c.is_base === true,
    });
  }
  return out.length ? out : null;
}
