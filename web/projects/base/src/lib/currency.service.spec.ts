import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CurrencyService } from './currency.service';
import { ATTOME_CONFIG } from './config';

/**
 * NGB-4.2. The rate table is a hand-edited static asset (D-490), so the two
 * things that matter are that a cache hit inside the TTL never hits the
 * network and that a malformed row never reaches the UI.
 */
describe('CurrencyService', () => {
  let service: CurrencyService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    localStorage.clear();
  });

  function create(): CurrencyService {
    service = TestBed.inject(CurrencyService);
    return service;
  }

  it('starts from the built-in fallback table and USD', () => {
    create();
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'EUR', 'GBP']);
    expect(service.preferredCurrency()).toBe('USD');
    expect(service.getRate('EUR').rate).toBeCloseTo(0.92, 5);
    httpMock.expectOne('currency-rates.json').flush([]); // empty body: keep the fallback
  });

  it('fetches, validates and caches the table', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([
      { code: 'USD', icon: '$', rate: 1 },
      { code: 'AED', icon: 'د.إ', rate: 3.6725 },
    ]);
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'AED']);
    expect(localStorage.getItem('attome-currency-rates')).toContain('AED');
    expect(localStorage.getItem('attome-currency-rates-fetched-at')).toBeTruthy();
  });

  it('serves a fresh cache without touching the network', () => {
    localStorage.setItem('attome-currency-rates', JSON.stringify([{ code: 'USD', icon: '$', rate: 1 }, { code: 'JPY', icon: '¥', rate: 150 }]));
    localStorage.setItem('attome-currency-rates-fetched-at', String(Date.now()));
    create();
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'JPY']);
    // httpMock.verify() in afterEach proves no request went out.
  });

  it('drops malformed rows and keeps the good ones', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([
      { code: 'USD', icon: '$', rate: 1 },
      { code: 'EU', icon: '€', rate: 0.9 },          // too short
      { code: 'EUR', icon: '€', rate: 0 },           // not positive
      { code: 'GBP', icon: '£', rate: Number.NaN },  // not finite
      { code: 'CHF', icon: 'Fr', rate: '0.9' },      // not a number
      null,
      'nope',
      { code: 'AED', icon: 'د.إ', rate: 3.6725 },
    ]);
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'AED']);
  });

  it('ignores a table with nothing usable left', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([{ code: 'X', rate: -1 }]);
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'EUR', 'GBP']);
  });

  it('adds USD when the fetched table omits the system base', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([{ code: 'AED', icon: 'د.إ', rate: 3.6725 }]);
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'AED']);
    expect(service.getRate('AED').rate).toBeCloseTo(3.6725, 5);
  });

  it('falls back to a stale cache when the fetch fails', () => {
    localStorage.setItem('attome-currency-rates', JSON.stringify([{ code: 'USD', icon: '$', rate: 1 }, { code: 'JPY', icon: '¥', rate: 150 }]));
    // Fetched long ago, so the TTL has expired and the service re-fetches.
    localStorage.setItem('attome-currency-rates-fetched-at', String(Date.now() - 8 * 24 * 60 * 60 * 1000));
    create();
    httpMock.expectOne('currency-rates.json').error(new ProgressEvent('error'));
    expect(service.rates().map(r => r.code)).toEqual(['USD', 'JPY']);
  });

  it('round-trips through the preferred currency within epsilon', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([
      { code: 'USD', icon: '$', rate: 1 },
      { code: 'EUR', icon: '€', rate: 0.92 },
    ]);
    service.setPreferredCurrency('EUR');
    const display = service.fromBase(123.45);
    expect(display).toBeCloseTo(123.45 * 0.92, 10);
    expect(service.toBase(display)).toBeCloseTo(123.45, 10);
    expect(localStorage.getItem('attome-preferred-currency')).toBe('EUR');
  });

  it('constructs with storage blocked and serves the fallback table (NGB-6.1e)', () => {
    // Same posture as ThemeService/LangService (NGB-F13): a blocked store is a
    // missing preference, never a thrown exception out of the constructor.
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    });
    try {
      const blocked = create();
      expect(blocked.getRates().map(r => r.code)).toEqual(['USD', 'EUR', 'GBP']);
      expect(blocked.getPreferredCurrency()).toBe('USD');
      // The fetch still runs; only the cache read/write is unavailable.
      httpMock.expectOne('currency-rates.json').flush([]);
    } finally {
      getItem.mockRestore();
    }
  });

  it('constructs without HttpClient or config (narrow component fixtures)', () => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({ providers: [] });
    const loose = TestBed.inject(CurrencyService);
    expect(loose.getRates().length).toBeGreaterThan(0);
    expect(loose.getPreferredCurrency()).toBe('USD');
  });

  it('exposes the preference as a signal', () => {
    create();
    httpMock.expectOne('currency-rates.json').flush([{ code: 'USD', icon: '$', rate: 1 }]);
    service.setPreferredCurrency('GBP');
    expect(service.preferredCurrency()).toBe('GBP');
  });
});
