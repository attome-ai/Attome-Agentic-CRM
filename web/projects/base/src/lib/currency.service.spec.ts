import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CurrencyService, amountStep, formatAmount, sanitiseCurrencies } from './currency.service';
import { ATTOME_CONFIG } from './config';

/** A19-T5: currencies come from the server; amounts are never converted here. */
describe('CurrencyService', () => {
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('loads the currencies and the base currency from the server', () => {
    const service = TestBed.inject(CurrencyService);
    httpMock.expectOne('http://localhost:7865/api/v1/currencies').flush({
      items: [
        { code: 'KWD', decimals: 3, symbol: 'د.ك', name: 'Kuwaiti Dinar', is_base: false },
        { code: 'SAR', decimals: 2, symbol: '﷼', name: 'Saudi Riyal', is_base: true },
      ],
      total: 2, page: 1, page_size: 2,
    });
    expect(service.baseCurrency()).toBe('SAR');
    expect(service.decimals('KWD')).toBe(3);
    expect(service.info('kwd').symbol).toBe('د.ك');
    expect(service.info('XYZ')).toEqual({ code: 'XYZ', decimals: 2, symbol: 'XYZ', name: 'XYZ' });
    expect(service.info(null).code).toBe('SAR');
  });

  it('keeps the built-in list when the server cannot be read', () => {
    const service = TestBed.inject(CurrencyService);
    httpMock.expectOne('http://localhost:7865/api/v1/currencies')
      .flush('no', { status: 500, statusText: 'Server Error' });
    expect(service.decimals('BHD')).toBe(3);
    expect(service.baseCurrency()).toBe('USD');
  });

  it('shows an amount with its currency decimals', () => {
    expect(formatAmount(1250.5, 3)).toContain('250.500');
    expect(formatAmount(1250, 0)).not.toContain('.');
    expect(amountStep(3)).toBe('0.001');
    expect(amountStep(0)).toBe('1');
  });

  it('drops malformed currency rows', () => {
    expect(sanitiseCurrencies('x')).toBeNull();
    expect(sanitiseCurrencies([{ code: 'US', decimals: 2 }, { code: 'EUR', decimals: 9 }])).toBeNull();
    expect(sanitiseCurrencies([{ code: 'eur', decimals: 2 }])).toEqual([
      { code: 'EUR', decimals: 2, symbol: 'EUR', name: 'EUR', is_base: false },
    ]);
  });
});
