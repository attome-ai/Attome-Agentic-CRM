import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApiService } from './api.service';
import { BrandService } from './brand.service';
import { ATTOME_CONFIG } from './config';
import { ThemeService } from './theme.service';

describe('BrandService (B13-T8)', () => {
  function create(get: ReturnType<typeof vi.fn>) {
    const setBrand = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: ThemeService, useValue: { setBrand } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://api.test' } },
      ],
    });
    return { brand: TestBed.inject(BrandService), setBrand };
  }

  it('calls the public route before sign-in and applies its colours', () => {
    const get = vi.fn().mockReturnValue(of({ variables: { '--color-primary': '#123456' }, hide_vendor_name: false }));
    const { brand, setBrand } = create(get);
    brand.loadPublic();
    expect(get).toHaveBeenCalledWith('/api/v1/branding/public');
    expect(setBrand).toHaveBeenCalledWith({ '--color-primary': '#123456' });
  });

  it('points the favicon at the published one', () => {
    const get = vi.fn().mockReturnValue(of({
      variables: {}, hide_vendor_name: false, favicon_url: '/api/v1/branding/asset?kind=favicon&v=abc', app_name: 'Acme CRM',
    }));
    const { brand } = create(get);
    brand.loadPublic();
    const link = document.head.querySelector<HTMLLinkElement>('link[rel="icon"]');
    expect(link?.href).toBe('http://api.test/api/v1/branding/asset?kind=favicon&v=abc');
    expect(brand.current()?.favicon_url).toContain('kind=favicon');
    expect(document.title).toBe('Acme CRM');
  });

  it('asks for the caller\'s brand with the app, and ignores a failure', () => {
    const get = vi.fn().mockReturnValue(throwError(() => new Error('offline')));
    const { brand, setBrand } = create(get);
    brand.loadMine('sales hub');
    expect(get).toHaveBeenCalledWith('/api/v1/branding/me?app=sales%20hub');
    expect(setBrand).not.toHaveBeenCalled();
  });
});
