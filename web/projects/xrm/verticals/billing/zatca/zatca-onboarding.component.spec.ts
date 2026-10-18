import { computed, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EinvoiceDevice, ZatcaOnboardingComponent, canOnboard } from './zatca-onboarding.component';

const DEVICES: EinvoiceDevice[] = [
  {
    id: 'd1', name: 'EGS-1', environment: 'production', status: 'active', egs_serial: '1-Attome|2-v2|3-x',
    invoice_types: '1100', last_icv: 42, has_production_csid: true, last_error: null,
  },
  {
    id: 'd2', name: 'EGS-2', environment: 'simulation', status: 'failed', egs_serial: '1-Attome|2-v2|3-y',
    invoice_types: '0100', last_icv: 0, has_production_csid: false, last_error: 'compliance CSID: Invalid-OTP',
  },
];

describe('ZatcaOnboardingComponent (AG2-T4)', () => {
  function create(lang: 'en' | 'ar' = 'en') {
    const get = vi.fn((_: string) => of({ items: DEVICES, total: 2, page: 1, page_size: 2 }));
    const post = vi.fn((_: string, __: unknown) => of(DEVICES[0]));
    const current = signal(lang);
    TestBed.configureTestingModule({
      imports: [ZatcaOnboardingComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current, isRtl: computed(() => current() === 'ar') },
        },
      ],
    });
    const fixture = TestBed.createComponent(ZatcaOnboardingComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists devices with their state and offers onboarding only where it can start', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/einvoice/devices');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('li[data-device="d1"] .zob-badge')?.getAttribute('data-status')).toBe('active');
    expect(el.querySelector('li[data-device="d1"] form')).toBeNull();
    expect(el.querySelector('li[data-device="d2"] form')).not.toBeNull();
    expect(el.textContent).toContain('Invalid-OTP');
    expect(canOnboard(DEVICES[1])).toBe(true);
    expect(canOnboard(DEVICES[0])).toBe(false);
  });

  it('sends the OTP to onboard a device', () => {
    const { fixture, post } = create();
    const input = (fixture.nativeElement as HTMLElement).querySelector('li[data-device="d2"] input') as HTMLInputElement;
    input.value = '12 3345';
    input.dispatchEvent(new Event('input'));
    fixture.componentInstance.onboard(DEVICES[1]);
    expect(post).toHaveBeenCalledWith('/api/v1/einvoice/devices/d2/onboard', { otp: '123345' });
  });

  it('creates a device from the form', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.draft.set({ name: 'EGS-3', environment: 'sandbox', organization_unit: 'Riyadh', location: 'RRRD2929', industry: 'Software', invoice_types: '1100' });
    c.create();
    expect(post).toHaveBeenCalledWith('/api/v1/einvoice/devices', expect.objectContaining({ name: 'EGS-3', environment: 'sandbox' }));
  });

  it('renders right to left in Arabic', () => {
    const { fixture } = create('ar');
    expect((fixture.nativeElement as HTMLElement).querySelector('section')?.getAttribute('dir')).toBe('rtl');
  });
});
