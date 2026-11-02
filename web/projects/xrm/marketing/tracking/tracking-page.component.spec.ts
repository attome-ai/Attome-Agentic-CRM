import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { TrackingPageComponent, barShares, embedSnippet } from './tracking-page.component';
import { TrackedSite, TrackingReport, TrackingService, toSite } from './tracking.service';

const SITES: TrackedSite[] = [
  { id: 's0', name: 'Old site', site_key: 'old', domains: null, enabled: false },
  { id: 's1', name: 'Main site', site_key: 'main', domains: 'acme.sa', enabled: true },
];

const REPORT: TrackingReport = {
  site: 'main',
  days: 30,
  visits: 120,
  identified: 18,
  sources: [{ label: 'newsletter', visits: 60 }, { label: 'google.com', visits: 30 }],
  landing_pages: [{ label: 'https://acme.sa/pricing', visits: 40 }],
  campaigns: [],
};

describe('TrackingPageComponent (E14-T12)', () => {
  const current = signal<'en' | 'ar'>('en');
  const tracking = {
    sites: vi.fn(() => of(SITES)),
    report: vi.fn(() => of(REPORT)),
    live: vi.fn(() => of([{
      session_id: 'v1', visitor_id: 'u1', contact_ref: 'c1', started_at: '2026-11-02T10:00:00Z',
      last_seen_at: '2026-11-02T10:04:00Z', page_count: 3, current_url: 'https://acme.sa/pricing',
    }])),
  };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [TrackingPageComponent],
      providers: [
        provideRouter([]),
        { provide: TrackingService, useValue: tracking },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'https://crm.acme.sa/' } },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => k,
            isRtl: () => current() === 'ar',
            intlLocale: () => (current() === 'ar' ? 'ar-SA' : 'en-US'),
            errorText: () => 'error',
          },
        },
      ],
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  function render() {
    const fixture = TestBed.createComponent(TrackingPageComponent);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('renders in English with the first enabled site', () => {
    const { el } = render();
    expect(el.querySelector('section')?.getAttribute('dir')).toBe('ltr');
    expect(tracking.report).toHaveBeenCalledWith('main', 30);
    expect(tracking.live).toHaveBeenCalledWith('main');
    expect(el.querySelector('[data-testid="tp-snippet"]')?.textContent).toContain(
      'https://crm.acme.sa/api/v1/track/script.js?site=main');
    expect(el.querySelector('[data-testid="tp-totals"]')?.textContent).toContain('120');
    expect(el.querySelectorAll('[data-testid="tp-sources"] li').length).toBe(2);
    expect(el.querySelector('[data-testid="tp-campaigns"]')?.textContent).toContain('marketingTracking.noData');
    expect(el.querySelector('[data-testid="tp-live"]')?.textContent).toContain('marketingTracking.known');
  });

  it('renders right to left in Arabic, code left to right', () => {
    current.set('ar');
    const { el } = render();
    expect(el.querySelector('section')?.getAttribute('dir')).toBe('rtl');
    expect(el.querySelector('[data-testid="tp-snippet"]')?.getAttribute('dir')).toBe('ltr');
  });

  it('picks another site', () => {
    const { fixture, el } = render();
    const select = el.querySelector('[data-testid="tp-site"]') as HTMLSelectElement;
    select.value = 'old';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(tracking.report).toHaveBeenLastCalledWith('old', 30);
    expect(el.querySelector('[data-testid="tp-snippet"]')?.textContent).toContain('site=old');
  });

  it('changes the period', () => {
    const { el } = render();
    const select = el.querySelector('[data-testid="tp-days"]') as HTMLSelectElement;
    select.value = '7';
    select.dispatchEvent(new Event('change'));
    expect(tracking.report).toHaveBeenLastCalledWith('main', 7);
  });

  it('copies the embed code', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const { fixture, el } = render();
    (el.querySelector('[data-testid="tp-copy"]') as HTMLButtonElement).click();
    await Promise.resolve();
    fixture.detectChanges();
    expect(writeText).toHaveBeenCalledWith(embedSnippet('https://crm.acme.sa', 'main'));
    expect(el.querySelector('[data-testid="tp-copy"]')?.textContent).toContain('marketingTracking.copied');
  });

  it('refreshes the live visitors', () => {
    const { el } = render();
    (el.querySelector('[data-testid="tp-refresh"]') as HTMLButtonElement).click();
    expect(tracking.live).toHaveBeenCalledTimes(2);
  });

  it('says so when there is no site', () => {
    tracking.sites.mockReturnValueOnce(of([]));
    const { el } = render();
    expect(el.querySelector('[data-testid="tp-no-sites"]')).not.toBeNull();
    expect(tracking.report).not.toHaveBeenCalled();
  });
});

describe('tracking helpers (E14-T12)', () => {
  it('builds the snippet with an escaped key and no doubled slash', () => {
    expect(embedSnippet('https://crm.acme.sa/', 'a b')).toBe(
      '<script async src="https://crm.acme.sa/api/v1/track/script.js?site=a%20b"></script>');
  });

  it('scales bars to the largest row', () => {
    expect(barShares([{ label: 'a', visits: 50 }, { label: 'b', visits: 25 }])).toEqual([100, 50]);
    expect(barShares([])).toEqual([]);
  });

  it('reads a site record and drops one without a key', () => {
    expect(toSite({ id: 's1', site_key: ' main ', enabled: true, name: '' })).toEqual({
      id: 's1', name: null, site_key: 'main', domains: null, enabled: true,
    });
    expect(toSite({ id: 's2', site_key: '' })).toBeNull();
  });
});
