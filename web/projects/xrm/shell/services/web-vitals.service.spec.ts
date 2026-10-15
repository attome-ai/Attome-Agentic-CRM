import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { WebVitals, vitalArea } from './web-vitals.service';

describe('WebVitals (AA12-T1)', () => {
  afterEach(() => vi.unstubAllGlobals());

  function setUp() {
    const fetch = vi.fn(() => Promise.resolve(new Response(null, { status: 204 })));
    vi.stubGlobal('fetch', fetch);
    TestBed.configureTestingModule({
      providers: [{ provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://api' } }],
    });
    return { vitals: TestBed.inject(WebVitals), fetch };
  }

  function sent(fetch: { mock: { calls: unknown[][] } }): unknown[] {
    return fetch.mock.calls.map(call => {
      const [url, init] = call as unknown as [string, RequestInit];
      expect(url).toBe('http://api/api/v1/telemetry/web-vitals');
      expect(init.keepalive).toBe(true);
      return JSON.parse(String(init.body));
    });
  }

  it('groups a screen by its module under /xrm/, else its first segment', () => {
    expect(vitalArea('/xrm/core/account/list')).toBe('core');
    expect(vitalArea('/xrm')).toBe('xrm');
    expect(vitalArea('/pricing')).toBe('pricing');
    expect(vitalArea('/')).toBe('home');
    expect(vitalArea('/x_y')).toBe('other');
  });

  it('sends LCP once and the slowest interaction when the page is hidden', () => {
    const { vitals, fetch } = setUp();
    vitals.recordLcp(1834.4);
    vitals.recordInteractions([
      { duration: 120, interactionId: 7 },
      { duration: 480, interactionId: 8 },
      { duration: 900 },
    ]);
    vitals.flush('/xrm/core/account/list');
    expect(sent(fetch)).toEqual([
      { name: 'LCP', value: 1834, area: 'core' },
      { name: 'INP', value: 480, area: 'core' },
    ]);

    fetch.mockClear();
    vitals.flush('/xrm/core/account/list');
    expect(fetch).not.toHaveBeenCalled();

    vitals.recordInteractions([{ duration: 200, interactionId: 9 }]);
    vitals.flush('/xrm/sales/deal/list');
    expect(sent(fetch)).toEqual([{ name: 'INP', value: 200, area: 'sales' }]);
  });

  it('sends nothing when nothing was measured', () => {
    const { vitals, fetch } = setUp();
    vitals.flush('/xrm');
    expect(fetch).not.toHaveBeenCalled();
  });
});
