import { expect, test } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mockApi } from '../helpers/mock-api';

/**
 * AA14-T6: Core Web Vitals on three key screens, the record list, a record
 * form and a dashboard, over a throttled "Fast 3G" link and a 4x slower CPU,
 * against the API mock (the browser's own cost: the server is not timed).
 *
 * LCP is the last `largest-contentful-paint` entry before the first input;
 * INP is the longest `event` entry (interaction to next paint) after one
 * keyboard and one pointer interaction on the screen. A screen over 2.5 s
 * LCP or 200 ms INP fails; every number goes to `perf/results.json`, which
 * the release gate keeps.
 */

const LCP_LIMIT_MS = 2500;
const INP_LIMIT_MS = 200;

const SCREENS: { name: string; path: string }[] = [
  { name: 'record list', path: '/xrm/entity/account/list' },
  { name: 'record form', path: '/xrm/entity/account/form' },
  { name: 'dashboard', path: '/xrm/dashboard' },
];

const RESULTS = join(__dirname, 'results.json');

interface Vitals { lcp: number; inp: number }

function record(name: string, vitals: Vitals): void {
  mkdirSync(dirname(RESULTS), { recursive: true });
  let all: Record<string, Vitals> = {};
  try {
    all = JSON.parse(readFileSync(RESULTS, 'utf8')) as Record<string, Vitals>;
  } catch {
    all = {};
  }
  all[name] = vitals;
  writeFileSync(RESULTS, `${JSON.stringify(all, null, 2)}\n`);
}

for (const screen of SCREENS) {
  test(`${screen.name} meets the Core Web Vitals limits`, async ({ page }) => {
    await mockApi(page);
    const cdp = await page.context().newCDPSession(page);
    // Chrome DevTools' "Fast 3G": 150 ms latency, 1.6 Mbps down, 750 Kbps up.
    await cdp.send('Network.enable');
    await cdp.send('Network.emulateNetworkConditions', {
      offline: false,
      latency: 150,
      downloadThroughput: (1.6 * 1024 * 1024) / 8,
      uploadThroughput: (750 * 1024) / 8,
    });
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
    await page.addInitScript(() => {
      const w = window as unknown as { __lcp: number; __inp: number };
      w.__lcp = 0;
      w.__inp = 0;
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) w.__lcp = entry.startTime;
      }).observe({ type: 'largest-contentful-paint', buffered: true });
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) w.__inp = Math.max(w.__inp, entry.duration);
      }).observe({ type: 'event', buffered: true, durationThreshold: 16 } as PerformanceObserverInit);
    });

    await page.goto(screen.path);
    await page.waitForLoadState('networkidle');
    const lcp = await page.evaluate(() => (window as unknown as { __lcp: number }).__lcp);
    // Two interactions: a key press and a click on the page's main area.
    await page.keyboard.press('Tab');
    await page.mouse.click(10, 200);
    await page.waitForTimeout(500);
    const inp = await page.evaluate(() => (window as unknown as { __inp: number }).__inp);

    record(screen.name, { lcp: Math.round(lcp), inp: Math.round(inp) });
    expect(lcp, `${screen.name} LCP`).toBeLessThanOrEqual(LCP_LIMIT_MS);
    expect(inp, `${screen.name} INP`).toBeLessThanOrEqual(INP_LIMIT_MS);
  });
}
