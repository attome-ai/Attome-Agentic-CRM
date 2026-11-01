import { expect, test } from '@playwright/test';
import { mockApi } from '../helpers/mock-api';

/** B19-T3: no sideways scrolling at a phone, a tablet and a desktop width. */
const SCREENS = ['/xrm/dashboard', '/xrm/settings', '/xrm/login', '/register', '/forgot-password'];
const WIDTHS = [390, 820, 1440];

for (const width of WIDTHS) {
  for (const path of SCREENS) {
    test(`${path} fits ${width} pixels`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      await mockApi(page);
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      const overflowing = await page.evaluate(() =>
        [document.documentElement, ...document.querySelectorAll('.xrm-main, .xrm-nav')]
          .filter(e => e.scrollWidth > e.clientWidth + 1)
          .map(e => `${e.tagName}.${e.className}: ${e.scrollWidth} > ${e.clientWidth}`));
      expect(overflowing).toEqual([]);
    });
  }
}

test('the sidebar leaves a phone its width, and opens over the page', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await mockApi(page);
  await page.goto('/xrm/dashboard');
  const main = page.locator('.xrm-main');
  await expect(main).toBeVisible();
  expect((await main.boundingBox())!.width).toBeGreaterThan(300);
  await page.locator('.expand-btn').click();
  await expect(page.locator('.sidebar')).not.toHaveClass(/collapsed/);
  expect((await main.boundingBox())!.width).toBeGreaterThan(300);
});

test('a page prints', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'only Chromium writes a PDF');
  await mockApi(page);
  await page.goto('/xrm/dashboard');
  await page.waitForLoadState('networkidle');
  await page.emulateMedia({ media: 'print' });
  const pdf = await page.pdf({ format: 'A4' });
  expect(pdf.subarray(0, 4).toString()).toBe('%PDF');
});
