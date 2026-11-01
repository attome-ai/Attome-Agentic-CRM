import { expect, test } from '@playwright/test';
import { mockApi } from '../helpers/mock-api';

/**
 * B21-T4: the built-in screens in English and in Arabic (the `chromium-en`
 * and `chromium-ar` projects), compared with their screenshot baselines. A
 * layout that moves by more than 1% of the screen's pixels fails; the
 * baselines live beside this file (`rtl-screens.spec.ts-snapshots/`), one per
 * project, and are made or renewed with `--update-snapshots` after a change
 * meant to move them. Against the API mock with empty data, so what is
 * compared is the screen's own layout and direction, never someone's records.
 */

/** The screens anyone reaches before signing in. */
const PUBLIC = ['/xrm/login', '/register', '/forgot-password'];

/** The built-in screens behind sign-in. */
const SIGNED_IN = [
  '/xrm/dashboard',
  '/xrm/settings',
  '/xrm/search',
  '/xrm/security',
  '/xrm/security/mfa',
  '/xrm/security/sessions',
  '/xrm/admin/entities',
  '/xrm/admin/queries',
  '/xrm/admin/views',
  '/xrm/admin/sidebar',
  '/xrm/admin/settings',
  '/xrm/admin/apps',
  '/xrm/admin/data-model',
  '/xrm/admin/duplicates',
  '/xrm/admin/changes',
  '/xrm/admin/governance-domains',
  '/xrm/admin/governance-inbox',
];

/** The same frame for every run: no animation, no blinking caret, a fixed size. */
async function settle(page: import('@playwright/test').Page): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.addStyleTag({
    content: '*, *::before, *::after { animation: none !important; transition: none !important; caret-color: transparent !important; }',
  });
  await page.waitForLoadState('networkidle');
}

function name(path: string): string {
  return `${path.replace(/^\//, '').replace(/[/:]/g, '-') || 'root'}.png`;
}

for (const path of [...PUBLIC, ...SIGNED_IN]) {
  test(`${path} looks as it did`, async ({ page }, testInfo) => {
    test.skip(!testInfo.project.name.startsWith('chromium-'), 'the desktop projects carry the baselines');
    await mockApi(page);
    await page.goto(path);
    await settle(page);
    const expected = testInfo.project.name.endsWith('-ar') ? 'rtl' : 'ltr';
    await expect(page.locator('html')).toHaveAttribute('dir', expected);
    await expect(page).toHaveScreenshot(name(path), { fullPage: true, maxDiffPixelRatio: 0.01 });
  });
}
