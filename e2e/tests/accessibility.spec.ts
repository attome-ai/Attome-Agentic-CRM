import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

/** B22-T1: the pages a visitor reaches before signing in. */
const ROUTES = [
  '/xrm/login',
  '/forgot-password',
  '/register',
  '/reset-password?token=sample',
  '/verify-email?token=sample',
  '/preferences',
  '/pay/sample',
  '/quote/sample',
  '/book/sample',
  '/book/manage/sample',
  '/esign/sample',
  '/approval-link?token=sample',
  '/portal',
];
const AA = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

for (const route of ROUTES) {
  test(`${route} has no AA violations`, async ({ page }) => {
    await page.goto(route);
    await page.waitForLoadState('networkidle');
    const { violations } = await new AxeBuilder({ page }).withTags(AA).analyze();
    const found = violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
    expect(found).toEqual([]);
  });
}
