import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { mockApi } from '../helpers/mock-api';

/** B12-T2: text contrast of key screens in each theme, public and signed in. */
const SCREENS = ['/xrm/login', '/register', '/forgot-password', '/xrm/dashboard', '/xrm/settings'];

for (const theme of ['light', 'dark']) {
  for (const path of SCREENS) {
    test(`${path} is readable in the ${theme} theme`, async ({ page }) => {
      await page.addInitScript(mode => localStorage.setItem('xrm-theme-mode', mode), theme);
      await mockApi(page);
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      await expect(page.locator('html')).toHaveClass(new RegExp(theme));
      const { violations } = await new AxeBuilder({ page }).withRules(['color-contrast']).analyze();
      expect(violations.flatMap(v => v.nodes.map(n => `${n.target.join(' ')}: ${n.any[0]?.message}`))).toEqual([]);
    });
  }
}
