import { expect, test } from '@playwright/test';

test('document direction follows language', async ({ page }, testInfo) => {
  await page.goto('/');
  const expected = testInfo.project.name.endsWith('-ar') ? 'rtl' : 'ltr';
  await expect(page.locator('html')).toHaveAttribute('dir', expected);
});
