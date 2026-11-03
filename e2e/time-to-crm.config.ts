import { defineConfig } from '@playwright/test';

/**
 * AK1-T1: the time-to-CRM flow (`time-to-crm.spec.ts`), apart from the
 * screen suites: API calls against a live deployment (`ATTOME_E2E_URL`), so
 * no browser project and no web server; one worker, one run.
 */
export default defineConfig({
  testDir: '.',
  testMatch: /time-to-crm\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env['CI'],
  reporter: [['list']],
});
