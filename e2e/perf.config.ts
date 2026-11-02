import { defineConfig, devices } from '@playwright/test';

/**
 * AA14-T6: the Core Web Vitals check (`perf/`), apart from the functional
 * suites: one desktop Chrome, one worker so the screens do not compete for
 * the throttled CPU. Run by the release gate's `web_vitals` step.
 */
export default defineConfig({
  testDir: './perf',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env['CI'],
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4198', trace: 'retain-on-failure' },
  projects: [
    {
      name: 'chromium-en',
      use: { ...devices['Desktop Chrome'], storageState: 'helpers/storage-en.json' },
    },
  ],
  webServer: {
    command: 'node perf/serve.mjs',
    url: 'http://localhost:4198',
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
