import { defineConfig, devices } from '@playwright/test';

/**
 * Z15-T9: each language and direction, on a desktop and on a phone. B17-T12:
 * the phone-only specs under `tests/mobile` run in the `phone` project alone.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4199', trace: 'retain-on-failure' },
  projects: [
    {
      name: 'chromium-en',
      testIgnore: /mobile\//,
      use: { ...devices['Desktop Chrome'], storageState: 'helpers/storage-en.json' },
    },
    {
      name: 'chromium-ar',
      testIgnore: /mobile\//,
      use: { ...devices['Desktop Chrome'], storageState: 'helpers/storage-ar.json', locale: 'ar-SA' },
    },
    {
      name: 'phone-ar',
      testIgnore: /mobile\//,
      use: { ...devices['Pixel 7'], storageState: 'helpers/storage-ar.json', locale: 'ar-SA' },
    },
    {
      name: 'phone',
      testMatch: /mobile\/.*\.spec\.ts/,
      use: { ...devices['Pixel 7'], storageState: 'helpers/storage-en.json' },
    },
  ],
  webServer: {
    command: 'npm --prefix ../web start',
    url: 'http://localhost:4199',
    reuseExistingServer: true,
    timeout: 300_000,
  },
});
