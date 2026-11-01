import { defineConfig, devices } from '@playwright/test';

/** Z15-T9: each language and direction, on a desktop and on a phone. */
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4199', trace: 'retain-on-failure' },
  projects: [
    {
      name: 'chromium-en',
      use: { ...devices['Desktop Chrome'], storageState: 'helpers/storage-en.json' },
    },
    {
      name: 'chromium-ar',
      use: { ...devices['Desktop Chrome'], storageState: 'helpers/storage-ar.json', locale: 'ar-SA' },
    },
    {
      name: 'phone-ar',
      use: { ...devices['Pixel 7'], storageState: 'helpers/storage-ar.json', locale: 'ar-SA' },
    },
  ],
  webServer: {
    command: 'npm --prefix ../web start',
    url: 'http://localhost:4199',
    reuseExistingServer: true,
    timeout: 300_000,
  },
});
