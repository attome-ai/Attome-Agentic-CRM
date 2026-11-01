# End-to-end tests

Playwright tests that run the web app in a real browser, in English and Arabic, on a desktop and a
phone.

```
npm ci
npx playwright install chromium
npx playwright test
```

The config starts the web app on port 4199, or uses one already running there.
