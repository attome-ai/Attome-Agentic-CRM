# End-to-end tests

Playwright tests that run the web app in a real browser, in English and Arabic, on a desktop and a
phone.

```
npm ci
npx playwright install chromium
npx playwright test
```

The config starts the web app on port 4199, or uses one already running there.

The specs under `tests/mobile` run only in the `phone` project (a Pixel 7): the record list as cards,
a swipe that completes a task, and the Arabic phone layout right to left, with axe on the cards
(`npx playwright test --project=phone`).

## Core Web Vitals

`npx playwright test -c perf.config.ts` opens the record list, a record form and a dashboard over a
throttled "Fast 3G" link with a 4x slower CPU, against the API mock, and fails a screen whose
largest content paints after 2.5 s (LCP) or whose interaction takes over 200 ms (INP). The numbers
go to `perf/results.json`. The release gate runs it with `attome release --check --web-vitals` and
keeps the numbers as `target/release-gate/web-vitals.json`; the bundle budgets stay in
`web/angular.json`, which every build checks.
