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

`tests/accessibility.spec.ts` runs axe (WCAG 2.2 A and AA) on the public pages and on every built-in
screen behind sign-in, in every project: the screens are read from the route tree itself
(`helpers/xrm-routes.ts` walks `web/src/app/xrm-shell.routes.ts`), so a new screen is checked without
being listed. They run over the API mock with empty data; the few screens whose template throws on
empty data are listed in the spec's `NEEDS_DATA` as `fixme` until they get sample data.

`tests/rtl-screens.spec.ts` compares the built-in screens, in English and in Arabic, with their
screenshot baselines (`tests/rtl-screens.spec.ts-snapshots/`, one per desktop project). The first
run, or a change meant to move a screen, makes them: `npx playwright test rtl-screens.spec.ts
--update-snapshots`; commit the images. After that a screen that moves by more than 1% of its
pixels fails.

## Core Web Vitals

`npm --prefix ../web run build`, then `npx playwright test -c perf.config.ts`, measures the production
build, served gzipped by `perf/serve.mjs` (the dev server is far larger, so it would say nothing).
It opens the record list, a record form and a dashboard over a
throttled "Fast 3G" link with a 4x slower CPU, against the API mock, and fails a screen whose
largest content paints after 2.5 s (LCP) or whose interaction takes over 200 ms (INP). The numbers
go to `perf/results.json`. The release gate runs it with `attome release --check --web-vitals` and
keeps the numbers as `target/release-gate/web-vitals.json`; the bundle budgets stay in
`web/angular.json`, which every build checks.

## Time to a working CRM

`npx playwright test -c time-to-crm.config.ts` walks a new customer's first hour against a live
deployment: install (until `/health/ready` answers; set `ATTOME_E2E_INSTALL_STARTED` to the
installer's start in epoch milliseconds to count the install itself), the first-run country,
describing an app (`model.app.plan`), drafting a model from a spreadsheet (`model.from_files`) and
making its build calls, importing the sheet and opening the records. Point it at the deployment
with `ATTOME_E2E_URL` and an administrator's `ATTOME_E2E_AUTH` header value (`ApiKey <id>:<secret>`);
without the URL it is skipped. Run the deployment on the fake model so the answers are
deterministic. Each step's time, and the model's share of it, goes to `results/time-to-crm.json`;
the run fails above 60 minutes in all, model latency excluded.
