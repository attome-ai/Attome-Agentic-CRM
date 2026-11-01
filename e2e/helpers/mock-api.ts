import type { Page, Route } from '@playwright/test';

/**
 * A signed-in session with no backend: every `/api` request is answered here,
 * so a spec can reach a page behind sign-in. A route a spec does not name gets
 * an empty list body, which the screens treat as nothing to show. What this
 * proves is the browser side only: it says nothing about the server.
 */
export type MockRoutes = Record<string, unknown>;

const USER_ID = '00000000-0000-7000-8000-000000000001';

function headers(route: Route): Record<string, string> {
  return {
    'access-control-allow-origin': route.request().headers()['origin'] ?? '*',
    'access-control-allow-credentials': 'true',
    'access-control-allow-headers': '*',
    'access-control-allow-methods': '*',
  };
}

export async function mockApi(page: Page, routes: MockRoutes = {}): Promise<void> {
  const answers: MockRoutes = {
    '/api/v1/auth/session': { user_id: USER_ID, email: 'e2e@example.test', idle_secs: 3600 },
    ...routes,
  };
  await page.route(/\/api\//, async route => {
    if (route.request().method() === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: headers(route) });
      return;
    }
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      status: 200,
      headers: headers(route),
      contentType: 'application/json',
      body: JSON.stringify(path in answers ? answers[path] : { items: [], total: 0, page: 1, page_size: 50 }),
    });
  });
}
