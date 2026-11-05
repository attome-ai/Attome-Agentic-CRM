import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { mockApi } from '../helpers/mock-api';
import { xrmStaticRoutes } from '../helpers/xrm-routes';

/** B22-T1: the pages a visitor reaches before signing in. */
const ROUTES = [
  '/xrm/login',
  '/forgot-password',
  '/register',
  '/reset-password?token=sample',
  '/verify-email?token=sample',
  '/preferences',
  '/pay/sample',
  '/quote/sample',
  '/book/sample',
  '/book/manage/sample',
  '/esign/sample',
  '/approval-link?token=sample',
  '/portal',
];
const AA = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

for (const route of ROUTES) {
  test(`${route} has no AA violations`, async ({ page }) => {
    await page.goto(route);
    await page.waitForLoadState('networkidle');
    const { violations } = await new AxeBuilder({ page }).withTags(AA).analyze();
    const found = violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
    expect(found).toEqual([]);
  });
}

/**
 * B22-T1: every built-in screen behind sign-in, read from the route tree
 * (`helpers/xrm-routes.ts`), over the API mock with empty data. The shell's
 * own reads get their real shapes (the sidebar and apps are arrays, the
 * signed-in user is a record): a screen whose template throws halfway leaves
 * the rest of it blank, which axe would report as unnamed buttons that are
 * not the screen's fault.
 */
const ME = '00000000-0000-7000-8000-000000000001';
const SHELL = {
  '/api/v1/sidebar/get': [],
  '/api/v1/apps': [],
  [`/api/v1/user_account/${ME}`]: { id: ME, row_version: 1, data: { id: ME, timezone: null } },
};
const SIGNED_IN = [
  ...new Set([...xrmStaticRoutes(), '/xrm/settings', '/xrm/search', '/xrm/security', '/xrm/security/mfa']),
];

/**
 * Screens whose template throws on the mock's empty data during change
 * detection (`Cannot read properties of undefined (reading 'length')`,
 * logged to the console), which stops the update halfway: the rest of the
 * screen stays blank, and axe then reports unnamed buttons and unlabelled
 * controls the real screen does not have (their catalog keys exist). Each
 * needs sample data in the mock, or a seeded backend (AC5-T5), before it can
 * be checked; until then they are listed here, not hidden.
 */
const NEEDS_DATA = new Set([
  '/xrm/admin/license/modules',
  '/xrm/admin/project/booking',
  '/xrm/marketing/deliverability',
  '/xrm/documents',
  '/xrm/admin/entity',
]);

for (const route of SIGNED_IN) {
  test(`${route} has no AA violations when signed in`, async ({ page }) => {
    test.fixme(NEEDS_DATA.has(route), 'blank under the API mock; needs sample data (see NEEDS_DATA)');
    await mockApi(page, SHELL);
    await page.goto(route);
    await page.waitForLoadState('networkidle');
    const { violations } = await new AxeBuilder({ page }).withTags(AA).analyze();
    const found = violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
    expect(found).toEqual([]);
  });
}

/** B22-T1: screens showing records, from the API mock with sample data. */
const RECORD_ID = '00000000-0000-7000-8000-0000000000a1';
const ACCOUNT_SCHEMA = {
  id: '00000000-0000-7000-8000-0000000000e1', name: 'account', plural_name: 'accounts',
  relationships: [], business_rules: [], allowed_actions: ['read', 'create', 'update', 'delete'],
  fields: [
    { id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name', field_type: 'text', options: null, sort_order: 1, is_required: true },
    { id: 'f2', entity_id: 'e1', name: 'industry', display_name: 'Industry', field_type: 'choice', options: { choices: ['retail', 'health'], multi: false }, sort_order: 2, is_required: false },
    { id: 'f3', entity_id: 'e1', name: 'annual_revenue', display_name: 'Annual revenue', field_type: 'currency', options: null, sort_order: 3, is_required: false },
    { id: 'f4', entity_id: 'e1', name: 'is_partner', display_name: 'Partner', field_type: 'bool', options: null, sort_order: 4, is_required: false },
  ],
};
const ACCOUNT = {
  id: RECORD_ID, entity_id: ACCOUNT_SCHEMA.id, row_version: 3,
  data: {
    id: RECORD_ID, name: 'شركة النخيل Palm Co', industry: 'retail', annual_revenue: 1250000, is_partner: true,
    created_at: '2026-10-01T08:00:00Z', modified_at: '2026-11-01T09:30:00Z', row_version: 3,
  },
};
const RECORD_ROUTES: { name: string; path: string }[] = [
  { name: 'record list', path: '/xrm/entity/account/list' },
  { name: 'record form', path: `/xrm/entity/account/form?id=${RECORD_ID}` },
];

for (const screen of RECORD_ROUTES) {
  test(`${screen.name} with records has no AA violations`, async ({ page }) => {
    await mockApi(page, {
      '/api/v1/schema/account': ACCOUNT_SCHEMA,
      '/api/v1/account': { items: [ACCOUNT.data, { ...ACCOUNT.data, id: `${RECORD_ID.slice(0, -1)}2`, name: 'Cedar Health' }] },
      [`/api/v1/account/${RECORD_ID}`]: ACCOUNT,
    });
    await page.goto(screen.path);
    await page.waitForLoadState('networkidle');
    const { violations } = await new AxeBuilder({ page }).withTags(AA).analyze();
    const found = violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
    expect(found).toEqual([]);
  });
}
