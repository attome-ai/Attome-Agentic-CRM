import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mockApi } from '../../helpers/mock-api';

/**
 * B17-T12: the record list on a phone (the `phone` project, a Pixel 7):
 * cards in place of the table (B17-T6), a swipe that completes a task, and
 * the Arabic layout right to left. Runs against the API mock, so it proves
 * the browser side only.
 */

const VIEW_ID = '00000000-0000-7000-8000-0000000000a1';
const TASKS = [
  { id: '00000000-0000-7000-8000-0000000000b1', subject: 'Call the supplier', status: 'open', due_date: '2026-11-02' },
  { id: '00000000-0000-7000-8000-0000000000b2', subject: 'Send the quote', status: 'open', due_date: '2026-11-03' },
];
const column = (name: string, display_name: string) => ({
  name, display_name, data_type: 'text', is_visible: true, is_sortable: true,
  is_searchable: true, is_clickable: false, route_template: '',
});
const VIEW_METADATA = { mobile: { card_title: 'subject', card_lines: ['due_date'], swipe_end: 'complete' } };

async function taskList(page: Page): Promise<void> {
  await mockApi(page, {
    '/api/v1/views': [{
      id: VIEW_ID, name: 'My tasks', icon: 'las la-tasks', is_default: true, kind: 'list',
      view_metadata: VIEW_METADATA, scope: 'system', is_mine: false,
    }],
    '/api/v1/schema/task': {
      id: '00000000-0000-7000-8000-0000000000c1', name: 'Task', plural_name: 'Tasks',
      fields: [], relationships: [], allowed_actions: ['read', 'update'],
    },
    '/api/v1/query/execute': {
      metadata: {
        query_id: '00000000-0000-7000-8000-0000000000d1', view_id: VIEW_ID, record_no: null,
        entity_logical_name: 'task', can_edit_query: false, view_kind: 'list', view_metadata: VIEW_METADATA,
      },
      data: {
        columns: [column('subject', 'Subject'), column('status', 'Status'), column('due_date', 'Due')],
        records: TASKS, total: TASKS.length, page: 1, page_size: 50,
      },
    },
  });
}

test('list shows cards on phone', async ({ page }) => {
  await taskList(page);
  await page.goto('/xrm/entity/task/list');
  const cards = page.getByTestId('list-card');
  await expect(cards).toHaveCount(TASKS.length);
  await expect(cards.first()).toContainText('Call the supplier');
  await expect(page.locator('table')).toHaveCount(0);
  const { violations } = await new AxeBuilder({ page })
    .include('[data-testid="list-cards"]')
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  const serious = violations.filter(v => v.impact === 'serious' || v.impact === 'critical');
  expect(serious.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`)).toEqual([]);
});

test('swipe completes task', async ({ page }) => {
  await taskList(page);
  const patched = page.waitForRequest(r => r.method() === 'PATCH' && r.url().includes(`/api/v1/task/${TASKS[0].id}`));
  await page.goto('/xrm/entity/task/list');
  const card = page.getByTestId('list-card').first();
  const box = (await card.boundingBox())!;
  const y = box.y + box.height / 2;
  // Toward the inline end: right in English.
  await page.mouse.move(box.x + 20, y);
  await page.mouse.down();
  await page.mouse.move(box.x + 60, y, { steps: 4 });
  await page.mouse.move(box.x + 140, y, { steps: 4 });
  await page.mouse.up();
  const request = await patched;
  expect(request.postDataJSON()).toEqual({ status: 'completed' });
});

test('arabic phone layout is rtl', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('xrm-lang', 'ar'));
  await taskList(page);
  await page.goto('/xrm/entity/task/list');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  const card = page.getByTestId('list-card').first();
  await expect(card).toBeVisible();
  // A card's text starts at its right edge.
  const align = await card.locator('.lc-open').evaluate(e => getComputedStyle(e).textAlign);
  expect(['start', 'right']).toContain(align);
  const direction = await card.evaluate(e => getComputedStyle(e).direction);
  expect(direction).toBe('rtl');
});
