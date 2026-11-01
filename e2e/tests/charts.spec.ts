import { expect, test } from '@playwright/test';
import { mockApi } from '../helpers/mock-api';

const DASHBOARD = '00000000-0000-7000-8000-00000000000a';
const PAGE = '00000000-0000-7000-8000-00000000000b';
const SECTION = '00000000-0000-7000-8000-00000000000c';

const KINDS: [string, string][] = [
  ['stacked_bar_chart', 'chart_stacked_bar'], ['combo_chart', 'chart_combo'], ['waterfall_chart', 'chart_waterfall'],
  ['treemap', 'chart_treemap'], ['sunburst_chart', 'chart_sunburst'], ['sankey_diagram', 'chart_sankey'],
  ['radar_chart', 'chart_radar'], ['polar_chart', 'chart_polar'], ['heatmap', 'chart_heatmap'],
  ['calendar_heatmap', 'chart_calendar_heatmap'], ['pareto_chart', 'chart_pareto'], ['control_chart', 'chart_control'],
  ['scatter_plot', 'chart_scatter'], ['bubble_chart', 'chart_bubble'], ['range_area_chart', 'chart_range_area'],
];

/** The app shell reading the mock's generic list as its own shapes. */
const MOCK_SHAPE_ERRORS = [
  'items.map is not a function',
  'this.apps(...).find is not a function',
  "Cannot read properties of undefined (reading 'timezone')",
];

function widgetId(index: number): string {
  return `00000000-0000-7000-8000-1${String(index).padStart(11, '0')}`;
}

const days = ['2026-01-05', '2026-01-06', '2026-01-07', '2026-01-08'];

function result(widgetType: string, renderKind: string, index: number) {
  const buckets = days.map((day, i) => ({
    key: renderKind === 'chart_calendar_heatmap'
      ? { kind: 'range', start: `${day}T00:00:00Z`, end: `${day}T23:59:59Z` }
      : { kind: 'value', value: `stage-${i}` },
    label: renderKind === 'chart_calendar_heatmap' ? day : `Stage ${i}`,
    values: [10 + i * 7, 4 + i, 2 + i * 3],
  }));
  return {
    widget_id: widgetId(index),
    data: {
      widget_id: widgetId(index),
      widget_type: widgetType,
      render_kind: renderKind,
      data_class: 'structured',
      drillability: 'exact',
      definition_source: 'published',
      published_version_number: 1,
      as_of: '2026-01-09T10:00:00Z',
      timezone: 'UTC',
      timezone_source: 'utc',
      definition_fingerprint: 'fp',
      applied_filters: [],
      structured: {
        measures: [
          { aggregation: 'sum', field: 'amount', label: 'Amount' },
          { aggregation: 'count', label: 'Deals' },
          { aggregation: 'avg', field: 'amount', label: 'Average' },
        ],
        group: { field: 'stage' },
        buckets,
        truncated: false,
      },
    },
  };
}

test('every chart type draws in a real browser, in the page direction', async ({ page }) => {
  const problems: string[] = [];
  page.on('pageerror', e => { if (!MOCK_SHAPE_ERRORS.includes(e.message)) problems.push(e.message); });

  await mockApi(page, {
    [`/api/v1/attome-dashboard/${DASHBOARD}/published`]: {
      state: 'published',
      version_id: DASHBOARD,
      version_number: 1,
      snapshot: {
        id: DASHBOARD,
        pages: [{
          id: PAGE,
          name: 'Charts',
          sections: [{
            id: SECTION,
            layout_mode: 'grid',
            widgets: KINDS.map(([type], i) => ({
              id: widgetId(i), name: type, widget_type: type,
              grid_col: (i % 3) * 4, grid_row: Math.floor(i / 3) * 4, grid_col_span: 4, grid_row_span: 4,
            })),
          }],
        }],
      },
    },
    [`/api/v1/attome-dashboard/${DASHBOARD}/pages/${PAGE}/data`]: {
      page_id: PAGE,
      definition_source: 'published',
      widgets: KINDS.map(([type, kind], i) => result(type, kind, i)),
    },
  });

  await page.goto(`/xrm/dashboard/view?id=${DASHBOARD}`);

  const charts = page.locator('attome-echart');
  await expect(charts).toHaveCount(KINDS.length, { timeout: 60_000 });
  for (let i = 0; i < KINDS.length; i++) {
    await expect(charts.nth(i).locator('svg path, svg rect, svg polygon').first(), KINDS[i][0]).toBeAttached({ timeout: 30_000 });
    await expect(charts.nth(i).locator('[role="img"]')).toHaveAttribute('aria-label', /.+/);
    // It fills its card. The card's own width is the shell's business: on a
    // phone the sidebar stays open and leaves it about 100 pixels.
    const chart = await charts.nth(i).boundingBox();
    const card = await page.locator('.xdv-widget').nth(i).boundingBox();
    expect(chart!.width, KINDS[i][0]).toBeGreaterThan(card!.width * 0.7);
    expect(chart!.height, KINDS[i][0]).toBeGreaterThan(150);
  }
  // The card follows the theme: the light default is no dark card behind dark text.
  await expect(page.locator('.xdv-widget').first()).toHaveCSS('background-color', 'rgb(255, 255, 255)');
  await expect(page.locator('attome-dashboard-chart table').first()).toBeAttached();
  await expect(page.getByText('dashboard.chart.')).toHaveCount(0);
  expect(problems).toEqual([]);
});
