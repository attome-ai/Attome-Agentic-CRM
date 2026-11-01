import { describe, expect, it } from 'vitest';
import { init } from '../../echarts/public-api';
import type { ChartBucket, ChartCategory, ChartSeries } from '../dashboard-chart/dashboard-chart.component';
import {
  CHART_REGISTRY, ChartInput, ChartOption, EChartKind, calendarDays, controlLimits, isEChartKind, paretoRows, rangeBand,
  tip, waterfallSteps,
} from './chart-registry';

const KINDS = Object.keys(CHART_REGISTRY) as EChartKind[];

const categories: ChartCategory[] = [
  { trackKey: 'a', label: '2026-01-01', date: '2026-01-01' },
  { trackKey: 'b', label: '2026-01-02', date: '2026-01-02' },
  { trackKey: 'c', label: '2026-01-03', date: '2026-01-03' },
];

function series(name: string, numbers: (number | null)[], color = '#8b5cf6'): ChartSeries {
  return {
    trackKey: name,
    name,
    color,
    points: numbers.map((value, i): ChartBucket | null => value === null ? null : {
      trackKey: `${categories[i].trackKey}|${name}`, label: categories[i].label, value, key: null,
    }),
  };
}

function input(overrides: Partial<ChartInput> = {}): ChartInput {
  return {
    categories,
    series: [series('Won', [5, 3, 9]), series('Lost', [2, 7, 1], '#22d3ee'), series('Open', [4, 4, 8], '#f59e0b')],
    threshold: null,
    rtl: false,
    textColor: '#111111',
    locale: 'en',
    labels: { cumulativeShare: 'Running share', mean: 'Mean', upperLimit: 'Upper', lowerLimit: 'Lower' },
    format: String,
    compact: String,
    ...overrides,
  };
}

/** The real library, drawing without a browser. */
function draw(option: ChartOption): string {
  const chart = init(null as unknown as HTMLElement, null, { renderer: 'svg', ssr: true, width: 640, height: 360 });
  chart.setOption({ animation: false, ...option });
  const svg = chart.renderToSVGString();
  chart.dispose();
  return svg;
}

function seriesOf(option: ChartOption): Record<string, unknown>[] {
  return option['series'] as Record<string, unknown>[];
}

describe('the chart registry', () => {
  it('registers an adapter per kind and nothing else', () => {
    expect(KINDS).toHaveLength(15);
    expect(isEChartKind('sankey')).toBe(true);
    expect(isEChartKind('bar')).toBe(false);
  });

  for (const kind of KINDS) {
    for (const rtl of [false, true]) {
      it(`${kind} draws marks ${rtl ? 'right to left' : 'left to right'}`, () => {
        const svg = draw(CHART_REGISTRY[kind].option(input({ rtl })));
        expect(svg).toContain('<svg');
        expect(svg).toMatch(/<(path|rect|polygon)\b/);
      });
    }

    it(`${kind} draws with the fewest series it allows, some of them missing`, () => {
      const few = [series('One', [4, null, 2]), series('Two', [1, 2, null]), series('Three', [3, 3, 3])]
        .slice(0, CHART_REGISTRY[kind].minSeries);
      expect(draw(CHART_REGISTRY[kind].option(input({ series: few })))).toContain('<svg');
    });

    it(`${kind} escapes a label in its tooltip`, () => {
      const hostile = '<img src=x onerror=alert(1)>';
      const named = [{ ...categories[0], label: hostile }, categories[1], categories[2]];
      const withLabel = input({
        categories: named,
        series: input().series.map(s => ({
          ...s, points: s.points.map((p, i) => p && (i === 0 ? { ...p, label: hostile } : p)),
        })),
      });
      const json = JSON.stringify(CHART_REGISTRY[kind].option(withLabel));
      const tips = [...json.matchAll(/"tip":"((?:[^"\\]|\\.)*)"/g)].map(m => m[1]);
      expect(tips.length).toBeGreaterThan(0);
      for (const text of tips) expect(text).not.toContain('<img');
    });
  }
});

describe('right to left', () => {
  it('mirrors a category axis and moves the value axis across', () => {
    const ltr = CHART_REGISTRY.stacked_bar.option(input());
    const rtl = CHART_REGISTRY.stacked_bar.option(input({ rtl: true }));
    expect((ltr['xAxis'] as ChartOption)['inverse']).toBe(false);
    expect((rtl['xAxis'] as ChartOption)['inverse']).toBe(true);
    expect((ltr['yAxis'] as ChartOption)['position']).toBe('left');
    expect((rtl['yAxis'] as ChartOption)['position']).toBe('right');
  });

  it('draws the first category on the right', () => {
    const first = (rtl: boolean) => {
      const svg = draw(CHART_REGISTRY.stacked_bar.option(input({ rtl })));
      return [...svg.matchAll(/transform="translate\(([\d.]+) [\d.]+\)"[^>]*>2026-01-01/g)].map(m => Number(m[1]))[0];
    };
    expect(first(true)).toBeGreaterThan(first(false));
  });

  it('turns a sankey around by swapping each link', () => {
    const link = (rtl: boolean) => (seriesOf(CHART_REGISTRY.sankey.option(input({ rtl })))[0]['links'] as ChartOption[])[0];
    expect(link(false)['source']).toBe('c:a');
    expect(link(true)['source']).toBe('s:Won');
  });
});

describe('what an adapter computes', () => {
  it('runs a waterfall through zero', () => {
    expect(waterfallSteps(series('Net', [5, -8, 2])).map(s => [s.from, s.to])).toEqual([[0, 5], [5, -3], [-3, -1]]);
  });

  it('orders a pareto largest first and ends at the whole', () => {
    const rows = paretoRows(series('Issues', [1, 6, 3]));
    expect(rows.map(r => r.bucket.value)).toEqual([6, 3, 1]);
    expect(rows.map(r => Math.round(r.share))).toEqual([60, 90, 100]);
  });

  it('leaves zero and negative values out of a pareto', () => {
    expect(paretoRows(series('Issues', [0, -2, 3])).map(r => r.bucket.value)).toEqual([3]);
  });

  it('takes control limits from the values shown', () => {
    expect(controlLimits([2, 4, 4, 4, 5, 5, 7, 9])).toEqual({ mean: 5, upper: 11, lower: -1 });
    expect(controlLimits([])).toEqual({ mean: 0, upper: 0, lower: 0 });
  });

  it('skips a category with no date in a calendar and sorts the rest', () => {
    const days = calendarDays(input({
      categories: [{ trackKey: 'x', label: 'Unknown' }, categories[2], categories[1]],
      series: [series('Won', [5, 3, 9])],
    }));
    expect(days.map(d => d.day)).toEqual(['2026-01-02', '2026-01-03']);
  });

  it('skips a category missing either edge of a band', () => {
    const band = rangeBand(input({ series: [series('Low', [1, null, 3]), series('High', [2, 5, 6])] }));
    expect(band).toEqual([{ index: 0, low: 1, high: 2 }, { index: 2, low: 3, high: 6 }]);
  });

  it('inherits the text colour and the font, so a theme switch needs no redraw', () => {
    const svg = draw(CHART_REGISTRY.stacked_bar.option(input({ textColor: 'currentColor' })));
    expect(svg).toContain('fill="currentColor"');
    expect(svg).toContain('font-family:inherit');
    expect(svg).not.toContain('YaHei');
  });

  it('keeps each value\'s bucket on the data item so a click can drill', () => {
    const items = seriesOf(CHART_REGISTRY.scatter.option(input()))[0]['data'] as ChartOption[];
    expect((items[0]['bucket'] as ChartBucket).trackKey).toBe('a|Won');
    expect(items[0]['value']).toEqual([5, 2]);
  });

  it('sizes a bubble by area', () => {
    const items = seriesOf(CHART_REGISTRY.bubble.option(input({
      series: [series('X', [1, 2, 3]), series('Y', [1, 2, 3]), series('Size', [100, 25, 1])],
    })))[0]['data'] as ChartOption[];
    expect(items.map(i => i['symbolSize'])).toEqual([40, 20, 6]);
  });

  it('draws the threshold as a line', () => {
    const [first] = seriesOf(CHART_REGISTRY.stacked_bar.option(input({ threshold: 6 })));
    expect((first['markLine'] as { data: unknown[] }).data).toEqual([{ yAxis: 6 }]);
  });

  it('gives a category and a series with the same name separate sankey nodes', () => {
    const same = input({ series: [series('2026-01-01', [5, 3, 9])] });
    expect(draw(CHART_REGISTRY.sankey.option(same))).toContain('<svg');
  });

  it('puts the limits of a control chart on its axis', () => {
    const option = CHART_REGISTRY.control.option(input({ series: [series('Rate', [10, 17, 24])] }));
    const axis = option['yAxis'] as { min: number; max: number };
    const limits = controlLimits([10, 17, 24]);
    expect(axis.min).toBeLessThan(limits.lower);
    expect(axis.max).toBeGreaterThan(limits.upper);
  });

  it('tells the parts of a single series treemap apart', () => {
    const data = seriesOf(CHART_REGISTRY.treemap.option(input({ series: [series('Won', [5, 3, 9])] })))[0]['data'] as ChartOption[];
    expect(new Set(data.map(d => (d['itemStyle'] as { color: string }).color)).size).toBe(3);
  });

  it('drops a value a treemap cannot draw', () => {
    const data = seriesOf(CHART_REGISTRY.treemap.option(input({ series: [series('Won', [5, 0, -2])] })))[0]['data'];
    expect(data).toHaveLength(1);
  });

  it('escapes every line of a tooltip', () => {
    expect(tip('<b>', 'a & b')).toBe('&#60;b&#62;<br/>a &#38; b');
  });
});
