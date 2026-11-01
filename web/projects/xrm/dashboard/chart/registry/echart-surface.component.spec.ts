import { TestBed } from '@angular/core/testing';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import type { ChartBucket } from '../dashboard-chart/dashboard-chart.component';
import { ECHART_LOADER, EChartInstance, EChartSurfaceComponent } from './echart-surface.component';

function stubChart() {
  let click: (params: { data?: unknown }) => void = () => undefined;
  const chart = {
    setOption: vi.fn(),
    on: vi.fn((_: 'click', handler: typeof click) => { click = handler; }),
    resize: vi.fn(),
    dispose: vi.fn(),
  } satisfies EChartInstance;
  return { chart, click: (params: { data?: unknown }) => click(params) };
}

async function render(load: () => Promise<unknown>, interactive = true) {
  TestBed.configureTestingModule({
    imports: [EChartSurfaceComponent],
    providers: [
      { provide: ECHART_LOADER, useValue: load },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(EChartSurfaceComponent);
  fixture.componentRef.setInput('option', { series: [] });
  fixture.componentRef.setInput('summary', 'Deals by stage');
  fixture.componentRef.setInput('interactive', interactive);
  const picked: ChartBucket[] = [];
  fixture.componentInstance.picked.subscribe(b => picked.push(b));
  await fixture.whenStable();
  fixture.detectChanges();
  await fixture.whenStable();
  return { fixture, picked, host: fixture.nativeElement as HTMLElement };
}

const bucket: ChartBucket = { trackKey: 'a', label: 'Open', value: 3, key: null };

describe('EChartSurfaceComponent', () => {
  it('is one labelled image and draws its option as a replacement', async () => {
    const { chart } = stubChart();
    const { host } = await render(async () => () => chart);
    expect(host.querySelector('[role="img"]')?.getAttribute('aria-label')).toBe('Deals by stage');
    expect(chart.setOption).toHaveBeenCalledWith({ series: [] }, { notMerge: true });
  });

  it('reports the clicked value, and ignores a mark with none', async () => {
    const stub = stubChart();
    const { picked } = await render(async () => () => stub.chart);
    stub.click({ data: { bucket } });
    stub.click({ data: { tip: 'a running share' } });
    stub.click({});
    expect(picked).toEqual([bucket]);
  });

  it('reports nothing when the chart is not interactive', async () => {
    const stub = stubChart();
    const { picked } = await render(async () => () => stub.chart, false);
    stub.click({ data: { bucket } });
    expect(picked).toEqual([]);
  });

  it('releases the chart when it is destroyed', async () => {
    const { chart } = stubChart();
    const { fixture } = await render(async () => () => chart);
    fixture.destroy();
    expect(chart.dispose).toHaveBeenCalled();
  });

  it('says so when the library cannot load', async () => {
    const { fixture, host } = await render(() => Promise.reject(new Error('offline')));
    fixture.detectChanges();
    expect(host.querySelector('[role="status"]')?.textContent).toContain('dashboard.chart.loadFailed');
    expect(host.querySelector('[role="img"]')).toBeNull();
  });
});
