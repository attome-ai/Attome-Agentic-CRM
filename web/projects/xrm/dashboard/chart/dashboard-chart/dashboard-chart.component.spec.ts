import { ComponentFixture, TestBed } from '@angular/core/testing';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { ChartBucket, ChartCategory, ChartKind, ChartSeries, DashboardChartComponent } from './dashboard-chart.component';

// Dashboard 10/10 Phase 4.1 (R-28) — the chart primitive: text alternative,
// keyboard-operable marks, a table view, and no arithmetic of its own.

const categories: ChartCategory[] = [
  { trackKey: 'open', label: 'open' },
  { trackKey: 'won', label: 'won' },
];

function point(category: string, value: number): ChartBucket {
  return { trackKey: category, label: category, value, key: { kind: 'value', value: category } };
}

const oneSeries: ChartSeries[] = [{ trackKey: 'total', name: '', color: '#000', points: [point('open', 117), point('won', 4)] }];

function render(kind: ChartKind, options: { interactive?: boolean; series?: ChartSeries[] } = {}): {
  fixture: ComponentFixture<DashboardChartComponent>;
  host: HTMLElement;
  selected: ChartBucket[];
} {
  TestBed.configureTestingModule({
    imports: [DashboardChartComponent],
    providers: [{ provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } }, provideAttomeI18n(), provideXrmI18n()],
  });
  const fixture = TestBed.createComponent(DashboardChartComponent);
  fixture.componentRef.setInput('kind', kind);
  fixture.componentRef.setInput('title', 'Deals');
  fixture.componentRef.setInput('categories', categories);
  fixture.componentRef.setInput('series', options.series ?? oneSeries);
  fixture.componentRef.setInput('interactive', options.interactive ?? false);
  const selected: ChartBucket[] = [];
  fixture.componentInstance.selected.subscribe(b => selected.push(b));
  fixture.detectChanges();
  return { fixture, host: fixture.nativeElement as HTMLElement, selected };
}

describe('DashboardChartComponent', () => {
  it('a non-interactive chart is one image whose label summarises the data', async () => {
    const { host, fixture } = render('bar');
    const svg = host.querySelector('svg')!;
    expect(svg.getAttribute('role')).toBe('img');
    // The summary is an ICU message; its formatter loads lazily.
    await vi.waitFor(() => expect(fixture.componentInstance.summary()).toContain('2 values'));
    expect(fixture.componentInstance.summary()).toContain('Deals');
    // messageformat isolates each parameter with direction marks.
    expect(fixture.componentInstance.summary().replace(/[\u200e\u200f\u2066-\u2069]/g, '')).toContain('highest open (117)');
    expect(host.querySelectorAll('rect[role="button"]').length).toBe(0);
    expect(host.querySelectorAll('rect').length).toBe(2);
  });

  it('an interactive chart exposes each value as a labelled button operable by keyboard', () => {
    const { host, selected } = render('bar', { interactive: true });
    expect(host.querySelector('svg')!.getAttribute('role')).toBe('group');
    const marks = host.querySelectorAll<SVGRectElement>('rect[role="button"]');
    expect(marks.length).toBe(2);
    expect(marks[0].getAttribute('tabindex')).toBe('0');
    expect(marks[0].getAttribute('aria-label')).toBe('open: 117');
    marks[1].dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    marks[0].dispatchEvent(new KeyboardEvent('keydown', { key: ' ' }));
    expect(selected.map(b => b.label)).toEqual(['won', 'open']);
  });

  it('shows a tooltip on focus and draws an axis with category labels', () => {
    const { host, fixture } = render('line', { interactive: true });
    host.querySelector<SVGCircleElement>('circle[role="button"]')!.dispatchEvent(new FocusEvent('focus'));
    fixture.detectChanges();
    expect(host.querySelector('.xch-tooltip')?.textContent).toContain('117');
    const labels = [...host.querySelectorAll('.xch-axis-label')].map(t => t.textContent?.trim());
    expect(labels).toContain('open');
    expect(labels).toContain('0');
  });

  it('the table alternative lists every value, and its values drill when the chart does', () => {
    const { host, fixture, selected } = render('donut', { interactive: true });
    host.querySelector<HTMLButtonElement>('.xch-toggle')!.click();
    fixture.detectChanges();
    const table = host.querySelector('table')!;
    expect(table.textContent).toContain('open');
    expect(table.textContent).toContain('117');
    table.querySelectorAll<HTMLButtonElement>('button')[1].click();
    expect(selected.map(b => b.label)).toEqual(['won']);
    expect(host.querySelector('.xch-toggle')!.getAttribute('aria-pressed')).toBe('true');
  });

  it('a series with no value for a category shows a dash, not a zero', () => {
    const series: ChartSeries[] = [
      { trackKey: 'a', name: 'North', color: '#000', points: [point('open', 2), null] },
      { trackKey: 'b', name: 'South', color: '#111', points: [point('open', 3), point('won', 5)] },
    ];
    const { host, fixture } = render('bar', { series });
    expect(host.querySelectorAll('rect').length).toBe(3);
    expect(host.querySelector('.xch-legend')?.textContent).toContain('South');
    fixture.componentInstance.toggleTable();
    fixture.detectChanges();
    const rows = host.querySelectorAll('tbody tr');
    expect(rows[1].textContent).toContain('—');
  });

  it('a funnel renders its stages in server order', () => {
    const { host } = render('funnel');
    const labels = [...host.querySelectorAll('.xch-funnel-label')].map(l => l.textContent);
    expect(labels).toEqual(['open', 'won']);
    expect(host.querySelector('.xch-funnel')!.getAttribute('role')).toBe('img');
  });
});
