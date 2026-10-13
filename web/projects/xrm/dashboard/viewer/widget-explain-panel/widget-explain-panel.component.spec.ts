import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { DashboardService, WidgetExplanation } from '@attome/xrm/dashboard/data';
import { WidgetExplainPanelComponent } from './widget-explain-panel.component';

// Dashboard 10/10 Phase 3.2 — the panel renders the server's explanation.

function explanation(overrides: Partial<WidgetExplanation>): WidgetExplanation {
  return {
    widget_id: 'w1',
    widget_type: 'bar_chart',
    data_class: 'structured',
    drillability: 'exact',
    definition_source: 'published',
    published_version_number: 2,
    definition_fingerprint: 'fp',
    as_of: '2026-09-17T10:00:00Z',
    timezone: 'Asia/Bahrain',
    timezone_source: 'page',
    filters: [
      { field: 'owner_ref', field_display_name: 'Owner', op: 'eq', value: 'u1', value_display: 'nora', origin: { kind: 'builtin', name: '@current_user' } },
    ],
    ...overrides,
  } as WidgetExplanation;
}

function render(e: WidgetExplanation): string {
  TestBed.configureTestingModule({
    imports: [WidgetExplainPanelComponent],
    providers: [
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(), provideXrmI18n(),
      { provide: DashboardService, useValue: { widgetExplain: vi.fn(() => of(e)) } },
    ],
  });
  const fixture = TestBed.createComponent(WidgetExplainPanelComponent);
  fixture.componentRef.setInput('dashboardId', 'd1');
  fixture.componentRef.setInput('widgetId', 'w1');
  fixture.detectChanges();
  return (fixture.nativeElement as HTMLElement).textContent ?? '';
}

describe('WidgetExplainPanelComponent', () => {
  it('shows the measure, filters with origins, scope and freshness of a structured widget', () => {
    const text = render(explanation({
      structured: {
        entity_logical_name: 'deal', entity_display_name: 'Deal',
        measures: [{ aggregation: 'sum', field: 'amount', field_display_name: 'Amount', expression: 'SUM(amount)' }],
        live_rows_only: true, access_level: 'team', caller_is_admin: false, presentation: {},
      },
    } as unknown as Partial<WidgetExplanation>));
    expect(text).toContain('SUM(amount)');
    expect(text).toContain('Owner');
    expect(text).toContain('nora');
    expect(text).toContain('builtin');
    expect(text).toContain('Scope');
    expect(text).toContain('Inactive records never count.');
    expect(text).toContain('Asia/Bahrain');
  });

  it('says a governed KPI is service-scoped and never claims caller scoping', () => {
    const text = render(explanation({
      data_class: 'kpi', drillability: 'explain_only', filters: [],
      kpi: {
        service_scoped: true,
        metrics: [{
          metric: { metric_id: 'm1', name: 'Win rate', status: 'ok', history: [], current: null },
          source_kind: 'formula', formula: 'won / total',
          lineage: { relation: 'root', cycle: false, missing: false, truncated: false, children: [
            { metric_id: 'm2', name: 'Won deals', relation: 'formula_input', cycle: false, missing: false, truncated: false, children: [] },
          ] },
        }],
      },
    } as unknown as Partial<WidgetExplanation>));
    expect(text).toContain('not filtered to you');
    expect(text).toContain('won / total');
    expect(text).toContain('Won deals');
    expect(text).not.toContain('Scope');
  });
});
