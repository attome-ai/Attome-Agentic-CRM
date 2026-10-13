import {
  AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnInit, inject, input, output, signal, viewChild,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DashboardService, MetricLineageNode, WidgetExplanation } from '@attome/xrm/dashboard/data';

/**
 * Dashboard 10/10 Phase 3.2 — "How was this calculated?".
 *
 * Renders `POST .../widgets/{id}/explain`, built from the same context the
 * number used: the measure in words and formally, every filter with its origin
 * (definition, parameter, cross-filter, built-in — a built-in shows only the
 * caller's own name), the timezone and where it came from, the live-row rule,
 * the caller's record scope, and freshness. A governed KPI says it is computed
 * by the platform for a fixed scope and shows its metric chain; a stored-query
 * widget says its rows are the result.
 */
@Component({
  selector:   'xrm-widget-explain-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe, NgTemplateOutlet],
  styleUrls:  ['../widget-records-drawer/widget-records-drawer.component.css', './widget-explain-panel.component.css'],
  templateUrl: './widget-explain-panel.component.html',
  host: { '(document:keydown.escape)': 'closed.emit()' },
})
export class WidgetExplainPanelComponent implements OnInit, AfterViewInit {
  private readonly dashboardApi = inject(DashboardService);
  private readonly lang         = inject(LangService);

  readonly dashboardId  = input.required<string>();
  readonly widgetId     = input.required<string>();
  readonly widgetName   = input('');
  readonly parameters   = input<Record<string, unknown>>({});
  readonly crossFilters = input<Record<string, unknown>>({});
  readonly preview      = input(false);

  readonly closed = output<void>();

  private readonly panel = viewChild<ElementRef<HTMLElement>>('panel');

  readonly loading     = signal(true);
  readonly error       = signal<string | null>(null);
  readonly explanation = signal<WidgetExplanation | null>(null);

  ngOnInit(): void {
    this.dashboardApi.widgetExplain(this.dashboardId(), this.widgetId(), {
      parameters: this.parameters(),
      cross_filters: this.crossFilters(),
      preview: this.preview(),
    }).subscribe({
      next: res => {
        this.loading.set(false);
        this.explanation.set(res);
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.error.set(e.message);
      },
    });
  }

  ngAfterViewInit(): void {
    this.panel()?.nativeElement.focus();
  }

  time(value: string | null | undefined): string {
    return value
      ? new Date(value).toLocaleString(this.lang.intlLocale(), { dateStyle: 'short', timeStyle: 'short' })
      : '';
  }

  filterValue(value: unknown): string {
    if (value === null || value === undefined) return '';
    if (Array.isArray(value)) return value.map(v => String(v)).join(', ');
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  lineageChildren(node: MetricLineageNode): MetricLineageNode[] {
    return node.children ?? [];
  }
}
