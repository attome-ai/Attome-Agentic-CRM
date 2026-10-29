import {
  AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnInit, inject, input, output, signal, viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { NgTemplateOutlet } from '@angular/common';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { entityFormRoute } from '@attome/xrm/core/entity';
import { DashboardService, MetricLineageNode, WidgetExplanation } from '@attome/xrm/dashboard/data';

/** P7-T7's explanation facts, as the panel reads them. */
interface ExplainFacts {
  definition_en?: string;
  definition_ar?: string;
  measure_basis?: { attribute: string; grain: string } | null;
  computed_at?: string | null;
  currency?: { code: string } | null;
  glossary_term_id?: string | null;
  lineage_url?: string | null;
}

/** P7-T12: what the panel shows of them. */
export interface ExplainWords {
  definition: string | null;
  basis: { attribute: string; grain: string } | null;
  computedAt: string | null;
  currency: string | null;
  glossaryTermId: string | null;
  lineageUrl: string | null;
}

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
  imports:    [RouterLink, TranslatePipe, NgTemplateOutlet],
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

  /** P7-T12: the explanation's words and computation facts (P7-T7), in
   * the reader's language. Read loosely so the panel does not wait on those
   * fields' generated types. */
  words(): ExplainWords | null {
    const e = this.explanation() as unknown as ExplainFacts | null;
    if (!e) return null;
    const definition = (this.lang.isRtl() ? e.definition_ar : e.definition_en) || e.definition_en || null;
    return {
      definition,
      basis: e.measure_basis ?? null,
      computedAt: e.computed_at ? this.time(e.computed_at) : null,
      currency: e.currency?.code ?? null,
      glossaryTermId: e.glossary_term_id ?? null,
      lineageUrl: e.lineage_url ?? null,
    };
  }

  glossaryRoute(): string[] {
    return entityFormRoute('glossary_term');
  }

  lineageChildren(node: MetricLineageNode): MetricLineageNode[] {
    return node.children ?? [];
  }
}
