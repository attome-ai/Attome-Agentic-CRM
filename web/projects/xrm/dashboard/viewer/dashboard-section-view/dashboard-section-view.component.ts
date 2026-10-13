import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { EntityRecord } from '@attome/xrm';
import { PageWidgetResult } from '@attome/xrm/dashboard/data';
import { DashboardWidgetViewComponent } from '../dashboard-widget-view/dashboard-widget-view.component';

interface GridConfig { columns?: number; row_height?: number; gap?: number; }

function cell(widget: EntityRecord, field: string, fallback = 0): number {
  const value = Number(widget.data[field] ?? fallback);
  return Number.isFinite(value) ? value : fallback;
}

/**
 * One `dashboard_section`, rendered as a CSS grid of widgets — mirrors
 * `layout.rs`'s own `section_tree` shape (the publish-snapshot builder), just
 * rendering instead of serializing. Part of the M26 Phase 2 backlog's minimal
 * dashboard viewer (see `DashboardWidgetViewComponent`'s doc comment for the
 * overall scope decision).
 *
 * Widgets within this section use real grid positioning — `grid_col`/
 * `grid_row`/spans on a CSS Grid, a field this crate's seed already populates
 * and the editor already writes.
 *
 * **Responsive model (Dashboard 10/10 Phase 4.2).** The section is a size
 * container. At 900px and wider it is the authored grid; below that it
 * collapses to two columns (a widget wider than half the authored grid takes
 * both), and below 600px to one. Collapsed layouts flow in reading order and
 * keep each widget's authored height. The breakpoints measure the section,
 * not the window, so a dashboard embedded in a narrow form collapses too.
 * `responsive_overrides` is not read: nothing authors it and it has no
 * defined shape.
 *
 * M26 R-15: the editor produces exactly one root grid section per page —
 * `DashboardViewerComponent::canvasSection` always forces
 * `layout_mode: 'grid'` and passes no other sections — so this component
 * used to carry two branches (a `'freeform'` `layout_mode` render path, and
 * child-section recursion over an `allSections` input) that no real caller
 * could ever reach. Both were deleted rather than kept "just in case"; re-add
 * a nested-section render path if/when an editor actually produces one.
 */
@Component({
  selector:   'attome-dashboard-section-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DashboardWidgetViewComponent],
  styleUrls:  ['./dashboard-section-view.component.css'],
  templateUrl: './dashboard-section-view.component.html',
})
export class DashboardSectionViewComponent {
  readonly section          = input.required<EntityRecord>();
  readonly widgetsBySection = input.required<ReadonlyMap<string, EntityRecord[]>>();
  /** The dashboard these widgets belong to; every widget's data comes from
   * its server-side data route (D-522). */
  readonly dashboardId = input<string | null>(null);
  /** Execute the draft (the editor's preview) instead of the published version. */
  readonly preview = input(false);
  /** The viewer's page-batch results by widget id; `null` while the page
   * request is in flight. */
  readonly results = input<ReadonlyMap<string, PageWidgetResult> | null>(null);
  /** Parameter values, for a widget that re-queries on its own (cross-filter). */
  readonly parameters = input<Record<string, unknown>>({});

  /** A widget's batch result, `null` while loading. */
  resultFor(widgetId: string): PageWidgetResult | null {
    return this.results()?.get(widgetId) ?? null;
  }

  /** In reading order — authored row, then column — so the DOM, the tab
   * order and the collapsed layouts all follow what the author laid out. */
  readonly widgets = computed(() => [...(this.widgetsBySection().get(this.section().id) ?? [])]
    .sort((a, b) => cell(a, 'grid_row') - cell(b, 'grid_row') || cell(a, 'grid_col') - cell(b, 'grid_col')));

  /** The authored grid, as custom properties the stylesheet's breakpoints read. */
  readonly gridStyle = computed<Record<string, string>>(() => {
    const cfg = this.parseJson<GridConfig>(this.section().data['grid_config']) ?? {};
    return {
      '--xdv-columns':    String(cfg.columns ?? 12),
      '--xdv-row-height': `${cfg.row_height ?? 100}px`,
      '--xdv-gap':        `${cfg.gap ?? 12}px`,
    };
  });

  /** A widget's authored placement, plus its span in the two-column layout:
   * wider than half the authored grid takes both columns. */
  widgetStyle(widget: EntityRecord): Record<string, string> {
    const columns = this.parseJson<GridConfig>(this.section().data['grid_config'])?.columns ?? 12;
    const colSpan = Math.max(1, cell(widget, 'grid_col_span', 1));
    return {
      '--xdv-col':      String(cell(widget, 'grid_col') + 1),
      '--xdv-row':      String(cell(widget, 'grid_row') + 1),
      '--xdv-col-span': String(colSpan),
      '--xdv-row-span': String(Math.max(1, cell(widget, 'grid_row_span', 1))),
      '--xdv-md-span':  colSpan > columns / 2 ? '2' : '1',
    };
  }

  private parseJson<T>(value: unknown): T | null {
    if (typeof value !== 'string' || !value.trim()) return null;
    try { return JSON.parse(value) as T; } catch { return null; }
  }
}
