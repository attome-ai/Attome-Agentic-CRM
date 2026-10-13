import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { WidgetTypeDescriptor } from '../page-editor.types';

interface CategoryGroup {
  category: string;
  types:    WidgetTypeDescriptor[];
}

const WIDGET_TYPE_ICONS: Record<string, string> = {
  kpi_card: 'la-hashtag',
  metric_list: 'la-list-ol',
  progress: 'la-tasks',
  line_chart: 'la-chart-line',
  bar_chart: 'la-chart-bar',
  column_chart: 'la-chart-bar',
  area_chart: 'la-water',
  pie_chart: 'la-chart-pie',
  donut_chart: 'la-circle-notch',
  funnel_chart: 'la-filter',
  table: 'la-table',
  top_list: 'la-list',
  leaderboard: 'la-trophy',
  text: 'la-heading',
  header: 'la-heading',
  image: 'la-image',
  gauge_chart: 'la-tachometer-alt',
};

/**
 * The "Add widget" panel — a searchable, category-filtered grid of
 * `WidgetTypeDescriptor`s. Signal inputs/outputs only, no service
 * injection (R-11): every list this renders is derived from the single
 * `widgetTypes` input, and every gesture (click-to-add, drag-to-canvas,
 * close) is reported upward through an output rather than mutating
 * anything owned by `PageEditorComponent` directly.
 *
 * HTML5 drag-and-drop payload (`dataTransfer.setData`/`setDragImage`) is
 * set up here, at the drag's actual origin element, but *which* type is
 * currently being dragged still has to reach the canvas before `drop`
 * fires (`dataTransfer.getData` is unreadable during `dragover` by spec) —
 * `dragStart`/`dragEnd` report that up so `PageEditorComponent` can track it
 * for the live drop-target ghost.
 */
@Component({
  selector:   'xrm-widget-palette',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  styleUrls:  ['./widget-palette.component.css'],
  templateUrl: './widget-palette.component.html',
})
export class WidgetPaletteComponent {
  readonly widgetTypes = input<WidgetTypeDescriptor[]>([]);

  readonly add       = output<string>();
  readonly dragStart  = output<string>();
  readonly dragEnd    = output<void>();
  readonly closePalette = output<void>();

  readonly search         = signal('');
  readonly categoryFilter = signal('all');

  readonly categories = computed<string[]>(() => {
    const cats = new Set(this.widgetTypes().map(t => t.category));
    return ['all', ...[...cats].sort()];
  });

  readonly groups = computed<CategoryGroup[]>(() => {
    const term = this.search().trim().toLowerCase();
    const cat = this.categoryFilter();
    const filtered = this.widgetTypes().filter(t =>
      (cat === 'all' || t.category === cat) &&
      (!term || t.display_name.toLowerCase().includes(term) || t.type_id.toLowerCase().includes(term)));
    const byCategory = new Map<string, WidgetTypeDescriptor[]>();
    for (const t of filtered) {
      const list = byCategory.get(t.category) ?? [];
      list.push(t);
      byCategory.set(t.category, list);
    }
    return [...byCategory.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([category, types]) => ({ category, types }));
  });

  onSearchInput(value: string): void {
    this.search.set(value);
  }

  typeIcon(typeId: string): string {
    return WIDGET_TYPE_ICONS[typeId] ?? 'la-cube';
  }

  onDragStart(ev: DragEvent, typeId: string): void {
    ev.dataTransfer?.setData('text/plain', typeId);
    if (ev.dataTransfer) {
      ev.dataTransfer.effectAllowed = 'copy';
      // Pin the native drag-ghost's top-left corner to the cursor (offset
      // 0,0), regardless of where inside the pill the gesture actually
      // grabbed it — see `PageEditorComponent`'s `dropPositionFromEvent`
      // doc comment for why that makes the drop math offset-free.
      ev.dataTransfer.setDragImage(ev.currentTarget as HTMLElement, 0, 0);
    }
    this.dragStart.emit(typeId);
  }

  onDragEnd(): void {
    this.dragEnd.emit();
  }
}
