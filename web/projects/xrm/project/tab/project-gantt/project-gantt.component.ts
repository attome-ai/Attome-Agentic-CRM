import { ChangeDetectionStrategy, Component, OnChanges, computed, inject, input, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';
import { GanttView, ProjectService } from '../../services/project.service';

const DAY_MS = 24 * 60 * 60 * 1000;

/** One drawn bar. */
export interface GanttBar {
  id: string;
  name: string;
  row: number;
  /** Days from the chart's first day. */
  start: number;
  length: number;
  critical: boolean;
  milestone: boolean;
  baselineStart: number | null;
  baselineLength: number | null;
}

/** One drawn dependency, from the end (or start) of one bar to another. */
export interface GanttLink {
  fromRow: number;
  fromDay: number;
  toRow: number;
  toDay: number;
  critical: boolean;
}

export interface GanttLayout {
  /** The chart's first day (UTC midnight), as epoch milliseconds. */
  origin: number;
  days: number;
  bars: GanttBar[];
  links: GanttLink[];
}

function day(value: string | null | undefined): number | null {
  if (!value) return null;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  return Math.floor(t / DAY_MS) * DAY_MS;
}

/**
 * V1-T1: lays a project's dated work items out as bars, one row each in
 * plan order, with the baseline under each bar and a link per dependency.
 * Items without dates are left out. Pure, so a spec checks it without a
 * browser.
 */
export function layoutGantt(view: GanttView): GanttLayout {
  const dated = view.items
    .map(item => ({ item, start: day(item.start_date), due: day(item.due_date) }))
    .filter(d => d.start !== null || d.due !== null)
    .map(d => ({ item: d.item, start: (d.start ?? d.due) as number, due: Math.max(d.due ?? d.start as number, d.start ?? 0) }));
  const baseline = new Map((view.baseline?.items ?? []).map(b => [b.work_item_id, b]));
  const all: number[] = [];
  for (const d of dated) { all.push(d.start, d.due); }
  for (const b of baseline.values()) {
    const s = day(b.planned_start); const e = day(b.planned_due);
    if (s !== null) all.push(s);
    if (e !== null) all.push(e);
  }
  if (all.length === 0) return { origin: 0, days: 0, bars: [], links: [] };
  const origin = Math.min(...all);
  const end = Math.max(...all);
  const rowOf = new Map<string, number>();
  const bars: GanttBar[] = dated.map((d, row) => {
    rowOf.set(d.item.id, row);
    const b = baseline.get(d.item.id);
    const bs = day(b?.planned_start); const be = day(b?.planned_due);
    return {
      id: d.item.id,
      name: d.item.name,
      row,
      start: (d.start - origin) / DAY_MS,
      length: Math.max((d.due - d.start) / DAY_MS, 0),
      critical: d.item.is_critical_path === true,
      milestone: d.due === d.start,
      baselineStart: bs !== null ? (bs - origin) / DAY_MS : null,
      baselineLength: bs !== null && be !== null ? Math.max((be - bs) / DAY_MS, 0) : null,
    };
  });
  const barOf = new Map(bars.map(b => [b.id, b]));
  const links: GanttLink[] = [];
  for (const dep of view.dependencies) {
    const from = barOf.get(dep.predecessor_id);
    const to = barOf.get(dep.successor_id);
    if (!from || !to) continue;
    const fromEnd = dep.dependency_type === 'finish_to_start' || dep.dependency_type === 'finish_to_finish';
    const toEnd = dep.dependency_type === 'finish_to_finish' || dep.dependency_type === 'start_to_finish';
    links.push({
      fromRow: from.row,
      fromDay: fromEnd ? from.start + from.length : from.start,
      toRow: to.row,
      toDay: toEnd ? to.start + to.length : to.start,
      critical: from.critical && to.critical,
    });
  }
  return { origin, days: (end - origin) / DAY_MS + 1, bars, links };
}

/**
 * V1-T1: the project Gantt chart — bars over a day scale, the critical
 * path marked, the latest baseline as a thin bar under each item and the
 * dependencies as links. The time scale reads left to right in both
 * languages, as printed plans do.
 */
@Component({
  selector: 'attome-project-gantt',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styles: `
    :host { display: block; }
    .gantt-state { margin: 0; padding-block: 16px; padding-inline: 20px; font-size: 13px;
                   color: var(--color-text-secondary, #94a3b8); }
    .gantt-legend { display: flex; gap: 16px; padding-block: 8px; padding-inline: 20px; font-size: 12px;
                    color: var(--color-text-secondary, #94a3b8); }
    .gantt-key { display: inline-block; inline-size: 14px; block-size: 8px; border-radius: 2px;
                 margin-inline-end: 6px; vertical-align: middle; }
    .gantt-key-planned { background: var(--color-accent, #8b5cf6); }
    .gantt-key-critical { background: var(--color-danger, #ef4444); }
    .gantt-key-baseline { background: var(--color-text-secondary, #94a3b8); block-size: 3px; }
    .gantt-scroll { overflow-x: auto; }
    .gantt-name { font-size: 12px; fill: var(--color-text-primary, #e5eefc); }
    .gantt-bar { fill: var(--color-accent, #8b5cf6); }
    .gantt-bar-critical { fill: var(--color-danger, #ef4444); }
    .gantt-baseline { fill: var(--color-text-secondary, #94a3b8); }
    .gantt-link { stroke: var(--color-text-secondary, #94a3b8); stroke-width: 1; fill: none; }
    .gantt-link-critical { stroke: var(--color-danger, #ef4444); }
    .gantt-grid { stroke: var(--color-border, #24324d); stroke-width: 1; }
  `,
  template: `
    @if (loading()) {
      <p class="gantt-state">{{ 'projectGantt.loading' | translate }}</p>
    } @else if (error()) {
      <p class="gantt-state">{{ error() }}</p>
    } @else if (layout().bars.length === 0) {
      <p class="gantt-state" data-gantt-empty>{{ 'projectGantt.empty' | translate }}</p>
    } @else {
      <div class="gantt-legend">
        <span><span class="gantt-key gantt-key-planned"></span>{{ 'projectGantt.planned' | translate }}</span>
        <span><span class="gantt-key gantt-key-critical"></span>{{ 'projectGantt.critical' | translate }}</span>
        <span><span class="gantt-key gantt-key-baseline"></span>{{ baselineLabel() | translate }}</span>
      </div>
      <div class="gantt-scroll" dir="ltr">
        <svg [attr.width]="width()" [attr.height]="height()" role="img"
             [attr.aria-label]="'projectGantt.title' | translate" data-gantt>
          @for (bar of layout().bars; track bar.id) {
            <line class="gantt-grid" x1="0" [attr.y1]="rowY(bar.row) + rowHeight" [attr.x2]="width()"
                  [attr.y2]="rowY(bar.row) + rowHeight" />
            <text class="gantt-name" x="8" [attr.y]="rowY(bar.row) + 18">{{ bar.name }}</text>
            @if (bar.baselineStart !== null) {
              <rect class="gantt-baseline" [attr.x]="dayX(bar.baselineStart)" [attr.y]="rowY(bar.row) + 24"
                    [attr.width]="span(bar.baselineLength ?? 0)" height="3" />
            }
            <rect [class]="bar.critical ? 'gantt-bar gantt-bar-critical' : 'gantt-bar'"
                  [attr.x]="dayX(bar.start)" [attr.y]="rowY(bar.row) + 8" [attr.width]="span(bar.length)"
                  height="14" rx="3" [attr.data-gantt-bar]="bar.id" />
          }
          @for (link of layout().links; track $index) {
            <path [class]="link.critical ? 'gantt-link gantt-link-critical' : 'gantt-link'"
                  [attr.d]="linkPath(link.fromRow, link.fromDay, link.toRow, link.toDay)" />
          }
        </svg>
      </div>
    }
  `,
})
export class ProjectGanttComponent implements OnChanges {
  private readonly svc = inject(ProjectService);

  readonly projectId = input.required<string>();

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  private readonly view = signal<GanttView | null>(null);

  readonly dayWidth = 24;
  readonly rowHeight = 32;
  readonly labelWidth = 220;

  readonly layout = computed(() => {
    const v = this.view();
    return v ? layoutGantt(v) : { origin: 0, days: 0, bars: [], links: [] };
  });
  readonly width = computed(() => this.labelWidth + Math.max(this.layout().days, 1) * this.dayWidth + 16);
  readonly height = computed(() => this.layout().bars.length * this.rowHeight + 8);
  readonly baselineLabel = computed(() =>
    this.view()?.baseline ? 'projectGantt.baseline' : 'projectGantt.noBaseline');

  ngOnChanges(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getGantt(this.projectId()).subscribe({
      next: v => { this.view.set(v); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  rowY(row: number): number { return row * this.rowHeight; }

  dayX(days: number): number { return this.labelWidth + days * this.dayWidth; }

  /** A bar's width; a milestone keeps a visible sliver. */
  span(days: number): number { return Math.max(days * this.dayWidth, 4); }

  linkPath(fromRow: number, fromDay: number, toRow: number, toDay: number): string {
    const x1 = this.dayX(fromDay);
    const y1 = this.rowY(fromRow) + 15;
    const x2 = this.dayX(toDay);
    const y2 = this.rowY(toRow) + 15;
    const mid = x1 + 8;
    return `M ${x1} ${y1} H ${mid} V ${y2} H ${x2}`;
  }
}
