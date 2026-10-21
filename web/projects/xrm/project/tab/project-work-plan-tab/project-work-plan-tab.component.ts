import { ChangeDetectionStrategy, Component, OnChanges, computed, inject, input, signal } from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { ApiError, TranslatePipe } from '@attome/base';
import { ProjectService, ProjectSummary, WorkItemRollupRow } from '../../services/project.service';
import { ProjectGanttComponent } from '../project-gantt/project-gantt.component';

const STATUS_LABEL: Record<string, string> = {
  not_started: 'Not started', in_progress: 'In progress', done: 'Done', blocked: 'Blocked',
};

/**
 * The "Work plan" tab — WBS tree view only for this build (Timeline/Board are
 * deferred per merry-splashing-whistle.md's scope answer). Every number here
 * comes from `GET /project/{id}/work-items/rollup`, a flat, depth-bounded list
 * (same envelope convention as `entity_crud/hierarchy.rs`'s ancestor/descendant
 * walk) that this component turns into a tree client-side, structurally the
 * same way `DocumentFolderBrowserComponent` turns a flat folder list into its
 * sidebar tree: a `Map<parent_id, children[]>` plus an `expandedItems` set.
 */
@Component({
  selector: 'attome-project-work-plan-tab',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgTemplateOutlet, TranslatePipe, ProjectGanttComponent],
  styleUrls: ['./project-work-plan-tab.component.css'],
  templateUrl: './project-work-plan-tab.component.html',
})
export class ProjectWorkPlanTabComponent implements OnChanges {
  private readonly svc = inject(ProjectService);

  readonly projectId = input.required<string>();

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly summary = signal<ProjectSummary | null>(null);
  private readonly items = signal<WorkItemRollupRow[]>([]);
  readonly expandedItems = signal<Set<string>>(new Set());
  /** V1-T1: the WBS tree or the Gantt timeline. */
  readonly view = signal<'wbs' | 'timeline'>('wbs');

  private readonly childrenByParent = computed(() => {
    const map = new Map<string, WorkItemRollupRow[]>();
    for (const item of this.items()) {
      const key = item.parent_work_item_id ?? '';
      const list = map.get(key) ?? [];
      list.push(item);
      map.set(key, list);
    }
    // `sequence` is optional (not every work item has one set) — nulls sort
    // last rather than colliding at 0.
    for (const list of map.values()) {
      list.sort((a, b) => (a.sequence ?? Number.MAX_SAFE_INTEGER) - (b.sequence ?? Number.MAX_SAFE_INTEGER));
    }
    return map;
  });

  readonly rootItems = computed(() => this.childrenByParent().get('') ?? []);

  ngOnChanges(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const id = this.projectId();
    this.svc.getWorkItemRollup(id).subscribe({
      next: res => { this.items.set(res.items); this.finishIfReady(); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
    this.svc.getSummary(id).subscribe({
      next: s => { this.summary.set(s); this.finishIfReady(); },
      error: () => { /* summary is supplementary here; the WBS tree still renders without it */ },
    });
  }

  private finishIfReady(): void {
    this.loading.set(false);
  }

  childrenOf(parentId: string): WorkItemRollupRow[] {
    return this.childrenByParent().get(parentId) ?? [];
  }

  hasChildren(parentId: string): boolean {
    return (this.childrenByParent().get(parentId) ?? []).length > 0;
  }

  isExpanded(id: string): boolean { return this.expandedItems().has(id); }

  toggleExpand(id: string): void {
    const next = new Set(this.expandedItems());
    if (next.has(id)) next.delete(id); else next.add(id);
    this.expandedItems.set(next);
  }

  expandAll(): void {
    this.expandedItems.set(new Set(this.items().map(i => i.id)));
  }

  collapseAll(): void {
    this.expandedItems.set(new Set());
  }

  statusLabel(status: string): string { return STATUS_LABEL[status] ?? status; }

  // The rollup endpoint returns owner_id only (no name-resolution join yet) —
  // show a short id rather than nothing, until that's wired up.
  shortId(id: string): string { return id.slice(0, 8); }

  formatDate(value: string | null): string {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit' }).format(date);
  }

  forecastCaption(s: ProjectSummary): string {
    if (s.forecast_buffer_days == null) return '';
    return s.forecast_buffer_days >= 0
      ? `${s.forecast_buffer_days} days buffer`
      : `${Math.abs(s.forecast_buffer_days)} days over`;
  }
}
