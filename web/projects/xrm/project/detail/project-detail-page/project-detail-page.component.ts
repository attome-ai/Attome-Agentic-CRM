import { NgComponentOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnChanges, Type, computed, inject, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ApiError } from '@attome/base';
import {
  EntityRecordResponse, EntityRouteRegistry, EntityService, RelatedGridComponent, entityListRoute,
} from '@attome/xrm/core/entity';
import { MissingFormPageComponent } from '@attome/xrm/core/entity/dispatcher';
import { ProjectChangeRequestsTabComponent } from '../../tab/project-change-requests-tab/project-change-requests-tab.component';
import { ProjectOverviewTabComponent } from '../../tab/project-overview-tab/project-overview-tab.component';
import { ProjectWorkPlanTabComponent } from '../../tab/project-work-plan-tab/project-work-plan-tab.component';

const PROJECT_ENTITY = 'attome_project';

type TabKey = 'overview' | 'work_plan' | 'deliverables' | 'issues' | 'change_requests' | 'communications' | 'team' | 'settings';

interface TabDef { key: TabKey; label: string; icon: string; }

const TABS: TabDef[] = [
  { key: 'overview',         label: 'Overview',         icon: 'la-th-large' },
  { key: 'work_plan',        label: 'Work plan',        icon: 'la-list-ul' },
  { key: 'deliverables',     label: 'Deliverables',     icon: 'la-clipboard-check' },
  { key: 'issues',           label: 'Issues & Risks',   icon: 'la-exclamation-triangle' },
  { key: 'change_requests',  label: 'Change Requests',  icon: 'la-sync' },
  { key: 'communications',   label: 'Communications',   icon: 'la-envelope' },
  { key: 'team',             label: 'Team',              icon: 'la-users' },
  { key: 'settings',         label: 'Settings',         icon: 'la-cog' },
];

/**
 * The tabbed Project detail page — the one screen in the plan
 * (merry-splashing-whistle.md) that generic entity list/form pages cannot
 * express. Overview and Work plan are bespoke (backed by `attome-project`'s
 * read-only aggregation + baseline-capture endpoints); Deliverables/Issues &
 * Risks/Communications/Team are each a plain `<xrm-related-grid>` filtered by
 * `project_id`; Change Requests adds a "Pending Decisions" Approve/Reject
 * panel (`ProjectChangeRequestsTabComponent`, `POST /project/change-request/
 * {id}/approve|reject`) above that same grid; Settings embeds `attome_project`'s
 * own registered form (`ProjectFormComponent` in `@attome/xrm/project/
 * registration`), resolved through `EntityRouteRegistry` so this page does not
 * statically pull every project form into its chunk — there is no generic
 * form any more (FORMS-IN-CODE-PLAN.md §6 step 2). This is the first tab-strip in the
 * codebase (none existed to reuse), so it's a local, self-contained pattern
 * rather than a new shared design-system component.
 */
@Component({
  selector: 'attome-project-detail-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    NgComponentOutlet,
    RelatedGridComponent,
    ProjectOverviewTabComponent,
    ProjectWorkPlanTabComponent,
    ProjectChangeRequestsTabComponent,
  ],
  styleUrls: ['./project-detail-page.component.css'],
  templateUrl: './project-detail-page.component.html',
})
export class ProjectDetailPageComponent implements OnChanges {
  private readonly entitySvc = inject(EntityService);
  private readonly router = inject(Router);
  private readonly registry = inject(EntityRouteRegistry);

  readonly PROJECT_ENTITY = PROJECT_ENTITY;
  readonly tabs = TABS;

  readonly id = input.required<string>();

  readonly record = signal<EntityRecordResponse | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly selectedTab = signal<TabKey>('overview');

  /** The Settings tab's form: `attome_project`'s registered form once its lazy
   * loader has run, the missing-form page if none is registered, `null`
   * while the loader is in flight. */
  readonly settingsForm = computed<Type<unknown> | null>(() => {
    if (this.registry.isPending(PROJECT_ENTITY)) return null;
    return this.registry.get(PROJECT_ENTITY)?.formComponent ?? MissingFormPageComponent;
  });
  readonly settingsInputs = computed(() => ({ name: PROJECT_ENTITY, id: this.id() }));

  constructor() {
    this.registry.ensureLoaded(PROJECT_ENTITY);
  }

  ngOnChanges(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.entitySvc.get(PROJECT_ENTITY, this.id()).subscribe({
      next: r => { this.record.set(r); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  selectTab(key: TabKey): void { this.selectedTab.set(key); }

  goBack(): void { void this.router.navigate(entityListRoute(PROJECT_ENTITY)); }

  display(r: EntityRecordResponse, field: string): string {
    const value = r.data[field];
    return value == null || value === '' ? '—' : String(value);
  }

  lookupName(r: EntityRecordResponse, field: string): string | null {
    return r.lookups?.[field]?.name ?? null;
  }

  deliveryTypeLabel(r: EntityRecordResponse): string {
    const value = r.data['delivery_type'];
    if (value == null || value === '') return '—';
    return String(value).split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(' ');
  }
}
