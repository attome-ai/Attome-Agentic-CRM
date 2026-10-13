import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityRecord } from '@attome/xrm';
import {
  XrmBaseFormComponent, EngineFormBase, XrmTabDirective, entityFormRoute, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { RecordSharesComponent } from '@attome/xrm/core/security';
import { DashboardService } from '@attome/xrm/dashboard/data';
import type { DashboardLifecycleAction, HealthCheckResponse, PublishResponse } from '@attome/xrm/dashboard/data';

interface LifecycleAction {
  action: DashboardLifecycleAction;
  label:  string; // translation key, resolved with `| translate` in the template
  icon:   string;
  style:  'primary' | 'secondary' | 'danger';
}

const UNPUBLISH: LifecycleAction =
  { action: 'unpublish', label: 'dashboardForm.actionUnpublish', icon: 'la-eye-slash', style: 'secondary' };

/** One transition button set per `lifecycle_status` value — mirrors
 * `attome-dashboard`'s own `lifecycle.rs` state machine. Since D-521
 * `lifecycle_status` describes the **working copy** and
 * `published_version_id` alone decides what viewers see: `start-revision`
 * returns a published dashboard to draft without taking the live version
 * offline, and `unpublish` (which clears the live version) is offered from
 * any status while one is live — see `lifecycleActions`. `clone` is offered
 * from every status, appended separately in the template. */
const LIFECYCLE_TRANSITIONS: Record<string, LifecycleAction[]> = {
  draft: [
    { action: 'submit-review', label: 'dashboardForm.actionSubmitReview', icon: 'la-paper-plane', style: 'primary' },
  ],
  review: [
    { action: 'approve', label: 'dashboardForm.actionApprove', icon: 'la-check', style: 'primary' },
    { action: 'reject',  label: 'dashboardForm.actionReject',  icon: 'la-times', style: 'secondary' },
  ],
  approved: [
    { action: 'publish', label: 'dashboardForm.actionPublish', icon: 'la-globe', style: 'primary' },
  ],
  published: [
    { action: 'start-revision', label: 'dashboardForm.actionStartRevision', icon: 'la-pencil-ruler', style: 'primary' },
    UNPUBLISH,
    { action: 'archive',   label: 'dashboardForm.actionArchive',   icon: 'la-archive',   style: 'danger' },
  ],
  archived: [],
};

/**
 * Form override for `attome_dashboard` — a page/section/widget tree has no
 * business rendering through the generic single-record field form, same
 * reasoning as `WorkflowDefinitionFormComponent`'s own doc comment. The
 * Pages tab here only manages the page list itself (add/delete); each
 * page's own layout is edited in the visual Page Editor
 * (`PageEditorComponent`, reached via "Edit Layout" per row).
 *
 * D-520 (Dashboard 10/10 Phase 1.1): a page belongs to exactly one dashboard
 * through `dashboard_page.dashboard_id`. The page list comes from the
 * draft tree route and "Add page" calls the pages route, which creates the
 * page and its root grid section in one transaction.
 */
@Component({
  selector:   'attome-dashboard-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [ReactiveFormsModule, FormsModule, TranslatePipe, DatePipe, RouterLink, RecordSharesComponent,
               XrmBaseFormComponent, XrmTabDirective],
  styleUrls:  ['../../../../../styles/xrm-form.css', './dashboard-editor.component.css'],
  templateUrl: './dashboard-editor.component.html',
})
export class DashboardEditorComponent extends EngineFormBase {
  protected override defineTabs(): XrmFormTabDef[] {
    // The base form prints labels as given, so the catalog keys resolve here.
    const t = (key: string) => this.lang.translate(key);
    return [
      { id: 'general', label: t('dashboard.editor.tabGeneral'), icon: 'las la-home' },
      { id: 'pages', label: t('dashboard.editor.tabPages'), icon: 'las la-th-large' },
      { id: 'versions', label: t('dashboard.editor.tabVersions'), icon: 'las la-history' },
      { id: 'sharing', label: t('dashboard.editor.tabSharing'), icon: 'las la-user-shield' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), t),
    ];
  }

  private readonly dashboardApi = inject(DashboardService);
  private readonly dialogService = inject(DialogService);
  private readonly lang = inject(LangService);

  // ── Pages ─────────────────────────────────────────────────────────────────
  readonly pages        = signal<EntityRecord[]>([]);
  readonly pagesLoading = signal(false);
  readonly newPageName  = signal('');
  readonly addingPage   = signal(false);

  // ── Lifecycle ────────────────────────────────────────────────────────────
  readonly lifecycleBusy  = signal(false);
  readonly lifecycleError = signal<string | null>(null);
  /** Set when a publish or rollback was only submitted for four-eyes
   * approval (202) — shown as a banner instead of a silent reload, since
   * nothing changed yet. */
  readonly approvalPending = signal(false);

  readonly currentStatus = computed(() =>
    (this.form().get('lifecycle_status')?.value as string | null) || 'draft');

  /** The live version's id (`attome_dashboard.published_version_id`, D-521), or
   * `null` when nothing is live. */
  readonly liveVersionId = computed(() => {
    // The form control when the schema renders one, otherwise the loaded
    // record (`form()` is replaced on every load, so this re-evaluates).
    const value = (this.form().get('published_version_id')?.value
      ?? this.record?.data['published_version_id']) as unknown;
    return typeof value === 'string' && value ? value : null;
  });

  readonly lifecycleActions = computed<LifecycleAction[]>(() => {
    const actions = LIFECYCLE_TRANSITIONS[this.currentStatus()] ?? [];
    const offersUnpublish = actions.some(a => a.action === 'unpublish');
    return this.liveVersionId() && !offersUnpublish && this.currentStatus() !== 'archived'
      ? [...actions, UNPUBLISH]
      : actions;
  });

  // ── Health check ─────────────────────────────────────────────────────────
  readonly healthCheckRunning = signal(false);
  /** Only ever set for the all-clear result — a broken result goes through
   * `DialogService.error` instead. */
  readonly healthCheckResult = signal<HealthCheckResponse | null>(null);

  // ── Versions ─────────────────────────────────────────────────────────────
  readonly versions        = signal<EntityRecord[]>([]);
  readonly versionsLoading = signal(false);
  readonly restoringId     = signal<string | null>(null);
  readonly activatingId    = signal<string | null>(null);

  private loadedChildrenForId: string | null = null;

  constructor() {
    super();
    // Child data needs a saved dashboard id, which arrives asynchronously —
    // an effect re-evaluates once `loading` flips false. Guarded so it fires
    // exactly once per record.
    effect(() => {
      const id = this.id();
      const stillLoading = this.loading();
      if (id && !stillLoading && this.loadedChildrenForId !== id) {
        untracked(() => {
          this.loadedChildrenForId = id;
          this.loadPages();
          this.loadVersions();
        });
      }
    });
  }

  // ── Pages ─────────────────────────────────────────────────────────────────

  /** Pages come from the draft tree route (D-520) — every page this
   * dashboard owns through `dashboard_id`, already ordered by `sequence`. */
  loadPages(): void {
    const id = this.id();
    if (!id) return;
    this.pagesLoading.set(true);
    this.dashboardApi.loadTree(id).subscribe({
      next: tree => {
        this.pages.set(tree.pages);
        this.pagesLoading.set(false);
      },
      error: (e: ApiError) => {
        this.pagesLoading.set(false);
        this.lifecycleError.set(e.message);
      },
    });
  }

  addPage(): void {
    const id = this.id();
    const name = this.newPageName().trim();
    if (!id || !name) return;
    this.addingPage.set(true);
    this.dashboardApi.createPage(id, {
      name,
      sequence:   this.pages().length * 10,
      is_visible: true,
    }).subscribe({
      next: () => {
        this.addingPage.set(false);
        this.newPageName.set('');
        this.loadPages();
      },
      error: (e: ApiError) => {
        this.addingPage.set(false);
        this.lifecycleError.set(e.message);
      },
    });
  }

  /** Deletes the page record — it belongs to this dashboard only (D-520). */
  deletePage(pageId: string): void {
    this.svc.delete('dashboard_page', pageId).subscribe({
      next: () => this.loadPages(),
      error: (e: ApiError) => this.lifecycleError.set(e.message),
    });
  }

  // ── Lifecycle actions ────────────────────────────────────────────────────

  runLifecycleAction(action: DashboardLifecycleAction): void {
    const id = this.id();
    if (!id) return;
    this.lifecycleBusy.set(true);
    this.lifecycleError.set(null);
    this.approvalPending.set(false);
    this.dashboardApi.transition(id, action, this.record?.row_version ?? 0).subscribe({
      next: res => {
        this.lifecycleBusy.set(false);
        if ((res as Partial<PublishResponse>).approval_pending) {
          this.approvalPending.set(true);
          return;
        }
        this.reload();
        this.loadVersions();
      },
      error: (e: ApiError) => { this.lifecycleBusy.set(false); this.lifecycleError.set(e.message); },
    });
  }

  // ── Versions ─────────────────────────────────────────────────────────────

  loadVersions(): void {
    const id = this.id();
    if (!id) return;
    this.versionsLoading.set(true);
    this.svc.list('dashboard_version', {
      filters: [{ field: 'dashboard_id', op: 'eq', value: id }],
      sorts:   [{ field: 'version_number', dir: 'desc' }],
      limit:   50,
    }).subscribe({
      next: res => { this.versions.set(res.data); this.versionsLoading.set(false); },
      error: () => this.versionsLoading.set(false),
    });
  }

  /** Whether `version` is the one viewers currently see. Computed client-side
   * against `published_version_id` — version rows carry no live flag. */
  isLive(version: EntityRecord): boolean {
    return version.id === this.liveVersionId();
  }

  /** Writes the version into the working copy only (D-521) — viewers keep
   * seeing the live version until the draft is published again. */
  restoreVersion(versionId: string): void {
    const id = this.id();
    if (!id) return;
    this.restoringId.set(versionId);
    this.lifecycleError.set(null);
    this.dashboardApi.restoreVersion(id, versionId).subscribe({
      next: () => {
        this.restoringId.set(null);
        this.reload();
        // The whole page/section/widget tree may have changed underneath
        // the current page list — reload it rather than show stale rows.
        this.loadPages();
      },
      error: (e: ApiError) => {
        this.restoringId.set(null);
        this.lifecycleError.set(e.message);
      },
    });
  }

  /** Makes a stored version live again (rollback). Rides the publish
   * approval: where publishing needs four-eyes, so does this (202). */
  activateVersion(versionId: string): void {
    const id = this.id();
    if (!id) return;
    this.activatingId.set(versionId);
    this.lifecycleError.set(null);
    this.approvalPending.set(false);
    this.dashboardApi.activateVersion(id, versionId, this.record?.row_version ?? 0).subscribe({
      next: res => {
        this.activatingId.set(null);
        if (res.approval_pending) {
          this.approvalPending.set(true);
          return;
        }
        this.reload();
      },
      error: (e: ApiError) => {
        this.activatingId.set(null);
        this.lifecycleError.set(e.message);
      },
    });
  }

  runHealthCheck(): void {
    const id = this.id();
    if (!id) return;
    this.healthCheckRunning.set(true);
    this.dashboardApi.healthCheck(id).subscribe({
      next: res => {
        this.healthCheckRunning.set(false);
        // Phase 3.5: the gate's blocking issues fail the check exactly as a
        // broken reference does; warnings are shown with a passing result.
        const gateLines = res.blocking.map(issue => this.lang.translate('dashboard.editor.gateLine', {
          widget: issue.widget_id ?? issue.page_id ?? '',
          message: `${issue.message} (${issue.code})`,
        }));
        if (res.broken.length === 0 && res.blocking.length === 0) {
          this.healthCheckResult.set(res);
          return;
        }
        if (res.broken.length === 0) {
          this.dialogService.error({
            title: this.lang.translate('dashboard.editor.healthCheckTitle'),
            message: this.lang.translate('dashboard.editor.gateBlocked', { count: res.blocking.length }),
            details: gateLines.join('\n'),
          });
          return;
        }
        const details = [...gateLines, ...res.broken
          .map(b => this.lang.translate('dashboard.editor.healthCheckDetailLine', {
            widget: b.widget_name || b.widget_id,
            page: b.page_name,
            section: b.section_type,
            // `field` is `"query_id"` or `"view_id"`, `value` is the raw
            // stored value that failed to resolve (`health::BrokenWidgetRef`).
            query: b.value,
            reason: this.lang.translate(b.reason === 'not_found'
              ? 'dashboard.editor.healthCheckReasonNotFound'
              : 'dashboard.editor.healthCheckReasonInvalid'),
          }))]
          .join('\n');
        this.dialogService.error({
          title: this.lang.translate('dashboard.editor.healthCheckTitle'),
          message: this.lang.translate('dashboard.editor.healthCheckBrokenSummary', {
            brokenCount: res.broken.length,
            checked: res.checked,
          }),
          details,
        });
      },
      error: (e: ApiError) => {
        this.healthCheckRunning.set(false);
        this.lifecycleError.set(e.message);
      },
    });
  }

  cloneDashboard(): void {
    const id = this.id();
    if (!id) return;
    this.lifecycleBusy.set(true);
    this.lifecycleError.set(null);
    this.dashboardApi.clone(id).subscribe({
      next: res => {
        this.lifecycleBusy.set(false);
        this.router.navigate(entityFormRoute('attome_dashboard'), { queryParams: { id: res.id } });
      },
      error: (e: ApiError) => { this.lifecycleBusy.set(false); this.lifecycleError.set(e.message); },
    });
  }
}
