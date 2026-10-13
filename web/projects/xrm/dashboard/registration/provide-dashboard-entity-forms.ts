import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { DashboardEditorComponent } from './dashboard/form/dashboard-editor/dashboard-editor.component';
import { dashboardActions } from './dashboard.actions';
// Relative import, not cross-entry-point — `PageEditorComponent` now lives
// under this same `registration` entry point (`page-editor/`, moved here by
// R-10 step 3: it *is* the `dashboard_page` form override, so this is its
// rightful home rather than `@attome/xrm/dashboard`'s own barrel).
import { PageEditorComponent } from './page-editor/page-editor.component';

// 'attome_dashboard' -> the stock generic list (the M26 gap-fill's own Template
// Gallery is the more useful landing page for templates specifically,
// registered as its own literal route in xrm-shell.routes.ts, not through
// this registry) plus a bulk "Archive selected" action (M26 Phase 2
// backlog), and a bespoke form — a page/section/widget tree has no business
// rendering through the generic single-record field form, same reasoning as
// `WorkflowDefinitionFormComponent`'s own doc comment.
//
// 'dashboard_page' -> same reasoning, one level down: a page's own
// section/widget layout is what `PageEditorComponent` (the visual
// drag-and-drop builder) is for, not the generic field form. Before this
// override, navigating to a page's form (from the flat "Pages" sidebar list,
// or any other generic-list link) showed only the page's own row of scalar
// fields — name/slug/background/etc — with no way to reach the actual layout
// editor short of going through a specific Dashboard's own Pages tab first.
// `PageEditorComponent` reads the dispatcher's `id` input (see that
// component's own doc comment) and derives `dashboardId` from the loaded
// page record's `dashboard_id` when reached this way, since the override
// contract carries no second id for it. Create mode (`id` null, e.g. the
// generic list's own "+New") is intentionally NOT supported here — a page
// has no layout to build until it exists, and it must be born under a
// specific dashboard; `DashboardEditorComponent`'s own Pages tab
// (`addPage()`) already owns page creation, matching how the layout tree's
// other two levels (`dashboard_section`/`dashboard_widget`) have no
// independent creation path either.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerDashboardEntityForms(registry: EntityRouteRegistry): void {
  registry.register('attome_dashboard', {
    formComponent: DashboardEditorComponent,
    selectionActions: dashboardActions(),
  });
  registry.register('dashboard_page', {
    formComponent: PageEditorComponent,
  });

  // The layout-tree and decision/scenario/metric entities' forms register
  // from `@attome/xrm/dashboard/layout-forms` and
  // `@attome/xrm/dashboard/modeling-forms`, each loaded on its own.
}
