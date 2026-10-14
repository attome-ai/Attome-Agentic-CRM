import { inject } from '@angular/core';
import { Router, Routes } from '@angular/router';
import { authGuard, layerCatalogsReady } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { provideXrmEntityFormLoaders } from './attome-metadata-form-loaders';

/**
 * D-792 — the fleet console's build-time gate. `angular.json` defines it per
 * build configuration (`define`): `true` only in `development`, `false` in
 * `production`. esbuild replaces the identifier with the literal, so a
 * production build drops the `fleet` route below and never emits the
 * `@attome/xrm/fleet` chunk. Never read it from `environment.ts`: a property
 * of an imported object is not reliably folded, a `define` literal is.
 */
declare const ATTOME_FLEET_CONSOLE: boolean;

// Each `loadComponent()` below imports the specific @attome/xrm secondary
// entry point that owns the component it renders (@attome/xrm/shell,
// /entity, /admin, /query, /security, /s2s, /license, /profiler, /jobs,
// /approvals, /data-protection), never the root `@attome/xrm` barrel. The root barrel re-exports nothing
// component-level, so importing it here would pull in nothing useful; the
// point of the split is that a user hitting only `/xrm/dashboard` doesn't
// download the S2S/license/jobs/profiler admin code, and vice versa.
// `providers: [provideXrmEntityFormLoaders()]` keeps that scoped to this
// route tree's own lazily-created environment injector rather than the root
// ApplicationConfig (measured: main chunk 847kB -> 360kB when the original
// version of this registration moved out of eager bootstrap). It no longer
// statically imports every module's registration function directly — with
// ~30 registered entities that collapsed into one 658KB shared chunk, well
// past the 260KB lazy-chunk cap (scripts/chunk-budget.mjs). Each entity's
// override now loads lazily, the first time that entity is actually routed
// to — see `./attome-metadata-form-loaders.ts` and `EntityRouteRegistry`'s doc
// comment (`@attome/xrm/core/entity`) for the full mechanism.
export const xrmShellRoutes: Routes = [
  {
    path: '',
    // NGB-5.2c / D-761 — xrm's own catalog, registered where xrm mounts; the
    // guard holds an Arabic session's first xrm render until it has landed.
    providers: [
      provideXrmEntityFormLoaders(),
      provideXrmI18n(),
    ],
    canActivate: [layerCatalogsReady],
    children: [
      {
        // Listed BEFORE the empty-path block below: Angular resolves a
        // route array's children in order and takes the first structural
        // match, so 'admin' (a literal prefix) must be tried before the
        // empty-path sibling whose own last child is a bare '**' wildcard —
        // otherwise the empty-path block matches first (an empty prefix
        // always matches) and its wildcard child swallows 'admin/**' too
        // (e.g. '/xrm/admin/sidebar' was resolving as an entity lookup for
        // a bogus 'admin' logicalname instead of ever reaching here).
        path: 'admin',
        loadComponent: () => import('@attome/xrm/shell').then(m => m.ShellComponent),
        children: [
          {
            path: 'entities',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.EntityManagerComponent),
          },
          {
            // Singular + `?id=`, matching the entity form convention this
            // screen edits the metadata for (`/xrm/core/systemuser/form?id=…`).
            // `withComponentInputBinding()` (app.config.ts) binds query params
            // to component inputs just as it does route params, so
            // EntityEditorComponent's `id` input is populated either way — the
            // change here is the URL shape, not the wiring.
            path: 'entity',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.EntityEditorComponent),
          },
          {
            // Every entity's editor URL was `/xrm/admin/entities/:id` until
            // this rename, and those are in bookmarks and in the browser
            // history of anyone who used the old Item Manager. A functional
            // `redirectTo` is the only form that can move a *path* parameter
            // into a *query* parameter — the string form cannot express that.
            path: 'entities/:id',
            redirectTo: ({ params }) =>
              inject(Router).createUrlTree(['/xrm/admin/entity'], {
                queryParams: { id: params['id'] },
              }),
          },
          {
            path: 'queries',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/query').then(m => m.QueryListComponent),
          },
          {
            path: 'queries/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/query').then(m => m.QueryEditorComponent),
          },
          {
            path: 'views',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/query').then(m => m.ViewListComponent),
          },
          {
            path: 'views/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/query').then(m => m.ViewEditorComponent),
          },
          {
            path: 'sidebar',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.SidebarManagerComponent),
          },
          {
            path: 'settings',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.SystemSettingsComponent),
          },
          {
            // D-404 / M83 Phase 1.
            path: 'calendars',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.CalendarManagerComponent),
          },
          {
            // M45 Phase 2 (D-472).
            path: 'rules',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.RulesManagerComponent),
          },
          {
            // M17 (Data Migration, D-433) — source -> mapping -> dry run ->
            // approve -> run -> report, over the existing staged-import
            // mechanism and this module's migration-project/run admin API.
            path: 'migration',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/migration').then(m => m.MigrationWizardComponent),
          },
          {
            // D-432 / M13 — the duplicate-candidate steward queue.
            path: 'duplicates',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin').then(m => m.DuplicatesManagerComponent),
          },
          // Basic Units U19 — governance screens over existing admin-only
          // routes (M14 data quality, M18 data catalog, M89 change feed),
          // and U8's state-model editor (M07). Their own entry point, so the
          // `core/admin` chunk every other admin page loads does not grow.
          {
            path: 'data/quality',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/governance').then(m => m.DataQualityComponent),
          },
          {
            path: 'data/catalog',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/governance').then(m => m.DataCatalogComponent),
          },
          {
            path: 'changes',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/governance').then(m => m.ChangeFeedComponent),
          },
          {
            path: 'state-models',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/governance').then(m => m.StateModelsManagerComponent),
          },
          {
            // Solution 7 Phase 2 (D-788, design §10) — the release report.
            // `:id` is bound to the detail page's `id` input
            // (`withComponentInputBinding()`); the post-apply notification
            // links to `/admin/release-reports/{id}`, which app.routes.ts
            // redirects here. The sidebar is seeded server-side, so it has
            // no entry from this file.
            path: 'release-reports',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/release-reports').then(m => m.ReleaseReportListComponent),
          },
          {
            path: 'release-reports/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/release-reports').then(m => m.ReleaseReportDetailComponent),
          },
          {
            // The search lab (`/xrm/search/lab`). Under `search/` rather than
            // `admin/` on purpose: it runs as the logged-in caller against live
            // data and shows exactly what that caller can see, so it is a
            // diagnostic for whoever is using search — not an admin surface
            // with elevated reach. It has none.
            path: 'search/lab',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/search').then(m => m.SearchLabComponent),
          },
          {
            // D-489 — the authors' knowledge-gap queue. An admin surface
            // (routes are `Authorized<Admin>` on the backend), so it sits in
            // this `/xrm/admin/...` group rather than beside the search lab.
            path: 'knowledge/gaps',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/search').then(m => m.GapQueueComponent),
          },
          {
            // Chatbot plan C8 — per-collection knowledge coverage. Admin-only
            // on the backend (`Authorized<Admin>`), beside the gap queue.
            path: 'knowledge/coverage',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/search').then(m => m.KnowledgeCoverageComponent),
          },
          {
            // Chatbot plan C8 — the draft review queue. No route of its own:
            // it reads and writes `knowledge_data_item` through the generic
            // entity API, so the entity's own permissions decide.
            path: 'knowledge/drafts',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/search').then(m => m.DraftQueueComponent),
          },
          {
            path: 'security/whoami',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/access').then(m => m.MyAccessComponent),
          },
          {
            path: 'security/mfa',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/access').then(m => m.MfaSettingsComponent),
          },
          {
            path: 'security/field-profiles',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.FieldSecurityProfilesComponent),
          },
          {
            path: 'security',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.SecurityAdminOverviewComponent),
          },
          {
            path: 'security/role-entity-access',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.RoleEntityAccessComponent),
          },
          {
            path: 'security/users/list',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.UsersListComponent),
          },
          {
            path: 'security/users',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.UserAccessComponent),
          },
          {
            path: 'security/organizations',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.OrganizationsListComponent),
          },
          {
            path: 'security/record-shares',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.RecordSharesComponent),
          },
          {
            // Web portal administration (web portal plan Phase 13 step 6,
            // G-8/G-14): portals, users, roles and grants, erasure, export.
            path: 'portals',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/portal').then(m => m.PortalAdminComponent),
          },
          {
            path: 's2s/clients',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/s2s').then(m => m.S2sClientListComponent),
          },
          {
            path: 's2s/clients/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/s2s').then(m => m.S2sClientEditorComponent),
          },
          {
            // M92 Extension Management Phase 1 — the bundle ledger's
            // lifecycle UI: installed named bundles, pending plans, drift,
            // and the rollback action (`POST …/bundles/{name}/rollback`).
            path: 'metadata/bundles',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/bundle').then(m => m.BundleLifecycleListComponent),
          },
          {
            // M19 gap list — the dedicated audit search surface
            // (`GET /api/v1/admin/audit/search`/`/export`), same
            // "own standalone admin page, not a per-entity list override"
            // shape as s2s/clients above.
            path: 'audit/search',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/audit').then(m => m.AuditSearchComponent),
          },
          {
            // Workflows are browsed through the generic entity list now
            // (workflow_definition is a registered entity — see
            // `attome_workflow::seed`), so the old bespoke admin list is gone.
            // Kept as a redirect rather than deleted outright: the sidebar
            // seed's previous URL, bookmarks, and the definition editor's
            // breadcrumb all pointed here.
            path: 'workflow/definitions',
            pathMatch: 'full',
            redirectTo: '/xrm/workflow/definition/list',
          },
          {
            path: 'workflow/definitions/new',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/workflow').then(m => m.WorkflowCreatePageComponent),
          },
          {
            path: 'workflow/definitions/:definitionId/versions/:versionId',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/workflow').then(m => m.WorkflowGraphEditorComponent),
          },
          {
            path: 'workflow/instances',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/workflow').then(m => m.WorkflowInstanceListComponent),
          },
          {
            path: 'workflow/instances/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/workflow').then(m => m.WorkflowInstanceDetailComponent),
          },
          {
            // Project Management (merry-splashing-whistle.md) — the bespoke
            // tabbed Project detail page; every other entity in the module
            // uses the generic list/form routes below.
            //
            // MUST be 'project/console/:id', not 'project/:id': the
            // `attome_project` entity's own generic list/form resolve to
            // /xrm/project/list and /xrm/project/form (single-segment
            // logicalname -> single-segment URL, entity-url.utils.ts), and
            // those are matched by the wildcard '**' route at the bottom of
            // this array. A two-segment 'project/:id' sibling, checked
            // BEFORE that wildcard (first-structural-match order, per this
            // file's header comment), would intercept /xrm/project/list and
            // /xrm/project/form themselves (segments ['project','list'] /
            // ['project','form'] both satisfy 'project/:id' with id='list'/
            // 'form') and render the detail page for a bogus project id
            // instead of ever reaching the generic list/form. Three segments
            // sidesteps this the same way 'workflow/instances/:id' above
            // sidesteps colliding with 'workflow/definition/list' — 'console'
            // can never equal 'list'/'form'.
            path: 'project/console/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/project').then(m => m.ProjectDetailPageComponent),
          },
          {
            // M72 Resource Management — the capacity heat grid. Not
            // entity-backed (no `resources` entity to collide with the
            // '**' generic list/form wildcard below), so a single segment is
            // safe here, unlike 'project/console/:id' above.
            path: 'resources/capacity',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/project').then(m => m.ResourceCapacityPageComponent),
          },
          {
            // Timesheets (M69 §4) — a bespoke list with Submit/Approve/Reject
            // actions (`attome-project`'s timesheet.rs), not the generic
            // `project_timesheet` list/form the '**' wildcard below would
            // otherwise resolve 'project/timesheet/list' to (same
            // "logicalname -> URL" collision 'project/console/:id' above
            // avoids) — this literal route MUST sit ahead of that wildcard.
            path: 'project/timesheet/list',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/project').then(m => m.ProjectTimesheetListComponent),
          },
          {
            // Work Intake service catalog (M70, D-423) — the "New Request"
            // picker. The offering catalog's own admin CRUD (create/edit an
            // offering) has no bespoke page — it renders through the
            // generic metadata-driven list/form pages the '**' wildcard
            // below already resolves (`xrm/service/offering/list`,
            // `xrm/service/offering/form`), same as `service_work_request`/
            // `service_ticket` (D-398). Only this literal route needs to sit
            // ahead of that wildcard.
            path: 'service/new-request',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/service').then(m => m.NewRequestPickerComponent),
          },
          {
            // D-365 — Web Crawling for Knowledge Base.
            path: 'webcrawl/targets',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/webcrawl').then(m => m.WebcrawlTargetListComponent),
          },
          {
            // No `:id` — auto-selects the most-recently-crawled target
            // (see WebcrawlPageListComponent), reached from the "Website"
            // sidebar link.
            path: 'webcrawl/website',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/webcrawl').then(m => m.WebcrawlPageListComponent),
          },
          {
            path: 'webcrawl/targets/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/webcrawl').then(m => m.WebcrawlPageListComponent),
          },
          {
            // Content Management (D-NNN) — page-builder CMS.
            path: 'content/pages',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/content').then(m => m.ContentPageListComponent),
          },
          {
            path: 'content/pages/:id',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/content').then(m => m.ContentPageEditorComponent),
          },
          {
            // D-778: Module Management. The `license/` URL is kept because
            // sidebar items and bookmarks point at it; licence upload and
            // usage pages are gone.
            path: 'license/modules',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/modules').then(m => m.ModuleManagementComponent),
          },
          {
            // M95/D-430 — Feature Flags, alongside Module Management.
            path: 'license/features',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/admin/modules').then(m => m.FeatureFlagsAdminComponent),
          },
          {
            path: 'profiler',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/profiler').then(m => m.ProfilerComponent),
          },
          {
            path: 'jobs/failed',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/jobs').then(m => m.FailedJobsListComponent),
          },
          {
            path: 'approvals',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/approvals').then(m => m.ApprovalQueueListComponent),
          },
          {
            // D-421 / M10 (Approval & Governance)
            path: 'approvals/policies',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/approvals').then(m => m.ApprovalPolicyListComponent),
          },
          {
            path: 'data-protection/dsr',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/data-protection').then(m => m.DsrRequestListComponent),
          },
          {
            path: 'data-protection/legal-holds',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/data-protection').then(m => m.LegalHoldListComponent),
          },
          {
            // M15 (Data Governance, D-413) — the accountability register.
            path: 'data-protection/domains',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/data-protection').then(m => m.DomainListComponent),
          },
          {
            // `:id` is bound to `DomainReportComponent`'s `id` input via
            // `withComponentInputBinding()` (app.config.ts).
            path: 'data-protection/domains/:id',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/data-protection').then(m => m.DomainReportComponent),
          },
        ],
      },
      {
        // Comes AFTER 'admin' above (see that block's comment on ordering).
        // An empty path always matches, so this block is only reached once
        // 'admin' has already failed to match the current URL.
        path: '',
        loadComponent: () => import('@attome/xrm/shell').then(m => m.ShellComponent),
        children: [
          {
            path: 'dashboard',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/shell').then(m => m.DashboardComponent),
          },
          {
            // U15 — the approver's own inbox (any signed-in user), reached
            // from the profile menu. Two literal segments, listed ahead of
            // the entity wildcard below (same ordering rule as 'modules/:module').
            path: 'my-work/approvals',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/core/approvals').then(m => m.MyApprovalsPageComponent),
          },
          {
            // U5 (D-602) — the signed-in user's own notification
            // preferences, reached from the profile menu. Literal segments,
            // ahead of the entity wildcard below (same rule as above).
            path: 'me/notifications',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/notification').then(m => m.NotificationPreferencesPageComponent),
          },
          {
            // Shared landing page for a licensable module with no engine
            // crate/route built yet (see ModuleComingSoonComponent's own
            // doc comment). Listed before the entity wildcard below —
            // same ordering rule as 'admin' above this block: a more
            // specific literal prefix must come before a catch-all sibling.
            path: 'modules/:module',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/shell').then(m => m.ModuleComingSoonComponent),
          },
          {
            // The AI Playground (`agent.playground_complete`) — send one
            // message to an `ai_agent`'s persona and see the reply,
            // without a session. Same "runs as the logged-in caller against
            // live data, no elevated reach" placement reasoning as
            // 'search/lab' above: it goes through the ordinary
            // `/api/v1/actions/{id}/invoke` surface every action uses, not
            // an admin-gated route.
            path: 'ai/playground',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/ai').then(m => m.AiPlaygroundComponent),
          },
          {
            // N31-T2: scoped AI switches (the API refuses non-administrators).
            path: 'ai/switches',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/ai').then(m => m.AiScopeSwitchesComponent),
          },
          {
            // N31-T2: the AI status page (the API refuses non-administrators).
            path: 'ai/status',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/ai').then(m => m.AiStatusComponent),
          },
          {
            // N24-T2: AI spend against the money caps (the API refuses
            // non-administrators).
            path: 'ai/spend',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/ai').then(m => m.AiSpendComponent),
          },
          {
            // C6 (D-556) — the live-session supervisor: the screen over
            // GET /api/v1/admin/agents/sessions, gated on
            // `ai_agent.supervise` (the same privilege the three actions
            // behind it require). It lists the sessions that are running right
            // now, shows the ceiling and the grants each one started with, and
            // lets an operator pause, resume or kill them — which is the ONLY
            // way to remove a capability from a session that is already
            // running, because a policy edit reaches the next session only.
            // A literal route ahead of the entity wildcard below, same shape as
            // 'ai/playground' just above and 'search/lab' before it.
            path: 'ai/sessions',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/ai').then(m => m.AiAgentSessionsComponent),
          },
          {
            // M26 Phase 2 backlog — the new architecture's read-only viewer
            // (`?id=`, `withComponentInputBinding()`): a page/section/widget
            // tree has no business rendering through the generic entity
            // form, so it gets its own literal route ahead of the entity
            // wildcard below, same reasoning as 'dashboard-templates'/
            // 'metric/scorecard' further down this list.
            path: 'dashboard/view',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/dashboard').then(m => m.DashboardViewerComponent),
          },
          {
            // M26 Phase 2 backlog, completed — the visual drag-and-drop
            // page editor (`?pageId=&dashboardId=`), reached from the
            // Dashboard Editor's Pages tab. A page/section/widget canvas has
            // no business rendering through the generic entity form any
            // more than the read-only viewer above does, so it gets its own
            // literal route the same way, ahead of the entity wildcard.
            path: 'dashboard/page/editor',
            canActivate: [authGuard],
            // `@attome/xrm/dashboard/registration`, not the `@attome/xrm/dashboard`
            // barrel — `PageEditorComponent` moved there (R-10 step 3): it *is*
            // the `dashboard_page` form override, so registration is its
            // rightful home. `loadChildren`, not `loadComponent`, so the
            // editor's leave-with-unsaved-work guard ships in that chunk too.
            loadChildren: () =>
              import('@attome/xrm/dashboard/registration').then(m => m.PAGE_EDITOR_ROUTES),
          },
          {
            // N9-T2: the agent designer (define, save as draft, publish).
            path: 'model/agents',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/model').then(m => m.AgentDesignerComponent),
          },
          {
            // Y1-T15: the metadata explorer (kinds, objects, history,
            // diff). The admin model API refuses non-administrators.
            path: 'model/explorer',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/model').then(m => m.MetadataExplorerComponent),
          },
          {
            // Y14 (first step): a published form drawn by the generic
            // renderer; `formId` and `recordId` bind from the path.
            path: 'model/forms/:formId/:recordId',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/model').then(m => m.FormRendererComponent),
          },
          {
            path: 'model/forms/:formId',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/model').then(m => m.FormRendererComponent),
          },
          {
            // M26 (Dashboard) gap-fill — the template gallery: a card grid
            // over `attome_dashboard` rows with `is_template = true`, not a
            // generic entity list, so (like 'dashboard/view' above) it needs
            // its own literal route ahead of the wildcard below. Moved from
            // `@attome/xrm/report` to `@attome/xrm/dashboard` (R-10 step 1).
            path: 'dashboard-templates',
            canActivate: [authGuard],
            loadComponent: () =>
              import('@attome/xrm/dashboard').then(m => m.DashboardTemplateGalleryComponent),
          },
          {
            // M27 Phase 1 (KPI & Metrics, D-407) — the scorecard admin page:
            // live status + trend + on-demand compute for every metric
            // (`metric.rs`'s bespoke routes, which the generic entity engine
            // can't express). Editing a definition/target itself is plain
            // field CRUD and stays on the generic
            // 'metric/definition/list'|'form' / 'metric/target/list'|'form'
            // paths below (the wildcard) — this is an addition, not an
            // override, so it needs its own literal path ahead of the
            // wildcard, same reasoning as 'dashboard/view' above.
            path: 'metric/scorecard',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/report').then(m => m.MetricListComponent),
          },
          {
            // The system-wide Documents page (D-36x) — a hand-built
            // folder-tree browser, not an entity list/form URL, so (like
            // 'dashboard'/'modules/:module' above) it needs its own literal
            // route ahead of the wildcard below rather than resolving
            // through EntityRouterComponent.
            path: 'documents',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/entity/dispatcher').then(m => m.DocumentsPageComponent),
          },
          {
            // D-369/D-371/D-372: the unified Role form (General/Privilege
            // Grants/Record Access/Assignments/Notes). role IS a
            // registered entity (D-372), so 'core/role/list' below resolves
            // generically through the wildcard — but this tabbed form
            // replaces the generic one, so (like 'dashboard/view' above) it
            // needs its own literal route here, ahead of the wildcard.
            path: 'core/role/form',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/security').then(m => m.RoleFormComponent),
          },
          // D-792 — the developer's fleet console (`/xrm/fleet/{deployments,
          // release-reports,publish,rollouts}`), present only in a build whose
          // `ATTOME_FLEET_CONSOLE` define is true (see its declaration above).
          // A literal path ahead of the entity wildcard below, like the others.
          // The sidebar group comes from the server's SidebarContributor, which
          // exists only when the server-side gate is open too.
          ...(typeof ATTOME_FLEET_CONSOLE !== 'undefined' && ATTOME_FLEET_CONSOLE
            ? [{
                path: 'fleet',
                canActivate: [authGuard],
                loadChildren: () => import('@attome/xrm/fleet').then(m => m.FLEET_ROUTES),
              }]
            : []),
          {
            // xrm/{module}/{...}/list   → entity list page
            // xrm/{module}/{...}/form   → entity form page (create)
            // xrm/{module}/{...}/form?id=UUID → entity form page (edit)
            // An xrm_{module}_{entity} logicalname maps to this path
            // (underscore -> '/'); every other prefix (trd_*, vertical,
            // project) is xrm/entity/{logicalname}/list|form
            // (entity-url.utils.ts, resolved by EntityRouterComponent). Must stay the
            // last sibling here — it's a bare wildcard (Angular does not
            // allow a wildcard route to have its own children, so it must
            // be a leaf) and would otherwise swallow 'dashboard' above it.
            path: '**',
            canActivate: [authGuard],
            loadComponent: () => import('@attome/xrm/core/entity/dispatcher').then(m => m.EntityRouterComponent),
          },
        ],
      },
    ],
  },
];
