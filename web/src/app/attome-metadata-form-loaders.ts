import {
  ENVIRONMENT_INITIALIZER, EnvironmentInjector, EnvironmentProviders, inject,
  makeEnvironmentProviders, runInInjectionContext,
} from '@angular/core';
import { EntityRouteRegistry } from '@attome/xrm/core/entity';

/**
 * Declares (but does not run) every built-in entity's bespoke-form loader,
 * so `EntityRouteRegistry.ensureLoaded` can find one when
 * `EntityRouterComponent` first routes to that entity. This file is the one
 * place allowed to know about every xrm module's registration at once — see
 * `EntityRouteRegistry`'s doc comment for why that composition used to be a
 * static `providers: [provide*EntityForms(), …]` list here, and why it blew
 * the 260KB lazy-chunk cap (scripts/chunk-budget.mjs) once ~30 entities were
 * registered.
 *
 * Registering a *loader* is cheap regardless of how many entities share it —
 * declaring it here just stores a closure in a `Map`, no `import()` runs
 * until `ensureLoaded` actually calls it. Two entities that share a loader
 * (e.g. every project sub-entity) will import that module twice if both are
 * visited in the same session — the runtime's own module cache dedupes the
 * actual fetch, and `registerProjectEntityForms` re-registering the same
 * entities a second time is a harmless no-op — so this doesn't need its own
 * per-loader dedup on top of `EntityRouteRegistry`'s per-*logicalname* one.
 */
function registerLoaders(registry: EntityRouteRegistry, injector: EnvironmentInjector): void {
  // A loader's `import()` half is async, but Angular's `inject()` context does
  // NOT survive an `await` — it's tied to the synchronous call stack (or an
  // explicit injector), not "whatever was active when this function started".
  // Some registration functions call `inject()` internally (e.g.
  // `userAccountStateActions()`, called from `registerSecurityEntityForms`),
  // which is exactly why the *previous* eager design worked with no special
  // handling: `ENVIRONMENT_INITIALIZER`'s factory itself runs inside an
  // injection context, synchronously. Once registration moved behind an
  // `await import(...)`, that context was gone by the time the registration
  // function actually ran — `runInInjectionContext` re-establishes it for
  // just that (synchronous, once the import resolves) call.
  const withInjectionContext = (register: (r: EntityRouteRegistry) => void, r: EntityRouteRegistry): void =>
    runInInjectionContext(injector, () => register(r));

  const security = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/core/security/registration');
    withInjectionContext(m.registerSecurityEntityForms, r);
  };
  const coreEntity = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/core/entity/registration');
    withInjectionContext(m.registerCoreEntityForms, r);
  };
  const workflow = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/workflow/registration');
    withInjectionContext(m.registerWorkflowEntityForms, r);
  };
  const dashboard = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/dashboard/registration');
    withInjectionContext(m.registerDashboardEntityForms, r);
  };
  const dashboardLayout = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/dashboard/layout-forms');
    withInjectionContext(m.registerDashboardLayoutForms, r);
  };
  const dashboardModeling = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/dashboard/modeling-forms');
    withInjectionContext(m.registerDashboardModelingForms, r);
  };
  const project = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/project/registration');
    withInjectionContext(m.registerProjectEntityForms, r);
  };
  const notification = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/notification');
    withInjectionContext(m.registerNotificationEntityForms, r);
  };
  const audit = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/audit');
    withInjectionContext(m.registerAuditEntityForms, r);
  };
  const webcrawl = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/webcrawl/registration');
    withInjectionContext(m.registerWebcrawlEntityForms, r);
  };
  const integration = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/integration');
    withInjectionContext(m.registerIntegrationEntityForms, r);
  };
  const grc = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/grc');
    withInjectionContext(m.registerGrcEntityForms, r);
  };
  const ai = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/ai');
    withInjectionContext(m.registerAiEntityForms, r);
  };
  const report = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/report');
    withInjectionContext(m.registerReportEntityForms, r);
  };
  const s2s = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/s2s');
    withInjectionContext(m.registerS2sEntityForms, r);
  };
  const search = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/search');
    withInjectionContext(m.registerSearchEntityForms, r);
  };
  const service = async (r: EntityRouteRegistry) => {
    const m = await import('@attome/xrm/service');
    withInjectionContext(m.registerServiceEntityForms, r);
  };
  // One loader per module entry point, in the short form: import, then pick
  // the registration function.
  const lazy = <M>(load: () => Promise<M>, pick: (m: M) => (r: EntityRouteRegistry) => void) =>
    async (r: EntityRouteRegistry) => withInjectionContext(pick(await load()), r);
  const portal = lazy(() => import('@attome/xrm/portal'), m => m.registerPortalEntityForms);
  // The verticals' entity forms (verticals/*/bundle.json), one entry point each.
  const assetManagement = lazy(() => import('@attome/xrm/verticals/asset-management'), m => m.registerAssetManagementEntityForms);
  const contractManagement = lazy(() => import('@attome/xrm/verticals/contract-management'), m => m.registerContractManagementEntityForms);
  const crm = lazy(() => import('@attome/xrm/verticals/crm'), m => m.registerCrmEntityForms);
  const customerService = lazy(() => import('@attome/xrm/verticals/customer-service'), m => m.registerCustomerServiceEntityForms);
  const enterpriseArchitecture = lazy(() => import('@attome/xrm/verticals/enterprise-architecture'), m => m.registerEnterpriseArchitectureEntityForms);
  const finance = lazy(() => import('@attome/xrm/verticals/finance'), m => m.registerFinanceEntityForms);
  const billing = lazy(() => import('@attome/xrm/verticals/billing'), m => m.registerBillingEntityForms);
  const humanResources = lazy(() => import('@attome/xrm/verticals/human-resources'), m => m.registerHumanResourcesEntityForms);
  const sales = lazy(() => import('@attome/xrm/verticals/sales'), m => m.registerSalesEntityForms);
  const vendorSupplier = lazy(() => import('@attome/xrm/verticals/vendor-supplier'), m => m.registerVendorSupplierEntityForms);

  // Grouped per shared loader, one `for` instead of one `registerLoader`
  // call per entity — with ~100 registered entities now, spelling each
  // call out individually pushed this file (eagerly bundled — it's wired
  // at ENVIRONMENT_INITIALIZER, not behind a route) over the host app's
  // initial-bundle budget. Every entity in platform-bundles/*.json and
  // verticals/*/bundle.json, and every code-created `trd_*` entity
  // (TrdModel::owned_entities), has its own form and so a loader here
  // (SYSTEM-CHANGES.md Topics 14/15); `entity-form-coverage.spec.ts` in
  // @attome/xrm fails when one is missing.
  const groups: [(r: EntityRouteRegistry) => Promise<void>, string[]][] = [
    [security, [
      'user_account', 'organization', 'team', 'privilege', 'role',
      'user_account_mm_team', 'user_account_mm_privilege',
    ]],
    [coreEntity, [
      'attome_document', 'note', 'note_reply', 'api_key', 'authentication_type', 'autovalue',
      'docgen_template', 'communication', 'communication_event', 'follow', 'feed_post', 'glossary_term',
      'license', 'profiler_finding', 'record_relationship', 'resource_skill',
      'resource_availability', 'tag_category', 'tag_item', 'reminder', 'activity',
      'scan_action', 'task_checklist_item', 'queue', 'queue_item', 'queue_item_skill',
    ]],
    [workflow, ['workflow_definition']],
    [dashboard, ['attome_dashboard', 'dashboard_page']],
    [dashboardLayout, [
      'dashboard_version', 'dashboard_section', 'dashboard_section_breakpoint',
      'dashboard_widget', 'dashboard_variable', 'dashboard_parameter',
    ]],
    [dashboardModeling, [
      'dashboard_decision', 'dashboard_decision_option', 'dashboard_decision_dependency',
      'dashboard_scenario', 'dashboard_scenario_assumption', 'dashboard_scenario_metric',
      'dashboard_scenario_result', 'dashboard_metric_definition', 'dashboard_metric_target',
      'metric_scorecard', 'metric_scorecard_item', 'metric_comment',
    ]],
    [project, [
      'attome_project', 'project_work_item', 'project_deliverable', 'project_issue',
      'project_change_request', 'project_portfolio', 'project_program',
      'project_work_item_dependency', 'project_baseline', 'project_baseline_item',
      'project_resource_rate', 'project_timesheet', 'project_time_entry', 'project_team',
      'resource_allocation', 'project_template', 'project_meeting', 'project_lesson',
    ]],
    [notification, ['notification_template']],
    [audit, [
      'audit_config', 'audit_header', 'audit_detail', 'audit_snapshot',
      'audit_consent_purpose', 'audit_consent', 'audit_legal_matter',
    ]],
    [webcrawl, ['knowledge_data_source', 'knowledge_data_item']],
    [integration, ['integration_system', 'integration_event']],
    [grc, [
      'grc_control_requirement', 'grc_policy', 'grc_assessment', 'grc_finding',
      'grc_regulation', 'grc_requirement', 'grc_control', 'grc_assessment_item',
      'grc_evidence', 'grc_risk', 'grc_risk_dependency', 'grc_policy_ack',
      'grc_regulatory_change', 'grc_regulatory_change_link',
    ]],
    // C6 (D-556) — `ai_agent_policy` and `ai_capability_pack` joined
    // this group with the capability-administration forms
    // (`projects/xrm/ai/forms/ai-agent-policy-form` and
    // `.../ai-capability-pack-form`): `registerAiEntityForms` registers both,
    // but `ensureLoaded` only ever calls the `ai` loader for a logicalname
    // listed here, so an entity missing from this array gets the "no form
    // registered" page (there is no generic form fallback, FORMS-IN-CODE-PLAN).
    [ai, [
      'ai_agent', 'ai_model', 'ai_personality', 'ai_provider', 'ai_tone',
      'ai_agent_policy', 'ai_capability_pack',
      'ai_followup_rule', 'ai_collection_rule', 'ai_payment_promise', 'ai_meeting_brief',
      'ai_meeting_notes', 'ai_work_measure',
    ]],
    [report, ['attome_report', 'report_schedule']],
    [s2s, ['s2s_client', 's2s_permission', 's2s_access_log']],
    [search, ['saved_search']],
    [service, [
      'service_work_request', 'service_sla_policy', 'service_ticket', 'service_offering',
      'service_sla_clock', 'service_work_queue', 'service_work_queue_member',
      'service_sla_calculation', 'supplier_sla_clock', 'service_escalation_rule',
      'service_conversion_map', 'service_catalog', 'service_category', 'service_offering_version',
      'service_request_item', 'service_fulfilment_task', 'service_order_guide',
    ]],
    [portal, ['webportal', 'webportal_user']],
    [assetManagement, ['asset', 'location']],
    [contractManagement, [
      'amendment', 'clause', 'contract', 'obligation',
      'contract_playbook_rule', 'contract_version', 'contract_comparison', 'contract_import',
      'counterparty_match_proposal',
    ]],
    [crm, ['account', 'activity', 'contact', 'lead', 'opportunity']],
    [customerService, ['customer']],
    [enterpriseArchitecture, ['ea_application', 'ea_capability', 'ea_system', 'ea_technology']],
    [finance, ['budget', 'cost_center', 'expense', 'invoice', 'payment']],
    [billing, ['invoice_line', 'invoice_schedule', 'region_tax_rate']],
    [humanResources, ['attendance', 'employee', 'leave_request', 'performance_review']],
    [sales, [
      'order', 'price_list', 'price_list_item', 'product', 'quote', 'quote_line', 'territory',
      'call_analysis', 'call_tracker', 'call_finding', 'call_scorecard', 'call_scorecard_answer',
      'call_comment', 'call_library', 'call_library_item', 'call_daily_aggregate',
      'points_model', 'points_rule', 'points_score',
      // D21-T11: "Start dialer" on the call list's list view.
      'call_list',
    ]],
    [vendorSupplier, ['vendor', 'vendor_compliance_document', 'vendor_evaluation']],
  ];
  for (const [loader, names] of groups) {
    for (const name of names) registry.registerLoader(name, loader);
  }
}

// ENVIRONMENT_INITIALIZER runs once, synchronously, when this route tree's
// environment injector is created — cheap, since `registerLoaders` only
// populates a `Map` of closures, never calling any of them.
export function provideXrmEntityFormLoaders(): EnvironmentProviders {
  return makeEnvironmentProviders([
    {
      provide: ENVIRONMENT_INITIALIZER,
      useValue: () => registerLoaders(inject(EntityRouteRegistry), inject(EnvironmentInjector)),
      multi: true,
    },
  ]);
}
