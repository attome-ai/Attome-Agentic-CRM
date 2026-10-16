import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { DashboardDecisionFormComponent } from './dashboard-decision-form/dashboard-decision-form.component';
import { DashboardDecisionOptionFormComponent } from './dashboard-decision-option-form/dashboard-decision-option-form.component';
import { DashboardDecisionDependencyFormComponent } from './dashboard-decision-dependency-form/dashboard-decision-dependency-form.component';
import { DashboardScenarioFormComponent } from './dashboard-scenario-form/dashboard-scenario-form.component';
import { DashboardScenarioAssumptionFormComponent } from './dashboard-scenario-assumption-form/dashboard-scenario-assumption-form.component';
import { DashboardScenarioMetricFormComponent } from './dashboard-scenario-metric-form/dashboard-scenario-metric-form.component';
import { DashboardScenarioResultFormComponent } from './dashboard-scenario-result-form/dashboard-scenario-result-form.component';
import { DashboardMetricDefinitionFormComponent } from './dashboard-metric-definition-form/dashboard-metric-definition-form.component';
import { DashboardMetricTargetFormComponent } from './dashboard-metric-target-form/dashboard-metric-target-form.component';
import { MetricScorecardFormComponent } from './metric-scorecard-form/metric-scorecard-form.component';
import { MetricScorecardItemFormComponent } from './metric-scorecard-item-form/metric-scorecard-item-form.component';
import { MetricCommentFormComponent } from './metric-comment-form/metric-comment-form.component';

/** Registers the decision/scenario-modeling and metric entities' form
 * overrides. Called from `EntityRouteRegistry.ensureLoaded`'s lazy
 * `import()`, never eagerly. */
export function registerDashboardModelingForms(registry: EntityRouteRegistry): void {
  registry.register('dashboard_decision', { formComponent: DashboardDecisionFormComponent });
  registry.register('dashboard_decision_option', { formComponent: DashboardDecisionOptionFormComponent });
  registry.register('dashboard_decision_dependency', { formComponent: DashboardDecisionDependencyFormComponent });
  registry.register('dashboard_scenario', { formComponent: DashboardScenarioFormComponent });
  registry.register('dashboard_scenario_assumption', { formComponent: DashboardScenarioAssumptionFormComponent });
  registry.register('dashboard_scenario_metric', { formComponent: DashboardScenarioMetricFormComponent });
  registry.register('dashboard_scenario_result', { formComponent: DashboardScenarioResultFormComponent });
  registry.register('dashboard_metric_definition', { formComponent: DashboardMetricDefinitionFormComponent });
  registry.register('dashboard_metric_target', { formComponent: DashboardMetricTargetFormComponent });
  registry.register('metric_scorecard', { formComponent: MetricScorecardFormComponent });
  registry.register('metric_scorecard_item', { formComponent: MetricScorecardItemFormComponent });
  registry.register('metric_comment', { formComponent: MetricCommentFormComponent });
}
