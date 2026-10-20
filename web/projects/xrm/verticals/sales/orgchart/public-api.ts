// @attome/xrm/verticals/sales/orgchart — the account org chart (D23-T11), its
// own entry point so only its route loads it.
export {
  CARD_H, CARD_W, OrgChartComponent, isUnder, layoutChart, matches,
} from './org-chart.component';
export type { ChartLayout, Connector, PlacedCard } from './org-chart.component';
export { OrgChartService } from './orgchart.service';
export type { ManagerSet, OrgChart, OrgNode } from './orgchart.service';
