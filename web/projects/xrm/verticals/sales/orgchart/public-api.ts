// @attome/xrm/verticals/sales/orgchart — the account org chart (D23-T11) and
// the deal's buying-committee map (D23-T12), its
// own entry point so only its route loads it.
export {
  CARD_H, CARD_W, OrgChartComponent, isUnder, layoutChart, matches,
} from './org-chart.component';
export type { ChartLayout, Connector, PlacedCard } from './org-chart.component';
export { CommitteeMapComponent, committeeRoots, influenceLines } from './committee-map.component';
export type { InfluenceLine } from './committee-map.component';
export { OrgChartService } from './orgchart.service';
export type {
  CoverageGap, DealContact, DealMap, InfluenceLink, ManagerSet, OrgChart, OrgNode,
} from './orgchart.service';
