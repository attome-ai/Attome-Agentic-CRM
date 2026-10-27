// @attome/xrm/report/builder — P1-T1: reports built by pointing, not SQL:
// a table of columns, a grouped summary, or a matrix, previewed live.
export { ReportBuilderComponent } from './report-builder.component';
export type { ReportField } from './report-builder.component';
export {
  MEASURE, PREVIEW_ROWS, REPORT_BUCKETS, REPORT_FUNCS, REPORT_LAYOUTS, REPORT_OPERATORS,
  emptyReport, keyText, measure, pivot, ready, reportSpec, summarise, tableColumns,
} from './report-builder.model';
export type {
  AnswerGroup, Matrix, ReportBucket, ReportCondition, ReportFunc, ReportGroup, ReportLayout, ReportOperator,
  ReportState, SummaryLine,
} from './report-builder.model';
