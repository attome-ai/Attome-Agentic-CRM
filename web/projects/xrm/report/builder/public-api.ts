// @attome/xrm/report/builder — P1-T1: reports built by pointing, not SQL:
// a table of columns, a grouped summary, or a matrix, previewed live.
export { ReportBuilderComponent } from './report-builder.component';
export type { ReportField, SharePrincipal } from './report-builder.component';
export { matrixChart, summaryChart } from './report-chart';
export { reportBuilderAr, reportBuilderEn } from './report-builder.i18n';
export {
  MEASURE, PREVIEW_ROWS, PROMPT_TYPES, REPORT_BUCKETS, REPORT_CHARTS, REPORT_FUNCS, REPORT_LAYOUTS, REPORT_OPERATORS,
  emptyReport, parameterDecls, promptNameOk, promptValues, keyText, measure, pivot, ready, reportSpec, summarise, tableColumns,
} from './report-builder.model';
export type {
  AnswerGroup, Matrix, PromptType, ReportBucket, ReportChart, ReportPrompt, ReportCondition, ReportFunc, ReportGroup, ReportLayout, ReportOperator,
  ReportState, SummaryLine,
} from './report-builder.model';
