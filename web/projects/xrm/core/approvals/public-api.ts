export { ApprovalsAdminService }      from './services/approvals-admin.service';
export { ApprovalQueueListComponent } from './approval/list/approval-queue-list/approval-queue-list.component';
export { ApprovalPolicyListComponent } from './policy/list/approval-policy-list/approval-policy-list.component';
export type {
  ApprovalRequestItem, ApprovalRequestsPage, DecideResponse,
  ApprovalPlan, ApprovalStep, StepMode, OnTimeout,
  ApprovalPolicy, ApprovalPoliciesPage, CreateApprovalPolicyBody, UpdateApprovalPolicyBody,
} from './services/approvals-admin.service';
// U15 — the approver's own inbox (any signed-in user; not the admin queue).
export { MyApprovalsPageComponent } from './my-approvals/my-approvals-page.component';
export { MyApprovalsService, DECISION_COMMENT_MAX } from './services/my-approvals.service';
// M9-T4 — the request page and a record's approval history.
export { ApprovalRequestPageComponent, showValue } from './request-page/request-page.component';
export type { ApprovalDetail, ChangedAttribute, DecisionEntry } from './request-page/request-page.component';
export { ApprovalHistoryPanelComponent, APPROVAL_HISTORY_PAGE_SIZE } from './record-history/approval-history-panel.component';
export type { ApprovalHistoryItem } from './record-history/approval-history-panel.component';
// M9-T3 — the public page an emailed approval link opens.
export { ApprovalLinkPageComponent } from './email-link/approval-link-page.component';
export type { ApprovalLinkView } from './email-link/approval-link-page.component';
export type {
  MyWorkItem, MyWorkAction, MyWorkPage, ApprovalDecision, ApprovalDecisionResponse,
} from './services/my-approvals.service';
