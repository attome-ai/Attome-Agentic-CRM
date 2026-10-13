/*
 * @attome/base/step-up — the D-510 step-up flow: the service and the prompt
 * component (NGB-5.1c, D-760). `isSafeReturnUrl` is re-exported for callers
 * that already import from here; its home is `@attome/base`.
 */
export {
  StepUpService, STEP_UP_NAVIGATE, STEP_UP_LOCAL_FACTORS, isSafeReturnUrl,
} from './step-up.service';
export type {
  StepUpLocalFactor, StepUpProvider, StepUpPending, StepUpPendingAction,
  StepUpPendingOptions, StepUpPromptState,
} from './step-up.service';
export { StepUpPromptComponent, KNOWN_OPERATIONS } from './step-up-prompt.component';
