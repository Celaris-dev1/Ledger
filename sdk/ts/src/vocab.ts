/**
 * Generic `ledger.*` record-type vocabulary shared by every agent framework adapter.
 * Coordinated 1:1 with the shared build brief and the Python SDK's `ledger_sdk.vocab`.
 */
export const GOAL_CREATED = "ledger.goal.created";
export const STEP_PLANNED = "ledger.step.planned";
export const ACTION_ATTEMPTED = "ledger.action.attempted";
export const ACTION_COMPLETED = "ledger.action.completed";
export const VERIFICATION_RECORDED = "ledger.verification.recorded";
export const APPROVAL_REQUESTED = "ledger.approval.requested";
export const APPROVAL_GRANTED = "ledger.approval.granted";
export const APPROVAL_DENIED = "ledger.approval.denied";
export const BUDGET_CHARGED = "ledger.budget.charged";

export const ALL = [
  GOAL_CREATED, STEP_PLANNED, ACTION_ATTEMPTED, ACTION_COMPLETED, VERIFICATION_RECORDED,
  APPROVAL_REQUESTED, APPROVAL_GRANTED, APPROVAL_DENIED, BUDGET_CHARGED,
] as const;
