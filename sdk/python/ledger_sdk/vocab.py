"""Generic ``ledger.*`` record-type vocabulary shared by every agent framework adapter.

Product-specific chains (gate.*, harbour.*, ...) keep their own record types; this vocabulary
is for framework adapters that want a stable, framework-agnostic set of event names to map
callbacks onto. Names are coordinated 1:1 with the shared build brief:

    goal.created, step.planned, action.attempted, action.completed, verification.recorded,
    approval.requested, approval.granted, approval.denied, budget.charged
"""
from __future__ import annotations

GOAL_CREATED = "ledger.goal.created"
STEP_PLANNED = "ledger.step.planned"
ACTION_ATTEMPTED = "ledger.action.attempted"
ACTION_COMPLETED = "ledger.action.completed"
VERIFICATION_RECORDED = "ledger.verification.recorded"
APPROVAL_REQUESTED = "ledger.approval.requested"
APPROVAL_GRANTED = "ledger.approval.granted"
APPROVAL_DENIED = "ledger.approval.denied"
BUDGET_CHARGED = "ledger.budget.charged"

ALL = (
    GOAL_CREATED,
    STEP_PLANNED,
    ACTION_ATTEMPTED,
    ACTION_COMPLETED,
    VERIFICATION_RECORDED,
    APPROVAL_REQUESTED,
    APPROVAL_GRANTED,
    APPROVAL_DENIED,
    BUDGET_CHARGED,
)

__all__ = [
    "GOAL_CREATED", "STEP_PLANNED", "ACTION_ATTEMPTED", "ACTION_COMPLETED",
    "VERIFICATION_RECORDED", "APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_DENIED",
    "BUDGET_CHARGED", "ALL",
]
