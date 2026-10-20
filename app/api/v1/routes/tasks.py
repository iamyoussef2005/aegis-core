"""Task execution route for AEGIS-CORE Week 4.

==============================================================================
CRITICAL SECURITY INVARIANTS:
------------------------------------------------------------------------------
1. Server-Owned State Only: The task context, simulated user, prompt, and policy
   are resolved exclusively from server-owned approval records.
2. At-Most-Once Execution: A task's approved proposal is consumed atomically.
   Any subsequent execution attempt is rejected as a replay attack (HTTP 409).
3. Zero Client-Submitted Policy: The execution request schema forbids extra
   parameters; no policy, limits, or tools can be supplied by the caller.
4. Firewall Gate Enforcement: Every tool call must pass through Week 3 PolicyEngine.
==============================================================================
"""

import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.agent.exceptions import (
    InvalidPromptError,
    InvalidProviderError,
    ProviderExecutionError,
    UserNotFoundError,
)
from app.agent.orchestrator import AgentOrchestrator
from app.agent.tracing import AgentResponse, SanitizedToolExecution
from app.db.session import get_db
from app.intent.approval import (
    PermissionApprovalService,
    default_approval_service,
)
from app.intent.exceptions import (
    InvalidProposalTransitionError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalReplayError,
    ProposalSecurityError,
    ProposalStateError,
)

router = APIRouter(prefix="/tasks", tags=["Task Execution & Policy Enforcement"])


def get_approval_service() -> PermissionApprovalService:
    """Dependency provider for the server-side PermissionApprovalService singleton."""
    return default_approval_service


# ---------------------------------------------------------------------------
# Request and Response Schemas
# ---------------------------------------------------------------------------


class TaskExecuteRequest(BaseModel):
    """Execution dispatch payload.

    NOTE: extra='forbid' strictly prohibits client-submitted policies, tools,
    or expanded constraint limits.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: int | None = Field(
        default=None,
        ge=1,
        description="Optional expected simulated user ID. If provided, server asserts exact tenant match.",
    )
    provider: Literal["fake", "openai"] = Field(
        default="fake",
        description="LLM provider mode ('fake' for offline deterministic testing, 'openai' for live model)",
    )


class TaskExecuteResponse(BaseModel):
    """Structured response detailing authorization, execution steps, and final output."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="Correlated task identifier")
    user_id: int = Field(..., description="Server-bound simulated user ID")
    proposal_id: str = Field(..., description="Associated approved proposal ID")
    authorized_tool: str = Field(..., description="Single authorized tool name")
    execution_status: str = Field(
        ..., description="Execution outcome: 'completed' or 'error'"
    )
    final_answer: str = Field(..., description="Final synthesized agent response")
    steps: list[SanitizedToolExecution] = Field(
        default_factory=list, description="Sanitized audit trace of executed tool steps"
    )
    policy_decisions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Audit records of PolicyEngine authorization decisions",
    )
    tool_calls_count: int = Field(..., description="Number of executed tool calls")
    duration_ms: float = Field(
        ..., description="Total execution duration in milliseconds"
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when execution began",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/{task_id}/execute",
    response_model=TaskExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Approved Agent Task",
    description=(
        "Executes an autonomous agent task strictly under an approved, immutable TaskPolicy. "
        "The task context, user identity, prompt, and constraints are resolved exclusively from "
        "server-owned state. A task may only be executed once (at-most-once execution). "
        "Unapproved, rejected, expired, replayed, or mismatched tasks are rejected."
    ),
    responses={
        403: {"description": "User tenant mismatch or security validation failure"},
        404: {"description": "Task proposal not found"},
        409: {
            "description": "Task unapproved, rejected, or replayed (at-most-once violation)"
        },
        410: {"description": "Task proposal expired"},
        503: {"description": "Upstream LLM provider failure"},
    },
)
def execute_approved_task(
    task_id: str,
    session: Annotated[Session, Depends(get_db)],
    approval_service: Annotated[
        PermissionApprovalService, Depends(get_approval_service)
    ],
    request: TaskExecuteRequest | None = None,
) -> TaskExecuteResponse:
    """Execute a task whose permission proposal was explicitly approved."""
    expected_user_id = request.user_id if request else None
    provider_name = request.provider if request else "fake"

    # 1. Atomically consume the approved proposal to enforce at-most-once execution
    try:
        proposal, policy = approval_service.consume_by_task_id(
            task_id=task_id,
            expected_user_id=expected_user_id,
        )
    except ProposalNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except ProposalExpiredError as err:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=str(err),
        ) from err
    except ProposalReplayError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Task '{task_id}' has already been executed. Replay is strictly forbidden.",
        ) from err
    except (ProposalStateError, InvalidProposalTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Task '{task_id}' cannot be executed: {err}",
        ) from err
    except ProposalSecurityError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        ) from err

    # 2. Extract server-owned verified prompt and user identity
    server_prompt = proposal.normalized_intent.source_request
    server_user_id = proposal.user_id

    # 3. Dispatch execution to AgentOrchestrator bound to the approved TaskPolicy
    orchestrator = AgentOrchestrator()
    start_time = time.perf_counter()

    try:
        agent_response: AgentResponse = orchestrator.run(
            user_id=server_user_id,
            prompt=server_prompt,
            provider_name=provider_name,
            session=session,
            policy=policy,
        )
    except UserNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except (InvalidPromptError, InvalidProviderError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        ) from err
    except ProviderExecutionError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"LLM provider failed: {err}",
        ) from err

    execution_duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    # Check for unhandled provider error inside agent response trace
    if agent_response.status == "error" and any(
        "Provider" in e or "timed out" in e for e in agent_response.errors
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="; ".join(agent_response.errors),
        )

    # 4. Extract policy decisions from steps for auditable response
    policy_decisions = [
        {
            "tool_name": step.tool_name,
            "decision": step.policy_action,
            "reason_code": step.policy_reason_code,
            "duration_ms": step.duration_ms,
        }
        for step in agent_response.execution_trace
        if step.policy_action is not None
    ]

    return TaskExecuteResponse(
        task_id=task_id,
        user_id=server_user_id,
        proposal_id=proposal.proposal_id,
        authorized_tool=proposal.requested_tool,
        execution_status=agent_response.status,
        final_answer=agent_response.final_answer,
        steps=agent_response.execution_trace,
        policy_decisions=policy_decisions,
        tool_calls_count=agent_response.tool_calls_count,
        duration_ms=execution_duration_ms,
    )
