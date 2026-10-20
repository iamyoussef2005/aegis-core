"""FastAPI route handlers for Mini AI Agent task execution in AEGIS-CORE.

==============================================================================
CRITICAL SECURITY MODEL & LOCAL SIMULATION NOTICE:
------------------------------------------------------------------------------
This endpoint operates exclusively on synthetic academic data for local AI
agent security experiments. The `user_id` parameter serves as an experimental
inbox selector for simulation scenarios, NOT an authenticated identity.

THIS IS NOT A PRODUCTION MULTI-USER API.
The endpoint MUST NOT be exposed on public interfaces.
In upcoming roadmap milestones (Weeks 3-5), these invocations will be mediated
by the AEGIS-CORE execution firewall, token authentication, and approval gates.
==============================================================================
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.agent.exceptions import (
    InvalidPromptError,
    InvalidProviderError,
    ProviderExecutionError,
    UserNotFoundError,
)
from app.agent.orchestrator import AgentOrchestrator
from app.agent.tracing import AgentResponse
from app.db.session import get_db

router = APIRouter(prefix="/agent", tags=["Mini AI Agent Runtime"])


class AgentRunRequest(BaseModel):
    """Input payload for dispatching a task to the Mini AI Agent."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(
        ...,
        ge=1,
        description="Simulated user account ID (local tenant selector, NOT authenticated session)",
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="User inquiry or instruction for the agent to resolve",
    )
    provider: Literal["fake", "openai"] = Field(
        default="fake",
        description="Configured provider mode: 'fake' for offline/testing or 'openai' for live model",
    )
    policy_profile: Literal[
        "read_only_all", "inbox_triage", "strict_search", "minimal_read", "none"
    ] = Field(
        default="read_only_all",
        description=(
            "Server-owned demonstration policy profile for research experiments. "
            "NOTE: This local simulation API allows profile selection for testing; "
            "it is NOT an authenticated production API or authorization boundary."
        ),
    )

    @field_validator("message")
    @classmethod
    def validate_non_empty_message(cls, v: str) -> str:
        """Reject empty or pure whitespace messages."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Message cannot be empty or whitespace only")
        return stripped


@router.post(
    "/run",
    response_model=AgentResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Mini AI Agent Task",
    description=(
        "Dispatches a user request to the autonomous Mini AI Agent. "
        "The agent executes bounded read-only tool calls against the selected user's inbox, "
        "enforces server-controlled tenant identity, and returns a structured response with sanitized audit traces. "
        "NOTE: user_id is a local simulation selector, NOT an authenticated session."
    ),
    responses={
        404: {"description": "Simulated user not found"},
        422: {"description": "Validation error in request parameters"},
        503: {"description": "LLM provider failure, timeout, or configuration error"},
    },
)
def run_agent_task(
    request: AgentRunRequest,
    session: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    """Execute an agent task using the configured orchestrator."""
    orchestrator = AgentOrchestrator()

    try:
        response = orchestrator.run(
            user_id=request.user_id,
            prompt=request.message,
            provider_name=request.provider,
            session=session,
            policy_profile=request.policy_profile,
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

    # If the orchestrator captured an upstream provider error within the trace
    if response.status == "error" and any(
        "Provider" in e or "timed out" in e for e in response.errors
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="; ".join(response.errors),
        )

    return response
