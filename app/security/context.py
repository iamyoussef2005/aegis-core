"""Trusted server-controlled runtime execution context for AEGIS-CORE tasks.

==============================================================================
CRITICAL SECURITY INVARIANT:
------------------------------------------------------------------------------
The TaskContext binds an active agent task to an authenticated/simulated user
identity and an approved, immutable TaskPolicy.
Neither the LLM nor untrusted data retrieved during tool execution may alter
this context or escalate permissions once execution begins.
==============================================================================
"""

from pydantic import BaseModel, ConfigDict, Field

from app.security.schemas import TaskPolicy


class TaskContext(BaseModel):
    """Immutable, server-controlled runtime execution context for an agent task."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(
        ...,
        min_length=1,
        description="Unique active task correlation identifier",
    )
    user_id: int = Field(
        ...,
        ge=1,
        description="Server-verified simulated user identity (cannot be model-altered)",
    )
    policy: TaskPolicy | None = Field(
        default=None,
        description="Approved security authorization policy bound to this task, or None",
    )
