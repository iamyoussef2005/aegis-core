"""Controlled Tool Execution Engine for the AEGIS-CORE Mini AI Agent.

==============================================================================
SECURITY ARCHITECTURE & ACCESS BOUNDARY:
------------------------------------------------------------------------------
ToolExecutor provides the single, controlled execution entry point for all tool calls:
1. Strict allowlist enforcement (rejects arbitrary names, shell calls, code execution).
2. Server-side identity injection (model cannot tamper with or select user_id).
3. Complete encapsulation of database sessions away from LLM providers.
4. Architectural hook for Week 3 Policy Interception & Firewall Evaluation.
==============================================================================
"""

import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.agent.schemas import ToolResult
from app.agent.tool_registry import ToolRegistry, default_tool_registry


class ToolExecutionOutcome(BaseModel):
    """Encapsulates the complete outcome and timing of a single executed tool call."""

    model_config = ConfigDict(extra="ignore")

    call_id: str = Field(..., description="Unique tool call invocation identifier")
    tool_name: str = Field(..., description="Name of the requested tool")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
    tool_result: ToolResult[Any] = Field(
        ..., description="Structured tool execution result"
    )
    formatted_content: str = Field(
        ...,
        description="Serialized tool output formatted as untrusted data for LLM context",
    )

    @property
    def success(self) -> bool:
        return self.tool_result.success


class ToolExecutor:
    """Enforces execution boundaries, timing, and dispatch for AI agent tools."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or default_tool_registry

    def execute(
        self,
        call_id: str,
        tool_name: str,
        raw_arguments: str | dict[str, Any],
        user_id: int,
        session: Session | None = None,
    ) -> ToolExecutionOutcome:
        """Execute a validated tool call under server-controlled identity.

        Args:
            call_id: Unique identifier for this tool call from the model.
            tool_name: Requested tool name.
            raw_arguments: JSON string or dict of tool arguments.
            user_id: Server-controlled user identity (IMMUTABLE, cannot be altered by model).
            session: Optional database session passed through to domain services.

        Returns:
            ToolExecutionOutcome with timing and serialized data.
        """
        start_time = time.perf_counter()

        # ======================================================================
        # EXTENSION POINT: Week 3 Security Policy Interception
        # ----------------------------------------------------------------------
        # In Week 3, the AEGIS-CORE Firewall Interceptor will evaluate this call:
        # decision = self.policy_engine.evaluate(user_id, tool_name, raw_arguments)
        # if decision.action == PolicyAction.DENY:
        #     return self._build_denial_outcome(call_id, tool_name, decision)
        # ======================================================================

        # Dispatch via registry with enforced server-controlled identity
        tool_result = self.registry.execute_tool(
            tool_name=tool_name,
            raw_arguments=raw_arguments,
            user_id=user_id,
            session=session,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Format output as untrusted external data
        formatted = ToolRegistry.format_tool_result_for_llm(tool_name, tool_result)

        return ToolExecutionOutcome(
            call_id=call_id,
            tool_name=tool_name,
            duration_ms=round(duration_ms, 2),
            tool_result=tool_result,
            formatted_content=formatted,
        )


# Global default executor instance
default_tool_executor = ToolExecutor()
