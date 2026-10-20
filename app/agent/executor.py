"""Controlled Tool Execution Engine for the AEGIS-CORE Mini AI Agent.

==============================================================================
SECURITY ARCHITECTURE & ACCESS BOUNDARY:
------------------------------------------------------------------------------
ToolExecutor provides the single, centralized authorization and execution
choke point for all AI agent tool calls:
1. Strict allowlist enforcement (rejects arbitrary names, shell calls, code execution).
2. Server-side identity injection (model cannot tamper with or select user_id).
3. Deterministic PolicyEngine evaluation prior to dispatch.
4. Fail-closed: Denied operations NEVER invoke the underlying tool adapter or DB.
5. Complete encapsulation of database sessions away from LLM providers.
==============================================================================
"""

import json
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.agent.schemas import ToolError, ToolResult
from app.agent.tool_registry import ToolRegistry, default_tool_registry
from app.security.context import TaskContext
from app.security.policy_engine import PolicyEngine
from app.security.schemas import (
    PolicyAction,
    PolicyDecision,
    PolicyReasonCode,
    TaskPolicy,
    ToolExecutionRequest,
    normalize_tool_arguments,
)


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
    policy_decision: PolicyDecision | None = Field(
        default=None,
        description="Deterministic security firewall evaluation decision",
    )

    @property
    def success(self) -> bool:
        return self.tool_result.success


class ToolExecutor:
    """Enforces execution boundaries, security policy authorization, and dispatch."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.registry = registry or default_tool_registry
        self.policy_engine = policy_engine or PolicyEngine()

    def _build_denial_outcome(
        self,
        call_id: str,
        tool_name: str,
        decision: PolicyDecision,
        duration_ms: float = 0.0,
    ) -> ToolExecutionOutcome:
        """Construct a standardized denial outcome adhering to tool result contract.

        Guarantees that the underlying tool adapter or database is NEVER called.
        """
        tool_result: ToolResult[Any] = ToolResult(
            success=False,
            tool_name=tool_name,
            error=ToolError(
                code=decision.reason_code.value,
                message=f"Access denied by security firewall: {decision.explanation}",
                details=decision.details,
            ),
        )
        formatted = ToolRegistry.format_tool_result_for_llm(tool_name, tool_result)
        return ToolExecutionOutcome(
            call_id=call_id,
            tool_name=tool_name,
            duration_ms=round(duration_ms, 2),
            tool_result=tool_result,
            formatted_content=formatted,
            policy_decision=decision,
        )

    def execute(
        self,
        call_id: str,
        tool_name: str,
        raw_arguments: str | dict[str, Any],
        user_id: int,
        session: Session | None = None,
        task_id: str | None = None,
        policy: TaskPolicy | None = None,
        context: TaskContext | None = None,
    ) -> ToolExecutionOutcome:
        """Execute an authorized tool call under server-controlled identity.

        Args:
            call_id: Unique identifier for this tool call from the model.
            tool_name: Requested tool name.
            raw_arguments: JSON string or dict of tool arguments.
            user_id: Server-controlled user identity (IMMUTABLE, cannot be altered by model).
            session: Optional database session passed through to domain services.
            task_id: Optional correlation task ID.
            policy: Optional task-scoped authorization policy.
            context: Optional trusted TaskContext (takes precedence for identity/policy).

        Returns:
            ToolExecutionOutcome with timing, policy decision, and serialized data.
        """
        start_time = time.perf_counter()

        # 1. Resolve trusted execution context and immutable identities
        if context is not None:
            effective_task_id = context.task_id
            effective_user_id = context.user_id
            effective_policy = context.policy
        else:
            effective_policy = policy
            effective_task_id = task_id or (
                policy.task_id if policy is not None else f"task_{user_id}"
            )
            effective_user_id = user_id

        # 2. Parse arguments safely from model payload
        if isinstance(raw_arguments, str):
            try:
                parsed_arguments = (
                    json.loads(raw_arguments) if raw_arguments.strip() else {}
                )
            except (json.JSONDecodeError, ValueError) as json_err:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                decision = PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.ARGUMENT_INVALID,
                    explanation=f"Malformed tool arguments JSON: {json_err}",
                    task_id=effective_task_id,
                    policy_version=getattr(
                        effective_policy, "policy_version", "unknown"
                    ),
                    tool_name=tool_name,
                    details={"raw_arguments": raw_arguments[:200]},
                )
                return self._build_denial_outcome(
                    call_id=call_id,
                    tool_name=tool_name,
                    decision=decision,
                    duration_ms=duration_ms,
                )
        elif isinstance(raw_arguments, dict):
            parsed_arguments = dict(raw_arguments)
        else:
            parsed_arguments = {"raw_value": str(raw_arguments)}

        # Invariant: Disregard any model-injected identity or policy fields
        # Server-controlled identity and policy strictly govern execution
        if isinstance(parsed_arguments, dict):
            for spoofed_field in ("user_id", "task_id", "policy", "token"):
                parsed_arguments.pop(spoofed_field, None)

        # 3. Construct ToolExecutionRequest bound to server identity
        execution_request = ToolExecutionRequest(
            task_id=effective_task_id,
            tool_name=tool_name,
            validated_arguments=parsed_arguments,
            user_id=effective_user_id,
        )

        # 4. Deterministic Security Policy Evaluation
        try:
            decision = self.policy_engine.evaluate(
                policy=effective_policy,
                request=execution_request,
                session=session,
            )
        except Exception as exc:
            # Invariant: Evaluation exceptions must fail closed (DENY)
            decision = PolicyDecision(
                decision=PolicyAction.DENY,
                reason_code=PolicyReasonCode.EVALUATION_ERROR,
                explanation=f"Policy evaluation raised unexpected exception: {exc}",
                task_id=effective_task_id,
                policy_version=getattr(effective_policy, "policy_version", "unknown"),
                tool_name=tool_name,
                details={"exception_type": type(exc).__name__},
            )

        # 5. Intercept DENIALS before any domain or database interaction
        if decision.decision == PolicyAction.DENY:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_denial_outcome(
                call_id=call_id,
                tool_name=tool_name,
                decision=decision,
                duration_ms=duration_ms,
            )

        # 6. Dispatch authorized tool call with normalized arguments
        normalized_args, _ = normalize_tool_arguments(tool_name, parsed_arguments)
        dispatch_args = (
            normalized_args if normalized_args is not None else parsed_arguments
        )

        tool_result = self.registry.execute_tool(
            tool_name=tool_name,
            raw_arguments=dispatch_args,
            user_id=effective_user_id,
            session=session,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Format output as untrusted external data for model consumption
        formatted = ToolRegistry.format_tool_result_for_llm(tool_name, tool_result)

        return ToolExecutionOutcome(
            call_id=call_id,
            tool_name=tool_name,
            duration_ms=round(duration_ms, 2),
            tool_result=tool_result,
            formatted_content=formatted,
            policy_decision=decision,
        )


# Global default executor instance
default_tool_executor = ToolExecutor()
