"""Execution tracing, audit models, and sensitive data sanitization for AEGIS-CORE.

==============================================================================
CRITICAL SECURITY & PRIVACY LOGGING BOUNDARY:
------------------------------------------------------------------------------
Traces recorded by this module may be returned to API consumers and logged
to diagnostic sinks. To prevent exfiltration and accidental data leakage:
1. API keys, Authorization headers, and Bearer tokens are NEVER recorded.
2. Complete private email bodies are stripped/truncated to preview length.
3. Raw database connection parameters and internal stack traces are redacted.
==============================================================================
"""

import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Sensitive parameter keys to scrub from logged tool arguments
SENSITIVE_ARGUMENT_KEYS = frozenset(
    {"api_key", "token", "authorization", "secret", "password", "key"}
)


def sanitize_arguments(args: dict[str, Any] | Any) -> dict[str, Any]:
    """Scrub sensitive credentials and normalize arguments for audit logs."""
    if not isinstance(args, dict):
        return {"raw_value": str(args)[:100]}

    sanitized: dict[str, Any] = {}
    for key, value in args.items():
        lower_key = str(key).lower()
        if any(s in lower_key for s in SENSITIVE_ARGUMENT_KEYS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, str) and len(value) > 200:
            sanitized[key] = f"{value[:200]}... [TRUNCATED]"
        else:
            sanitized[key] = value

    return sanitized


def sanitize_result_summary(
    tool_name: str, result_dict: dict[str, Any] | None
) -> dict[str, Any]:
    """Generate a privacy-preserving summary of tool output (stripping full email bodies)."""
    if not result_dict or not isinstance(result_dict, dict):
        return {}

    data = result_dict.get("data")
    if not data or not isinstance(data, dict):
        return {"has_data": False}

    summary: dict[str, Any] = {
        "owner_id": data.get("owner_id"),
        "count": data.get("count"),
        "total": data.get("total"),
    }

    # If result contains a list of emails, produce safe metadata previews without full bodies
    if "emails" in data and isinstance(data["emails"], list):
        summary["items_preview"] = [
            {
                "id": email.get("id"),
                "sender": email.get("sender"),
                "subject": email.get("subject"),
                "is_read": email.get("is_read"),
                "body_length": len(email.get("body", "")),
            }
            for email in data["emails"]
            if isinstance(email, dict)
        ]
    elif "id" in data and "subject" in data:
        # Single email detail response
        summary["email_preview"] = {
            "id": data.get("id"),
            "sender": data.get("sender"),
            "subject": data.get("subject"),
            "is_read": data.get("is_read"),
            "body_length": len(data.get("body", "")),
        }

    return summary


# ---------------------------------------------------------------------------
# Structured Tracing Models
# ---------------------------------------------------------------------------


class SanitizedToolExecution(BaseModel):
    """Sanitized trace record of a single tool execution step."""

    model_config = ConfigDict(extra="ignore")

    call_id: str = Field(..., description="Unique tool call invocation identifier")
    tool_name: str = Field(..., description="Name of the executed tool")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Sanitized arguments passed to tool"
    )
    outcome: str = Field(..., description="Outcome status: SUCCESS or ERROR")
    duration_ms: float = Field(
        ..., description="Tool execution duration in milliseconds"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Execution timestamp in UTC ISO format",
    )
    error_code: str | None = Field(
        default=None, description="Error classification code if tool execution failed"
    )
    error_message: str | None = Field(
        default=None, description="Sanitized error description if tool execution failed"
    )
    policy_action: str | None = Field(
        default=None,
        description="Firewall policy decision action: 'ALLOW' or 'DENY'",
    )
    policy_reason_code: str | None = Field(
        default=None,
        description="Machine-readable policy evaluation reason code",
    )
    result_summary: dict[str, Any] | None = Field(
        default=None,
        description="Privacy-preserving summary of results without full private bodies",
    )


class AgentResponse(BaseModel):
    """Standardized response model returned by the Agent Orchestrator and REST API."""

    model_config = ConfigDict(extra="ignore")

    task_id: str = Field(
        ..., description="Unique task identifier for request correlation"
    )
    final_answer: str = Field(
        ..., description="The final synthesized answer returned by the agent"
    )
    provider_mode: str = Field(
        ...,
        description="Identifier of the LLM provider mode utilized (e.g. 'fake', 'openai')",
    )
    tool_calls_count: int = Field(
        ..., ge=0, description="Total number of tool calls executed during the task"
    )
    execution_trace: list[SanitizedToolExecution] = Field(
        default_factory=list,
        description="Structured, sanitized audit trace of all executed tool steps",
    )
    status: str = Field(
        ...,
        description="Execution status: 'success', 'error', or 'max_tool_calls_exceeded'",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="List of error messages encountered during execution",
    )


# ---------------------------------------------------------------------------
# In-Memory Execution Tracer
# ---------------------------------------------------------------------------


class ExecutionTracer:
    """Manages recording, timing, and sanitizing execution events for a single agent task."""

    def __init__(
        self,
        task_id: str,
        user_id: int,
        provider_mode: str,
    ) -> None:
        self.task_id = task_id
        self.user_id = user_id
        self.provider_mode = provider_mode
        self.started_at = datetime.now(UTC)
        self.start_perf = time.perf_counter()
        self.steps: list[SanitizedToolExecution] = []
        self.errors: list[str] = []

    def record_tool_step(
        self,
        call_id: str,
        tool_name: str,
        arguments: dict[str, Any] | str,
        success: bool,
        duration_ms: float,
        result_dict: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        policy_action: str | None = None,
        policy_reason_code: str | None = None,
    ) -> SanitizedToolExecution:
        """Record and append a sanitized tool execution event."""
        if isinstance(arguments, str):
            try:
                import json

                parsed_args = json.loads(arguments) if arguments.strip() else {}
            except Exception:
                parsed_args = {"raw": arguments[:100]}
        else:
            parsed_args = arguments

        sanitized_args = sanitize_arguments(parsed_args)
        sanitized_summary = (
            sanitize_result_summary(tool_name, result_dict) if success else None
        )

        step = SanitizedToolExecution(
            call_id=call_id,
            tool_name=tool_name,
            arguments=sanitized_args,
            outcome="SUCCESS" if success else "ERROR",
            duration_ms=round(duration_ms, 2),
            timestamp=datetime.now(UTC).isoformat(),
            error_code=error_code,
            error_message=error_message,
            policy_action=policy_action,
            policy_reason_code=policy_reason_code,
            result_summary=sanitized_summary,
        )
        self.steps.append(step)
        return step

    def record_error(self, message: str) -> None:
        """Record a top-level error message."""
        self.errors.append(message)

    def build_response(
        self,
        final_answer: str,
        status: str,
    ) -> AgentResponse:
        """Construct the final structured AgentResponse."""
        return AgentResponse(
            task_id=self.task_id,
            final_answer=final_answer,
            provider_mode=self.provider_mode,
            tool_calls_count=len(self.steps),
            execution_trace=self.steps,
            status=status,
            errors=self.errors,
        )
