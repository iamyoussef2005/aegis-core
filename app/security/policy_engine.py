"""Deterministic, default-deny security policy engine for AEGIS-CORE.

Evaluates AI agent tool execution requests against task-scoped authorization
policies prior to execution.
"""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from app.security.schemas import (
    KNOWN_SYSTEM_TOOLS,
    PolicyAction,
    PolicyDecision,
    PolicyReasonCode,
    TaskPolicy,
    ToolExecutionRequest,
    normalize_tool_arguments,
)


class PolicyEngine:
    """Deterministic, default-deny security policy evaluator for AEGIS-CORE.

    Enforces all core security invariants:
    1. Default-deny: Missing, invalid, or expired policies evaluate to DENY.
    2. Scope verification: Execution requests must match the policy's task_id and bound_user_id.
    3. Tool permission: Exact tool-name matching against policy.allowed_tools.
    4. Argument normalization: Strict schema validation and default expansion.
    5. Argument constraints: Parameter bounds and forbidden patterns are evaluated strictly.
    6. Ownership verification: Foreign-user email lookups are denied even if permitted by policy.
    7. Fail-closed: Any unhandled evaluation error produces an explicit DENY decision.
    """

    def __init__(
        self,
        known_tools: frozenset[str] | None = None,
        ownership_verifier: Callable[[int, int], bool] | None = None,
    ) -> None:
        """Initialize the policy engine.

        Args:
            known_tools: Optional custom set of recognized system tools.
                         Defaults to system-wide KNOWN_SYSTEM_TOOLS.
            ownership_verifier: Optional callback `(user_id: int, email_id: int) -> bool`
                                returning True if the email is owned by the user.
        """
        self.known_tools: frozenset[str] = (
            known_tools if known_tools is not None else KNOWN_SYSTEM_TOOLS
        )
        self.ownership_verifier = ownership_verifier

    def evaluate(
        self,
        policy: TaskPolicy | None,
        request: ToolExecutionRequest,
        current_time: datetime | None = None,
        session: Session | None = None,
    ) -> PolicyDecision:
        """Evaluate an execution request against a task policy.

        Args:
            policy: The task-scoped TaskPolicy, or None if no policy is attached.
            request: The ToolExecutionRequest containing task_id, user_id, tool_name, and arguments.
            current_time: Optional explicit timestamp for deterministic expiration testing.
            session: Optional database session for repository-level ownership boundary verification.

        Returns:
            PolicyDecision with ALLOW or DENY, reason_code, explanation, task_id, and policy_version.
        """
        try:
            # 1. Validate request structure and type
            if not isinstance(request, ToolExecutionRequest):
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.ARGUMENT_INVALID,
                    explanation=(
                        f"Expected ToolExecutionRequest, got: {type(request).__name__}"
                    ),
                    task_id=getattr(request, "task_id", "unknown"),
                    policy_version=getattr(policy, "policy_version", "unknown"),
                )

            # 2. Invariant: Missing policy fails closed (Default Deny)
            if policy is None:
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.POLICY_MISSING,
                    explanation="No security policy attached to task; default-deny enforced.",
                    task_id=request.task_id,
                    policy_version="none",
                    tool_name=request.tool_name,
                )

            # 3. Invariant: Invalid policy type fails closed
            if not isinstance(policy, TaskPolicy):
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.POLICY_INVALID,
                    explanation=f"Invalid policy object type: {type(policy).__name__}; fail-closed.",
                    task_id=request.task_id,
                    policy_version="unknown",
                    tool_name=request.tool_name,
                )

            # 4. Invariant: Expired policy fails closed
            if policy.is_expired(current_time):
                expires_str = (
                    policy.expires_at.isoformat() if policy.expires_at else "unknown"
                )
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.POLICY_EXPIRED,
                    explanation=f"Policy expired at {expires_str}; fail-closed.",
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                )

            # 5. Invariant: Task scope binding verification
            if request.task_id != policy.task_id:
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.TASK_MISMATCH,
                    explanation=(
                        f"Execution request task_id '{request.task_id}' does not match "
                        f"policy task_id '{policy.task_id}'."
                    ),
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                    details={
                        "request_task_id": request.task_id,
                        "policy_task_id": policy.task_id,
                    },
                )

            # 6. Invariant: Server-controlled user identity binding verification
            if request.user_id != policy.bound_user_id:
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.USER_MISMATCH,
                    explanation=(
                        f"Execution request user_id ({request.user_id}) does not match "
                        f"policy bound_user_id ({policy.bound_user_id})."
                    ),
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                    details={
                        "request_user_id": request.user_id,
                        "policy_user_id": policy.bound_user_id,
                    },
                )

            # 7. Invariant: Exact tool matching against registered system tools
            # Strict case-sensitive string matching; no prefix or regex matching
            if request.tool_name not in self.known_tools:
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.TOOL_NOT_ALLOWED,
                    explanation=(
                        f"Tool '{request.tool_name}' is not a recognized system tool. "
                        f"Registered system tools: {sorted(self.known_tools)}"
                    ),
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                )

            # 8. Invariant: Tool permission check (exact match, no wildcards, non-empty allowlist)
            if (
                not policy.allowed_tools
                or request.tool_name not in policy.allowed_tools
            ):
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.TOOL_NOT_ALLOWED,
                    explanation=(
                        f"Tool '{request.tool_name}' is not permitted by policy for task '{policy.task_id}'. "
                        f"Allowed tools: {sorted(policy.allowed_tools)}"
                    ),
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                    details={"allowed_tools": sorted(policy.allowed_tools)},
                )

            # 9. Schema validation and default expansion
            # Normalize arguments against strict tool schema before evaluating constraints
            normalized_args, arg_error = normalize_tool_arguments(
                request.tool_name, request.validated_arguments
            )
            if arg_error is not None or normalized_args is None:
                return PolicyDecision(
                    decision=PolicyAction.DENY,
                    reason_code=PolicyReasonCode.ARGUMENT_INVALID,
                    explanation=(
                        f"Invalid or malformed arguments for tool '{request.tool_name}': {arg_error}"
                    ),
                    task_id=policy.task_id,
                    policy_version=policy.policy_version,
                    tool_name=request.tool_name,
                    details={
                        "raw_arguments": request.validated_arguments,
                        "error": arg_error,
                    },
                )

            # 10. Invariant: Tool argument constraints verification
            # Evaluated strictly on the normalized arguments with defaults expanded
            if request.tool_name in policy.constraints:
                constraint = policy.constraints[request.tool_name]
                is_valid, violation = constraint.validate_arguments(normalized_args)
                if not is_valid:
                    return PolicyDecision(
                        decision=PolicyAction.DENY,
                        reason_code=PolicyReasonCode.CONSTRAINT_VIOLATION,
                        explanation=(
                            violation
                            or f"Constraint violation for tool '{request.tool_name}'."
                        ),
                        task_id=policy.task_id,
                        policy_version=policy.policy_version,
                        tool_name=request.tool_name,
                        details={
                            "tool_name": request.tool_name,
                            "normalized_arguments": normalized_args,
                            "raw_arguments": request.validated_arguments,
                            "violation": violation,
                        },
                    )

            # 11. Invariant: Ownership boundary check (Deny foreign-owned email lookups)
            if request.tool_name == "get_email_details":
                email_id = normalized_args.get("email_id")
                if email_id is not None:
                    # Check via explicit ownership verifier callback if registered
                    if self.ownership_verifier is not None:
                        is_owned = self.ownership_verifier(request.user_id, email_id)
                        if not is_owned:
                            return PolicyDecision(
                                decision=PolicyAction.DENY,
                                reason_code=PolicyReasonCode.USER_MISMATCH,
                                explanation=(
                                    f"Foreign-owned email lookup denied: email_id {email_id} "
                                    f"is not owned by user {request.user_id}."
                                ),
                                task_id=policy.task_id,
                                policy_version=policy.policy_version,
                                tool_name=request.tool_name,
                                details={
                                    "email_id": email_id,
                                    "request_user_id": request.user_id,
                                },
                            )
                    # Check via database session if supplied
                    elif session is not None:
                        from app.models.email_message import EmailMessage

                        msg = session.get(EmailMessage, email_id)
                        if msg is not None and msg.owner_id != request.user_id:
                            return PolicyDecision(
                                decision=PolicyAction.DENY,
                                reason_code=PolicyReasonCode.USER_MISMATCH,
                                explanation=(
                                    f"Foreign-owned email lookup denied: email_id {email_id} "
                                    f"is owned by user {msg.owner_id}, not user {request.user_id}."
                                ),
                                task_id=policy.task_id,
                                policy_version=policy.policy_version,
                                tool_name=request.tool_name,
                                details={
                                    "email_id": email_id,
                                    "owner_id": msg.owner_id,
                                    "request_user_id": request.user_id,
                                },
                            )

            # 12. Authorization Success
            return PolicyDecision(
                decision=PolicyAction.ALLOW,
                reason_code=PolicyReasonCode.ALLOW,
                explanation=(
                    f"Tool '{request.tool_name}' authorized for task '{policy.task_id}' "
                    f"under policy v{policy.policy_version}."
                ),
                task_id=policy.task_id,
                policy_version=policy.policy_version,
                tool_name=request.tool_name,
                details={"normalized_arguments": normalized_args},
            )

        except Exception as err:
            # Absolute fail-closed guarantee on unexpected failure
            return PolicyDecision(
                decision=PolicyAction.DENY,
                reason_code=PolicyReasonCode.EVALUATION_ERROR,
                explanation=f"Internal policy evaluation failure (fail-closed): {err}",
                task_id=getattr(request, "task_id", "unknown"),
                policy_version=getattr(policy, "policy_version", "unknown"),
                tool_name=getattr(request, "tool_name", None),
                details={
                    "error_type": type(err).__name__,
                    "error_message": str(err),
                },
            )
