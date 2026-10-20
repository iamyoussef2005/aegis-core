"""Pydantic v2 schemas and data contracts for the AEGIS-CORE security policy engine.

==============================================================================
CRITICAL SECURITY INVARIANTS:
------------------------------------------------------------------------------
1. Default-deny: Any operation not explicitly authorized is forbidden.
2. No wildcard permissions: Tool names and constraints must be exact.
3. Immutability: Policy and decision objects are frozen to prevent tampering.
4. Server-controlled identity: Policy is strictly bound to task_id and bound_user_id.
5. Fail-closed: Expired, missing, or malformed policies evaluate to DENY.
6. Schema normalization: Arguments are normalized and defaults expanded prior to constraint checks.
7. Least privilege: Scoped ID restrictions, limit caps, and search term whitelists are enforced.
==============================================================================
"""

import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

# Static system-known tool allowlist
DEFAULT_SYSTEM_TOOLS: frozenset[str] = frozenset(
    {"read_inbox", "get_email_details", "search_emails"}
)
KNOWN_SYSTEM_TOOLS: frozenset[str] = DEFAULT_SYSTEM_TOOLS

# Forbidden wildcard tokens
FORBIDDEN_WILDCARDS: frozenset[str] = frozenset(
    {"*", ".*", "all", "__all__", "ANY", "?", "%"}
)


# ---------------------------------------------------------------------------
# Decision Actions and Reason Codes
# ---------------------------------------------------------------------------


class PolicyAction(StrEnum):
    """Deterministic policy decision outcome."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyReasonCode(StrEnum):
    """Standardized machine-readable reason codes for policy evaluations."""

    # Authorization success
    ALLOW = "ALLOW"
    POLICY_ALLOW = "ALLOW"  # backward compatibility alias

    # Structural & lifecycle denials
    POLICY_MISSING = "POLICY_MISSING"
    POLICY_INVALID = "POLICY_INVALID"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    TASK_MISMATCH = "TASK_MISMATCH"
    USER_MISMATCH = "USER_MISMATCH"

    # Permission denials
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    TOOL_NOT_PERMITTED = "TOOL_NOT_ALLOWED"  # backward compatibility alias
    UNKNOWN_TOOL = "TOOL_NOT_ALLOWED"  # backward compatibility alias

    # Constraint & argument denials
    ARGUMENT_INVALID = "ARGUMENT_INVALID"
    INVALID_ARGUMENTS = "ARGUMENT_INVALID"  # backward compatibility alias
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"

    # Internal failure (fail-closed)
    EVALUATION_ERROR = "EVALUATION_ERROR"


# ---------------------------------------------------------------------------
# Strict Tool Argument Schemas for Firewall Normalization & Default Expansion
# ---------------------------------------------------------------------------


class StrictReadInboxArgs(BaseModel):
    """Strict argument schema for read_inbox with default expansion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    limit: int = Field(default=5, ge=1, le=20)
    offset: int = Field(default=0, ge=0)
    is_read: bool | None = Field(default=None)


class StrictGetEmailDetailsArgs(BaseModel):
    """Strict argument schema for get_email_details."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    email_id: int = Field(..., ge=1)


class StrictSearchEmailsArgs(BaseModel):
    """Strict argument schema for search_emails with default expansion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query: str = Field(..., min_length=1, max_length=200)
    limit: int = Field(default=5, ge=1, le=10)
    offset: int = Field(default=0, ge=0)

    @field_validator("query")
    @classmethod
    def validate_non_empty_query(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Search query cannot be empty or whitespace only.")
        return stripped


STRICT_TOOL_ARG_MODELS: dict[str, type[BaseModel]] = {
    "read_inbox": StrictReadInboxArgs,
    "get_email_details": StrictGetEmailDetailsArgs,
    "search_emails": StrictSearchEmailsArgs,
}


def normalize_tool_arguments(
    tool_name: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate arguments against strict tool schema and expand default values.

    Returns:
        Tuple of (normalized_arguments_dict, error_message).
        If invalid, normalized_arguments_dict is None.
    """
    model_cls = STRICT_TOOL_ARG_MODELS.get(tool_name)
    if model_cls is None:
        return None, f"No argument schema defined for tool '{tool_name}'"

    try:
        validated = model_cls.model_validate(arguments)
        return validated.model_dump(), None
    except ValidationError as err:
        errors = err.errors(include_url=False)
        error_msgs = []
        for e in errors:
            loc = ".".join(str(p) for p in e["loc"]) if e["loc"] else "root"
            msg = e["msg"]
            error_msgs.append(f"{loc}: {msg}")
        return None, "; ".join(error_msgs)


# ---------------------------------------------------------------------------
# Per-Tool Parameter Constraints
# ---------------------------------------------------------------------------


class BaseToolConstraint(BaseModel):
    """Abstract base model for tool execution argument constraints."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate execution arguments against this constraint.

        Args:
            arguments: Dictionary of validated tool arguments.

        Returns:
            Tuple of (is_valid, violation_explanation).
            If valid, violation_explanation is None.
        """
        return True, None


class ReadInboxConstraint(BaseToolConstraint):
    """Execution constraints for the 'read_inbox' tool."""

    max_limit: int | None = Field(
        default=None,
        ge=1,
        le=20,
        description="Maximum allowed limit for emails returned per invocation",
    )
    max_offset: int | None = Field(
        default=None,
        ge=0,
        description="Maximum allowed pagination offset",
    )
    allowed_is_read: bool | None = Field(
        default=None,
        description="Enforced read-status filter (e.g. False to allow only unread emails)",
    )

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        req_limit = arguments.get("limit")
        if (
            req_limit is not None
            and self.max_limit is not None
            and req_limit > self.max_limit
        ):
            return (
                False,
                f"Requested limit ({req_limit}) exceeds policy maximum limit ({self.max_limit}).",
            )

        req_offset = arguments.get("offset")
        if (
            req_offset is not None
            and self.max_offset is not None
            and req_offset > self.max_offset
        ):
            return (
                False,
                f"Requested offset ({req_offset}) exceeds policy maximum offset ({self.max_offset}).",
            )

        if self.allowed_is_read is not None:
            req_is_read = arguments.get("is_read")
            if req_is_read != self.allowed_is_read:
                return (
                    False,
                    f"Requested is_read filter ({req_is_read}) does not match policy enforced value ({self.allowed_is_read}).",
                )

        return True, None


class GetEmailDetailsConstraint(BaseToolConstraint):
    """Execution constraints for the 'get_email_details' tool."""

    allowed_email_ids: frozenset[int] | None = Field(
        default=None,
        description="Explicit whitelist of email IDs authorized for inspection",
    )
    denied_email_ids: frozenset[int] | None = Field(
        default=None,
        description="Explicit blacklist of email IDs forbidden from inspection",
    )
    max_email_id: int | None = Field(
        default=None,
        ge=1,
        description="Upper bound on accessible email ID",
    )

    @field_validator("allowed_email_ids", "denied_email_ids", mode="before")
    @classmethod
    def coerce_frozenset(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (list, tuple, set, frozenset)):
            for item in v:
                if not isinstance(item, int) or item < 1:
                    raise ValueError(
                        f"Email IDs must be positive integers, got: {item}"
                    )
            return frozenset(v)
        raise ValueError("Email IDs list must be an iterable of integers.")

    @model_validator(mode="after")
    def validate_no_overlap(self) -> Self:
        if self.allowed_email_ids and self.denied_email_ids:
            overlap = self.allowed_email_ids & self.denied_email_ids
            if overlap:
                raise ValueError(
                    f"Email IDs cannot appear in both allowed and denied sets: {sorted(overlap)}"
                )
        return self

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        email_id = arguments.get("email_id")
        if email_id is None:
            return False, "Missing required argument 'email_id'."

        if self.denied_email_ids and email_id in self.denied_email_ids:
            return (
                False,
                f"Access to email_id {email_id} is explicitly denied by policy blacklist.",
            )

        if self.allowed_email_ids is not None:
            if not self.allowed_email_ids:
                return (
                    False,
                    "Policy allowed_email_ids whitelist is empty (empty allowlist denies all).",
                )
            if email_id not in self.allowed_email_ids:
                return (
                    False,
                    f"email_id {email_id} is not in the policy allowed_email_ids whitelist: {sorted(self.allowed_email_ids)}.",
                )

        if self.max_email_id is not None and email_id > self.max_email_id:
            return (
                False,
                f"email_id {email_id} exceeds policy maximum email ID ({self.max_email_id}).",
            )

        return True, None


class SearchEmailsConstraint(BaseToolConstraint):
    """Execution constraints for the 'search_emails' tool."""

    max_limit: int | None = Field(
        default=None,
        ge=1,
        le=10,
        description="Maximum allowed limit for search results",
    )
    max_offset: int | None = Field(
        default=None,
        ge=0,
        description="Maximum allowed pagination offset for search",
    )
    max_query_length: int | None = Field(
        default=None,
        ge=1,
        le=200,
        description="Maximum allowed query string character length",
    )
    min_query_length: int | None = Field(
        default=None,
        ge=1,
        description="Minimum required query string character length",
    )
    allowed_search_terms: frozenset[str] | None = Field(
        default=None,
        description="Explicit whitelist of permitted exact search terms (case/unicode normalized)",
    )
    blocked_search_terms: frozenset[str] | None = Field(
        default=None,
        validation_alias=AliasChoices("blocked_search_terms", "blocked_keywords"),
        description="Explicit blacklist of forbidden search terms (case/unicode normalized)",
    )

    @field_validator("allowed_search_terms", "blocked_search_terms", mode="before")
    @classmethod
    def coerce_search_terms(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (list, tuple, set, frozenset)):
            cleaned: list[str] = []
            for item in v:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        "Search terms cannot contain empty or non-string values."
                    )
                cleaned.append(item.strip())
            return frozenset(cleaned)
        raise ValueError("Search terms must be an iterable of strings.")

    @property
    def blocked_keywords(self) -> frozenset[str] | None:
        """Backward compatibility alias for blocked_search_terms."""
        return self.blocked_search_terms

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        req_limit = arguments.get("limit")
        if (
            req_limit is not None
            and self.max_limit is not None
            and req_limit > self.max_limit
        ):
            return (
                False,
                f"Requested search limit ({req_limit}) exceeds policy maximum limit ({self.max_limit}).",
            )

        req_offset = arguments.get("offset")
        if (
            req_offset is not None
            and self.max_offset is not None
            and req_offset > self.max_offset
        ):
            return (
                False,
                f"Requested search offset ({req_offset}) exceeds policy maximum offset ({self.max_offset}).",
            )

        query = arguments.get("query", "")
        if self.max_query_length is not None and len(query) > self.max_query_length:
            return (
                False,
                f"Search query length ({len(query)}) exceeds policy maximum length ({self.max_query_length}).",
            )

        if self.min_query_length is not None and len(query) < self.min_query_length:
            return (
                False,
                f"Search query length ({len(query)}) is below policy minimum length ({self.min_query_length}).",
            )

        # Canonical Unicode normalization and casefolding
        norm_query = unicodedata.normalize("NFKC", query).strip().casefold()

        # Strict allowlist check (Least Privilege)
        if self.allowed_search_terms is not None:
            if not self.allowed_search_terms:
                return (
                    False,
                    "Search allowed_search_terms whitelist is empty (empty allowlist denies all).",
                )
            normalized_allowed = {
                unicodedata.normalize("NFKC", t).strip().casefold()
                for t in self.allowed_search_terms
            }
            if norm_query not in normalized_allowed:
                return (
                    False,
                    f"Search query '{query}' is not in policy allowed_search_terms whitelist: {sorted(self.allowed_search_terms)}.",
                )

        # Blocklist check
        if self.blocked_search_terms and norm_query:
            normalized_blocked = {
                unicodedata.normalize("NFKC", t).strip().casefold()
                for t in self.blocked_search_terms
            }
            for kw in normalized_blocked:
                if kw in norm_query:
                    return (
                        False,
                        f"Search query contains forbidden keyword '{kw}'.",
                    )

        return True, None


class GenericToolConstraint(BaseToolConstraint):
    """Generic argument constraints for arbitrary tools."""

    max_numeric_values: dict[str, float] = Field(
        default_factory=dict,
        description="Maximum upper bounds on named numeric parameters",
    )
    allowed_values: dict[str, list[Any]] = Field(
        default_factory=dict,
        description="Explicit whitelists of allowed values for named parameters",
    )
    blocked_values: dict[str, list[Any]] = Field(
        default_factory=dict,
        description="Explicit blacklists of forbidden values for named parameters",
    )

    def validate_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        for field_name, max_val in self.max_numeric_values.items():
            if field_name in arguments:
                val = arguments[field_name]
                if isinstance(val, (int, float)) and val > max_val:
                    return (
                        False,
                        f"Argument '{field_name}' ({val}) exceeds policy maximum allowed value ({max_val}).",
                    )

        for field_name, allowed in self.allowed_values.items():
            if field_name in arguments:
                val = arguments[field_name]
                if val not in allowed:
                    return (
                        False,
                        f"Argument '{field_name}' ({val}) is not in policy allowed values: {allowed}.",
                    )

        for field_name, blocked in self.blocked_values.items():
            if field_name in arguments:
                val = arguments[field_name]
                if val in blocked:
                    return (
                        False,
                        f"Argument '{field_name}' has forbidden value: '{val}'.",
                    )

        return True, None


ToolConstraint = (
    ReadInboxConstraint
    | GetEmailDetailsConstraint
    | SearchEmailsConstraint
    | GenericToolConstraint
    | BaseToolConstraint
)

CONSTRAINT_TYPE_MAP: dict[str, type[BaseToolConstraint]] = {
    "read_inbox": ReadInboxConstraint,
    "get_email_details": GetEmailDetailsConstraint,
    "search_emails": SearchEmailsConstraint,
}


# ---------------------------------------------------------------------------
# TaskPolicy
# ---------------------------------------------------------------------------


class TaskPolicy(BaseModel):
    """Immutable, task-scoped security authorization policy.

    Binds a specific active task and server-verified user identity to an explicit
    allowlist of authorized tools and argument constraints.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(
        ...,
        min_length=1,
        description="Unique task identifier this policy is strictly bound to",
    )
    bound_user_id: int = Field(
        ...,
        ge=1,
        description="Server-controlled simulated user identity this policy is bound to",
    )
    allowed_tools: frozenset[str] = Field(
        ...,
        description="Strict set of tool names authorized for invocation under this task",
    )
    constraints: dict[str, BaseToolConstraint] = Field(
        default_factory=dict,
        description="Optional per-tool parameter bounds and argument constraints",
    )
    policy_version: str = Field(
        default="1.0.0",
        description="Semantic version of this policy definition",
    )
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the policy was issued",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Optional UTC expiration timestamp after which the policy fails closed",
    )

    @field_validator("task_id", mode="before")
    @classmethod
    def validate_task_id(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("task_id cannot be empty or whitespace only.")
        return v.strip()

    @field_validator("allowed_tools", mode="before")
    @classmethod
    def coerce_allowed_tools(cls, v: Any) -> Any:
        if isinstance(v, (list, tuple, set)):
            return frozenset(v)
        if isinstance(v, str):
            raise ValueError(
                "allowed_tools must be a set, list, or frozenset of tool names, not a string."
            )
        return v

    @field_validator("allowed_tools", mode="after")
    @classmethod
    def validate_allowed_tools(cls, v: frozenset[str]) -> frozenset[str]:
        if not v:
            raise ValueError(
                "allowed_tools cannot be empty. Must specify explicit tool permissions."
            )
        for tool in v:
            if not isinstance(tool, str) or not tool.strip():
                raise ValueError("Tool name must be a non-empty string.")
            clean_tool = tool.strip()
            if (
                clean_tool in FORBIDDEN_WILDCARDS
                or "*" in clean_tool
                or "?" in clean_tool
                or "%" in clean_tool
            ):
                raise ValueError(
                    f"Wildcard permission '{tool}' is forbidden. Exact tool names must be specified."
                )
            if clean_tool not in KNOWN_SYSTEM_TOOLS:
                raise ValueError(
                    f"Tool '{tool}' is not a recognized system tool. Known tools: {sorted(KNOWN_SYSTEM_TOOLS)}"
                )
        return v

    @field_validator("constraints", mode="before")
    @classmethod
    def parse_constraints(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError(
                "constraints must be a dictionary mapping tool names to constraints."
            )
        parsed: dict[str, Any] = {}
        for tool_name, constraint_val in v.items():
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ValueError("Constraint tool name must be a non-empty string.")
            clean_name = tool_name.strip()
            if isinstance(constraint_val, BaseToolConstraint):
                parsed[clean_name] = constraint_val
            elif isinstance(constraint_val, dict):
                target_cls = CONSTRAINT_TYPE_MAP.get(clean_name, GenericToolConstraint)
                parsed[clean_name] = target_cls.model_validate(constraint_val)
            else:
                raise ValueError(
                    f"Invalid constraint type for tool '{clean_name}': {type(constraint_val).__name__}. "
                    f"Expected BaseToolConstraint or dict."
                )
        return parsed

    @field_validator("issued_at", "expires_at", mode="after")
    @classmethod
    def ensure_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def validate_policy_invariants(self) -> Self:
        # Invariant 1: Constraints must only reference tools declared in allowed_tools
        for tool_name in self.constraints:
            if tool_name not in self.allowed_tools:
                raise ValueError(
                    f"Constraint defined for tool '{tool_name}', but '{tool_name}' is not in allowed_tools. "
                    f"Allowed tools: {sorted(self.allowed_tools)}"
                )

        # Invariant 2: Expiration must be strictly after issuance
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError(
                f"Policy expires_at ({self.expires_at.isoformat()}) must be strictly after issued_at ({self.issued_at.isoformat()})."
            )

        return self

    def is_expired(self, current_time: datetime | None = None) -> bool:
        """Check if this policy has expired.

        Args:
            current_time: Optional explicit timestamp for deterministic testing.
                          Defaults to current UTC time.

        Returns:
            True if policy has an expiration timestamp and current_time exceeds it.
        """
        if self.expires_at is None:
            return False
        now = current_time or datetime.now(UTC)
        now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        return now > self.expires_at


# ---------------------------------------------------------------------------
# ToolExecutionRequest
# ---------------------------------------------------------------------------


class ToolExecutionRequest(BaseModel):
    """Encapsulates a single tool invocation request presented to the firewall.

    Carries the active task context, server-controlled user identity, requested
    tool name, and validated arguments.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    task_id: str = Field(
        ...,
        min_length=1,
        description="Active task correlation ID",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        description="Target tool name to execute",
    )
    validated_arguments: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("validated_arguments", "arguments"),
        description="Pre-validated tool arguments",
    )
    user_id: int = Field(
        ...,
        ge=1,
        validation_alias=AliasChoices("user_id", "bound_user_id"),
        description="Server-controlled simulated user identity",
    )

    @field_validator("task_id", mode="before")
    @classmethod
    def validate_task_id(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("task_id cannot be empty or whitespace only.")
        return v.strip()

    @field_validator("tool_name", mode="before")
    @classmethod
    def validate_tool_name(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("tool_name cannot be empty or whitespace only.")
        return v

    @property
    def arguments(self) -> dict[str, Any]:
        """Convenience property for validated_arguments."""
        return self.validated_arguments

    @property
    def bound_user_id(self) -> int:
        """Convenience property for user_id matching policy field naming."""
        return self.user_id


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------


class PolicyDecision(BaseModel):
    """Deterministic security evaluation decision rendered by PolicyEngine."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    decision: PolicyAction = Field(
        ...,
        description="Deterministic decision: ALLOW or DENY",
    )
    reason_code: PolicyReasonCode = Field(
        ...,
        description="Standardized machine-readable reason code",
    )
    explanation: str = Field(
        ...,
        validation_alias=AliasChoices(
            "explanation", "human_readable_explanation", "reason"
        ),
        description="Human-readable explanation of why the decision was rendered",
    )
    task_id: str = Field(
        ...,
        description="Active task identifier",
    )
    policy_version: str = Field(
        default="1.0.0",
        description="Version of the evaluated security policy",
    )
    tool_name: str | None = Field(
        default=None,
        description="Name of the requested tool under evaluation",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional diagnostic context or constraint violation specifics",
    )

    @property
    def is_allowed(self) -> bool:
        """True if the policy decision is ALLOW."""
        return self.decision == PolicyAction.ALLOW

    @property
    def is_denied(self) -> bool:
        """True if the policy decision is DENY."""
        return self.decision == PolicyAction.DENY

    @property
    def human_readable_explanation(self) -> str:
        """Human-readable explanation alias."""
        return self.explanation

    @property
    def reason(self) -> str:
        """Reason explanation alias."""
        return self.explanation
