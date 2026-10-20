"""Pydantic v2 schemas for Mini AI Agent tool inputs, outputs, and errors.

==============================================================================
CRITICAL ARCHITECTURAL CONTEXT & ACCESS BOUNDARY NOTICE:
------------------------------------------------------------------------------
The `user_id` parameter across these schemas serves strictly as a local
simulation identity selector (inbox partitioner) within our research environment,
NOT a cryptographically authenticated session identity.

THESE ADAPTERS DO NOT PROVIDE PRODUCTION-GRADE AUTHORIZATION.
In subsequent roadmap milestones (Weeks 3-5), tool calls will be intercepted and
mediated by the AEGIS-CORE execution firewall with cryptographic agent tokens
and deterministic policy rules.
==============================================================================
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.email import EmailMessageResponse


class ToolError(BaseModel):
    """Structured error payload for tool execution failures."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(
        ...,
        description="Standardized machine-readable error code (e.g. VALIDATION_ERROR, USER_NOT_FOUND, EMAIL_NOT_FOUND)",
    )
    message: str = Field(
        ...,
        description="Human-readable explanation of why the tool invocation failed",
    )
    details: Any = Field(
        default=None,
        description="Optional diagnostic details or validation error lists",
    )


class ToolResult[DataT](BaseModel):
    """Standardized envelope for all AI Agent tool adapter results.

    Guarantees consistent, structured, JSON-serializable outputs across all tools.
    """

    model_config = ConfigDict(from_attributes=True)

    success: bool = Field(
        ...,
        description="Boolean indicating whether the tool executed successfully",
    )
    tool_name: str = Field(
        ...,
        description="Name of the tool that generated this result",
    )
    data: DataT | None = Field(
        default=None,
        description="Structured data payload on success; None on failure",
    )
    error: ToolError | None = Field(
        default=None,
        description="Structured error payload on failure; None on success",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")

    def to_json(self, **kwargs: Any) -> str:
        """Serialize result to a valid JSON string."""
        return self.model_dump_json(**kwargs)


# ---------------------------------------------------------------------------
# Tool 1: read_inbox Schemas
# ---------------------------------------------------------------------------


class ReadInboxInput(BaseModel):
    """Input parameters for the read_inbox tool adapter."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(
        ...,
        ge=1,
        description="Simulated user ID (local simulation identity selector)",
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of emails to return (1-20, default 5)",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Pagination offset count (default 0)",
    )
    is_read: bool | None = Field(
        default=None,
        description="Optional filter: true for read, false for unread, null for all",
    )


class ReadInboxData(BaseModel):
    """Structured data returned on successful read_inbox invocation."""

    model_config = ConfigDict(from_attributes=True)

    emails: list[EmailMessageResponse] = Field(
        default_factory=list,
        description="List of bounded, owner-scoped email messages",
    )
    count: int = Field(
        ge=0,
        description="Number of emails returned in this batch",
    )
    total: int = Field(
        ge=0,
        description="Total matching emails for this owner",
    )
    owner_id: int = Field(
        ...,
        description="ID of the simulated user whose inbox was queried",
    )
    limit: int = Field(
        ...,
        description="Pagination limit applied to query",
    )
    offset: int = Field(
        default=0,
        description="Pagination offset applied to query",
    )


# ---------------------------------------------------------------------------
# Tool 2: get_email_details Schemas
# ---------------------------------------------------------------------------


class GetEmailDetailsInput(BaseModel):
    """Input parameters for the get_email_details tool adapter."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(
        ...,
        ge=1,
        description="Simulated user ID (local simulation identity selector)",
    )
    email_id: int = Field(
        ...,
        ge=1,
        description="Unique integer ID of the email message to retrieve",
    )


# ---------------------------------------------------------------------------
# Tool 3: search_emails Schemas
# ---------------------------------------------------------------------------


class SearchEmailsInput(BaseModel):
    """Input parameters for the search_emails tool adapter."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(
        ...,
        ge=1,
        description="Simulated user ID (local simulation identity selector)",
    )
    query: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Search keyword or phrase across subject and body (supports English & Arabic)",
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum number of search results to return (1-10, default 5)",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Pagination offset count (default 0)",
    )

    @field_validator("query")
    @classmethod
    def validate_non_empty_query(cls, v: str) -> str:
        """Ensure search query is not only whitespace."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Search query cannot be empty or whitespace only")
        return stripped


class SearchEmailsData(BaseModel):
    """Structured data returned on successful search_emails invocation."""

    model_config = ConfigDict(from_attributes=True)

    emails: list[EmailMessageResponse] = Field(
        default_factory=list,
        description="List of matching owner-scoped email messages",
    )
    count: int = Field(
        ge=0,
        description="Number of matching emails returned in this batch",
    )
    total: int = Field(
        ge=0,
        description="Total matching emails for this query in the user's inbox",
    )
    owner_id: int = Field(
        ...,
        description="ID of the simulated user whose inbox was searched",
    )
    query: str = Field(
        ...,
        description="Search query executed",
    )
    limit: int = Field(
        ...,
        description="Search limit applied",
    )
    offset: int = Field(
        default=0,
        description="Search offset applied",
    )
