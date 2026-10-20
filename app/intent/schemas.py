"""Pydantic v2 schemas and data contracts for AEGIS-CORE structured task intent.

==============================================================================
CRITICAL SECURITY INVARIANTS:
------------------------------------------------------------------------------
1. Strict schema validation: extra="forbid" and frozen=True.
2. Whitelisted intent types: Only supported read-only intents are accepted.
3. No permission inflation: Counts and query targets are bounded strictly.
4. Separation of language and authorization: response_language specifies
   output presentation only and has zero influence over tool permissions.
5. Conservative ambiguity: Ambiguous requests explicitly require clarification.
==============================================================================
"""

from enum import StrEnum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class IntentType(StrEnum):
    """Whitelisted intent types supported in Week 4."""

    READ_LATEST_EMAILS = "read_latest_emails"
    SUMMARIZE_RECENT_EMAILS = "summarize_recent_emails"
    SEARCH_EMAILS = "search_emails"
    READ_EMAIL_DETAILS = "read_email_details"
    AMBIGUOUS = "ambiguous"


class ResourceType(StrEnum):
    """Target system resource types."""

    EMAIL = "email"
    INBOX = "inbox"
    UNKNOWN = "unknown"


class ActionType(StrEnum):
    """Requested high-level action category."""

    READ = "read"
    SUMMARIZE = "summarize"
    SEARCH = "search"
    SHOW = "show"
    UNKNOWN = "unknown"


class TaskIntent(BaseModel):
    """Structured, immutable representation of parsed user task intent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent_type: IntentType = Field(
        ...,
        description="Whitelisted task intent type",
    )
    resource_type: ResourceType = Field(
        default=ResourceType.EMAIL,
        description="Target resource domain (strictly 'email' or 'inbox')",
    )
    requested_action: ActionType = Field(
        ...,
        description="Requested action verb category",
    )
    requested_count: int | None = Field(
        default=None,
        ge=1,
        le=20,
        description="Bounded number of items requested (1 to 20)",
    )
    search_query: str | None = Field(
        default=None,
        max_length=200,
        description="Sanitized search query keyword",
    )
    requested_email_id: int | None = Field(
        default=None,
        ge=1,
        description="Specific email ID requested for retrieval",
    )
    response_language: str = Field(
        default="en",
        description="Requested presentation language ('en', 'ar', etc.). Does NOT grant permissions.",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Deterministic confidence indicator (1.0 for exact rule match, 0.0 for ambiguous)",
    )
    is_ambiguous: bool = Field(
        default=False,
        description="Ambiguity indicator flag. If True, clarification is required before policy proposal.",
    )
    requires_clarification: bool = Field(
        default=False,
        description="Flag indicating human or supervisor clarification is needed",
    )
    clarification_prompt: str | None = Field(
        default=None,
        description="Suggested clarification prompt for the user when ambiguous",
    )
    source_request: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Raw, normalized user input prompt that generated this intent",
    )

    @field_validator("search_query")
    @classmethod
    def validate_search_query(cls, v: str | None) -> str | None:
        if v is not None:
            stripped = v.strip()
            if not stripped:
                raise ValueError("Search query cannot be empty or whitespace only.")
            return stripped
        return None

    @field_validator("response_language")
    @classmethod
    def validate_response_language(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean in ("ar", "arabic", "عربي", "العربية"):
            return "ar"
        if clean in ("en", "english", "انجليزي", "الانجليزية"):
            return "en"
        return clean or "en"

    @model_validator(mode="after")
    def validate_intent_consistency(self) -> Self:
        """Enforce internal consistency between intent_type and required attributes."""
        if self.requires_clarification or self.is_ambiguous:
            if not self.clarification_prompt:
                raise ValueError(
                    "clarification_prompt is required when is_ambiguous or requires_clarification is True."
                )
            return self

        match self.intent_type:
            case IntentType.READ_LATEST_EMAILS:
                if self.requested_count is None:
                    raise ValueError(
                        "requested_count is required for READ_LATEST_EMAILS."
                    )
            case IntentType.SUMMARIZE_RECENT_EMAILS:
                if self.requested_count is None:
                    raise ValueError(
                        "requested_count is required for SUMMARIZE_RECENT_EMAILS."
                    )
            case IntentType.SEARCH_EMAILS:
                if not self.search_query:
                    raise ValueError("search_query is required for SEARCH_EMAILS.")
            case IntentType.READ_EMAIL_DETAILS:
                if self.requested_email_id is None:
                    raise ValueError(
                        "requested_email_id is required for READ_EMAIL_DETAILS."
                    )
            case IntentType.AMBIGUOUS:
                if not self.clarification_prompt:
                    raise ValueError(
                        "clarification_prompt is required for AMBIGUOUS intent."
                    )
        return self

    @property
    def is_valid(self) -> bool:
        """True if the intent is fully resolved, unambiguous, and ready for policy proposal."""
        return (
            not self.is_ambiguous
            and not self.requires_clarification
            and self.intent_type != IntentType.AMBIGUOUS
        )

    @property
    def target_tool_name(self) -> str | None:
        """Map intent to underlying system tool name if valid."""
        match self.intent_type:
            case IntentType.READ_LATEST_EMAILS:
                return "read_inbox"
            case IntentType.SUMMARIZE_RECENT_EMAILS:
                return "read_inbox"
            case IntentType.SEARCH_EMAILS:
                return "search_emails"
            case IntentType.READ_EMAIL_DETAILS:
                return "get_email_details"
            case _:
                return None
