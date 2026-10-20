"""Permission proposal schemas and contracts for AEGIS-CORE.

==============================================================================
CRITICAL TRUST RULE:
------------------------------------------------------------------------------
A proposal is NOT an approved policy.
The proposal must NEVER directly authorize execution.
It encapsulates an unapproved, proposed security perimeter generated from a
validated TaskIntent. It cannot be evaluated as an active policy by the
PolicyEngine or ToolExecutor until explicitly approved and sealed into an
immutable TaskPolicy by a trusted supervisor or human authority.
==============================================================================
"""

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.agent.tool_registry import ALLOWED_TOOL_NAMES
from app.intent.exceptions import ProposalSecurityError
from app.intent.schemas import TaskIntent
from app.security.schemas import KNOWN_SYSTEM_TOOLS, BaseToolConstraint

__all__ = [
    "PermissionProposal",
    "ProposalSecurityError",
    "ProposalStatus",
]


class ProposalStatus(StrEnum):
    """Lifecycle status of a permission proposal."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class PermissionProposal(BaseModel):
    """Immutable data contract representing an unapproved, proposed tool permission."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str = Field(
        ...,
        min_length=16,
        description="Cryptographically unpredictable unique proposal identifier",
    )
    task_id: str = Field(
        ...,
        min_length=1,
        description="Server-controlled correlation task identifier",
    )
    user_id: int = Field(
        ...,
        ge=1,
        description="Server-verified simulated user identity",
    )
    normalized_intent: TaskIntent = Field(
        ...,
        description="The validated, unambiguous TaskIntent driving this proposal",
    )
    requested_tool: str = Field(
        ...,
        description="Single exact allowlisted tool name",
    )
    requested_constraints: dict[str, BaseToolConstraint] = Field(
        ...,
        description="Tool-specific argument constraints derived under least privilege",
    )
    human_readable_summary: str = Field(
        ...,
        min_length=5,
        description="Concise human-readable explanation of proposed permissions",
    )
    rationale: str = Field(
        ...,
        min_length=5,
        description="Auditable security rationale detailing why constraints were selected",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="UTC expiration timestamp after which the proposal cannot be approved",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of proposal creation",
    )
    status: ProposalStatus = Field(
        default=ProposalStatus.PENDING,
        description="Current lifecycle status of proposal (strictly PENDING upon creation)",
    )
    proposal_version: str = Field(
        default="1.0.0",
        description="Semver schema version of permission proposal",
    )

    @field_validator("requested_tool")
    @classmethod
    def validate_requested_tool(cls, v: str) -> str:
        if v not in ALLOWED_TOOL_NAMES or v not in KNOWN_SYSTEM_TOOLS:
            raise ValueError(
                f"Requested tool '{v}' is not recognized in allowed system tools: {sorted(ALLOWED_TOOL_NAMES)}"
            )
        return v

    @field_validator("proposal_id")
    @classmethod
    def validate_proposal_id(cls, v: str) -> str:
        if not re.match(r"^prop_[a-f0-9]{16,64}$", v):
            raise ValueError(
                f"proposal_id '{v}' is not a valid unforgeable format (expected 'prop_<hex>')."
            )
        return v

    @model_validator(mode="after")
    def validate_proposal_integrity(self) -> Self:
        # Invariant: Intent must not be ambiguous or require clarification
        if (
            self.normalized_intent.is_ambiguous
            or self.normalized_intent.requires_clarification
        ):
            raise ValueError(
                "Cannot create a PermissionProposal for an ambiguous or unresolved TaskIntent."
            )

        # Invariant: Constraints must match requested tool
        if self.requested_tool not in self.requested_constraints:
            raise ValueError(
                f"requested_constraints must contain constraints for requested tool '{self.requested_tool}'."
            )

        # Invariant: Only one exact tool permission per proposal (no multi-tool bundling)
        if len(self.requested_constraints) != 1:
            raise ValueError(
                f"PermissionProposal must constrain exactly one tool, got: {list(self.requested_constraints.keys())}"
            )

        # Invariant: Expiration must be after creation
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError(
                f"Proposal expiration ({self.expires_at}) must be strictly after creation ({self.created_at})."
            )

        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if proposal has expired."""
        if self.expires_at is None:
            return False
        current_time = now or datetime.now(UTC)
        return current_time > self.expires_at

    @property
    def is_pending(self) -> bool:
        """Check if proposal is in PENDING status."""
        return self.status == ProposalStatus.PENDING

    @property
    def is_approved(self) -> bool:
        """Check if proposal is in APPROVED status."""
        return self.status == ProposalStatus.APPROVED

    @property
    def is_rejected(self) -> bool:
        """Check if proposal is in REJECTED status."""
        return self.status == ProposalStatus.REJECTED

    @property
    def is_consumed(self) -> bool:
        """Check if proposal is in CONSUMED status."""
        return self.status == ProposalStatus.CONSUMED
