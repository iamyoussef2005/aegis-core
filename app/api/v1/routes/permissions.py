"""FastAPI route handlers for permission proposals and explicit approval lifecycle.

==============================================================================
CRITICAL SECURITY MODEL & LOCAL SIMULATION NOTICE:
------------------------------------------------------------------------------
This API mediates AI agent tool permissions in a local academic simulation.
A public HTTP approve endpoint without authentication is NOT proof of human
approval or production security.

For this milestone, AEGIS-CORE enforces an explicit local demonstration controller
trust boundary:
1. Approval actions require an explicit trusted local controller identifier
   (e.g., 'local-supervisor' via Header or Request Body).
2. Model agents, automated scripts, or untrusted callers are strictly denied (403).
3. Approved proposals are sealed into immutable TaskPolicies with exact argument bounds.
4. Neither the client nor the model can supply substitute policies or widened limits.
==============================================================================
"""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.intent.approval import (
    PermissionApprovalService,
    default_approval_service,
)
from app.intent.exceptions import (
    EmptyRequestError,
    IntentError,
    InvalidProposalTransitionError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalReplayError,
    ProposalSecurityError,
    ProposalStateError,
    UntrustedControllerError,
)
from app.intent.proposals import ProposalStatus
from app.services.user import UserService

router = APIRouter(prefix="/permissions", tags=["Permission Proposals & Approvals"])


def get_approval_service() -> PermissionApprovalService:
    """Dependency provider returning the default server-side approval service singleton."""
    return default_approval_service


# ---------------------------------------------------------------------------
# Request and Response Schemas
# ---------------------------------------------------------------------------


class PermissionProposeRequest(BaseModel):
    """Input payload for generating a permission proposal from user intent."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(
        ...,
        ge=1,
        description="Simulated user account identifier (tenant selector)",
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="User task request or inquiry to parse into bounded permissions",
    )
    task_id: str | None = Field(
        default=None,
        description="Optional correlation task identifier. If omitted, generated automatically.",
    )


class PermissionProposeResponse(BaseModel):
    """Structured response detailing the generated unapproved permission proposal."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(
        ..., description="Cryptographically unforgeable proposal identifier"
    )
    task_id: str = Field(..., description="Bound task correlation identifier")
    user_id: int = Field(..., description="Bound user identity")
    requested_tool: str = Field(..., description="Exact single allowlisted tool name")
    requested_constraints: dict[str, Any] = Field(
        ..., description="Tool argument constraints derived under least privilege"
    )
    human_readable_summary: str = Field(..., description="Human-auditable explanation")
    rationale: str = Field(..., description="Security rationale for constraints")
    status: ProposalStatus = Field(
        ..., description="Proposal lifecycle state (PENDING)"
    )
    expires_at: datetime | None = Field(
        default=None, description="Expiration timestamp"
    )
    created_at: datetime = Field(..., description="Creation timestamp")
    proposal_version: str = Field(
        default="1.0.0", description="Proposal schema version"
    )


class PermissionApproveRequest(BaseModel):
    """Input payload for approving a stored permission proposal."""

    model_config = ConfigDict(extra="forbid")

    controller_id: str | None = Field(
        default=None,
        description="Explicit identifier of trusted demonstration controller approving the proposal",
    )
    reason: str = Field(
        default="Explicit local supervisor review",
        min_length=3,
        description="Auditable justification for approval",
    )


class PermissionApproveResponse(BaseModel):
    """Receipt returned upon successful activation of an approved proposal."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(..., description="Approved proposal identifier")
    task_id: str = Field(..., description="Bound task identifier")
    user_id: int = Field(..., description="Bound simulated user identifier")
    status: ProposalStatus = Field(..., description="Updated status (APPROVED)")
    authorized_tool: str = Field(..., description="Single authorized tool name")
    approved_at: datetime = Field(..., description="Approval timestamp")
    approved_by: str = Field(..., description="Controller that approved the proposal")
    message: str = Field(..., description="Status summary message")


class PermissionRejectRequest(BaseModel):
    """Input payload for explicitly rejecting a proposal."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        default="Rejected by supervisor",
        min_length=3,
        description="Auditable justification for rejection",
    )
    controller_id: str = Field(
        default="local-supervisor",
        min_length=1,
        description="Controller identifier rejecting the proposal",
    )


class PermissionRejectResponse(BaseModel):
    """Receipt returned upon successful rejection of a proposal."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(..., description="Rejected proposal identifier")
    status: ProposalStatus = Field(..., description="Updated status (REJECTED)")
    rejected_at: datetime = Field(
        default_factory=lambda: datetime.now(
            datetime.UTC if hasattr(datetime, "UTC") else None
        ),
        description="Rejection timestamp",
    )
    message: str = Field(..., description="Status summary message")


# ---------------------------------------------------------------------------
# API Route Handlers
# ---------------------------------------------------------------------------


@router.post(
    "/propose",
    response_model=PermissionProposeResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Permission Proposal from Natural Language",
    description=(
        "Parses user intent from natural language, derives minimal tool permissions "
        "and argument constraints, and stores a PermissionProposal in strictly PENDING status. "
        "Does NOT execute tools or activate any policies."
    ),
    responses={
        404: {"description": "Simulated user not found"},
        422: {"description": "Ambiguous, empty, or unsupported user intent"},
    },
)
def create_permission_proposal(
    request: PermissionProposeRequest,
    session: Annotated[Session, Depends(get_db)],
    approval_service: Annotated[
        PermissionApprovalService, Depends(get_approval_service)
    ],
) -> PermissionProposeResponse:
    """Generate a bounded permission proposal from natural language input."""
    # Verify user account exists
    user_service = UserService(session)
    user_record = user_service.get_user_by_id(request.user_id)
    if user_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {request.user_id} not found.",
        )

    try:
        proposal = approval_service.propose(
            user_id=request.user_id,
            message=request.message,
            task_id=request.task_id,
        )
    except EmptyRequestError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        ) from err
    except (ProposalSecurityError, IntentError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unable to propose permissions: {err}",
        ) from err

    # Serialize constraints safely
    serialized_constraints: dict[str, Any] = {
        tool_name: constraint.model_dump()
        for tool_name, constraint in proposal.requested_constraints.items()
    }

    return PermissionProposeResponse(
        proposal_id=proposal.proposal_id,
        task_id=proposal.task_id,
        user_id=proposal.user_id,
        requested_tool=proposal.requested_tool,
        requested_constraints=serialized_constraints,
        human_readable_summary=proposal.human_readable_summary,
        rationale=proposal.rationale,
        status=proposal.status,
        expires_at=proposal.expires_at,
        created_at=proposal.created_at,
        proposal_version=proposal.proposal_version,
    )


@router.post(
    "/{proposal_id}/approve",
    response_model=PermissionApproveResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve Stored Permission Proposal",
    description=(
        "Explicitly approves a stored server-generated PermissionProposal via a trusted local "
        "demonstration controller, sealing it into an immutable TaskPolicy. "
        "Does NOT accept client-supplied replacement policies or widened bounds."
    ),
    responses={
        403: {"description": "Untrusted or model-generated approval attempt"},
        404: {"description": "Proposal not found"},
        409: {"description": "Proposal already approved, consumed, or invalid state"},
        410: {"description": "Proposal expired"},
    },
)
def approve_permission_proposal(
    proposal_id: str,
    approval_service: Annotated[
        PermissionApprovalService, Depends(get_approval_service)
    ],
    request: PermissionApproveRequest | None = None,
    x_aegis_controller: Annotated[
        str | None, Header(alias="X-AEGIS-Controller")
    ] = None,
) -> PermissionApproveResponse:
    """Explicitly activate a pending permission proposal via trusted controller."""
    # Determine effective controller identity:
    # Must be explicitly provided via 'X-AEGIS-Controller' header or 'controller_id' in body.
    # It must never silently default to an authorized supervisor when omitted.
    effective_controller = x_aegis_controller or (
        request.controller_id if request and request.controller_id else None
    )
    if not effective_controller or not effective_controller.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Missing trusted controller authorization. Approval requires an explicit trusted "
                "controller identity supplied via the 'X-AEGIS-Controller' header or 'controller_id' in request body."
            ),
        )
    reason = request.reason if request else "Explicit local supervisor review"

    try:
        receipt, _ = approval_service.approve(
            proposal_id=proposal_id,
            controller_id=effective_controller,
            reason=reason,
        )
    except UntrustedControllerError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        ) from err
    except ProposalNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except ProposalExpiredError as err:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=str(err),
        ) from err
    except (
        ProposalStateError,
        ProposalReplayError,
        InvalidProposalTransitionError,
    ) as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err
    except ProposalSecurityError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        ) from err

    return PermissionApproveResponse(
        proposal_id=receipt.proposal_id,
        task_id=receipt.task_id,
        user_id=receipt.user_id,
        status=receipt.status,
        authorized_tool=receipt.authorized_tool,
        approved_at=receipt.approved_at,
        approved_by=receipt.approved_by,
        message=receipt.message,
    )


@router.post(
    "/{proposal_id}/reject",
    response_model=PermissionRejectResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject Stored Permission Proposal",
    description="Explicitly rejects a pending proposal, preventing policy activation.",
    responses={
        404: {"description": "Proposal not found"},
        409: {"description": "Proposal is not in PENDING state"},
    },
)
def reject_permission_proposal(
    proposal_id: str,
    approval_service: Annotated[
        PermissionApprovalService, Depends(get_approval_service)
    ],
    request: PermissionRejectRequest | None = None,
) -> PermissionRejectResponse:
    """Explicitly reject a pending permission proposal."""
    controller_id = request.controller_id if request else "local-supervisor"
    reason = request.reason if request else "Rejected by supervisor"

    try:
        rejected = approval_service.reject(
            proposal_id=proposal_id,
            controller_id=controller_id,
            reason=reason,
        )
    except ProposalNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except (ProposalStateError, InvalidProposalTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err

    now = datetime.now(datetime.UTC if hasattr(datetime, "UTC") else None)
    return PermissionRejectResponse(
        proposal_id=rejected.proposal_id,
        status=rejected.status,
        rejected_at=now,
        message=f"Proposal '{proposal_id}' was rejected: {reason}",
    )
