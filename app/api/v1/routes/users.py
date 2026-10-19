"""FastAPI route handlers for simulated users and owner-scoped mock email access.

==============================================================================
SECURITY MODEL & ACCESS BOUNDARY NOTICE (WEEK 1 RESEARCH SIMULATOR):
------------------------------------------------------------------------------
These endpoints operate exclusively on synthetic academic data for local AI
agent security experiments. The `user_id` parameter serves as an experimental
tenant/inbox selector for simulation scenarios, NOT an authenticated identity.

THIS IS NOT A PRODUCTION MULTI-USER API.
In upcoming roadmap milestones (Week 2+ Auth / Week 4 Policy Engine), these
endpoints will be intercepted by the AEGIS-CORE security firewall to enforce
cryptographic credentials, agent manifests, and human-in-the-loop approvals.
==============================================================================
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.email import (
    EmailCountResponse,
    EmailListResponse,
    EmailMessageResponse,
)
from app.schemas.user import UserResponse
from app.services.email import EmailService
from app.services.user import UserService

router = APIRouter(prefix="/users", tags=["Simulated Users & Email Inbox"])


@router.get(
    "",
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List Simulated Users",
    description=(
        "Retrieves the list of simulated academic user accounts in the mock environment. "
        "Does not expose credentials or internal configuration keys."
    ),
)
def get_users(
    session: Annotated[Session, Depends(get_db)],
) -> list[UserResponse]:
    """List all available demo users."""
    service = UserService(session)
    return service.list_users()


@router.get(
    "/{user_id}/emails/count",
    response_model=EmailCountResponse,
    status_code=status.HTTP_200_OK,
    summary="Count User Emails",
    description=(
        "Returns the total number of emails for a specified simulated user. "
        "Supports optional filtering by read status (is_read=true/false)."
    ),
    responses={404: {"description": "User not found"}},
)
def get_user_email_count(
    user_id: int,
    session: Annotated[Session, Depends(get_db)],
    is_read: Annotated[
        bool | None,
        Query(description="Filter by read status (true or false)"),
    ] = None,
) -> EmailCountResponse:
    """Return count of emails belonging to the user."""
    service = EmailService(session)
    count_data = service.get_user_email_count(user_id=user_id, is_read=is_read)
    if count_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )
    return count_data


@router.get(
    "/{user_id}/emails/recent",
    response_model=list[EmailMessageResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Recent User Emails",
    description=(
        "Returns the latest simulated emails for a specified user, ordered by "
        "received timestamp descending (most recent first). Default count is 3 (max 10)."
    ),
    responses={404: {"description": "User not found"}},
)
def get_recent_user_emails(
    user_id: int,
    session: Annotated[Session, Depends(get_db)],
    count: Annotated[
        int,
        Query(
            ge=1,
            le=10,
            description="Number of recent emails to retrieve (1-10)",
        ),
    ] = 3,
) -> list[EmailMessageResponse]:
    """Return most recent emails for the given user."""
    service = EmailService(session)
    recent_emails = service.get_recent_user_emails(user_id=user_id, count=count)
    if recent_emails is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )
    return recent_emails


@router.get(
    "/{user_id}/emails",
    response_model=EmailListResponse,
    status_code=status.HTTP_200_OK,
    summary="List User Emails",
    description=(
        "Lists emails belonging to the specified user with deterministic pagination "
        "and read-status filtering. Sorts by received_at descending, then id descending."
    ),
    responses={404: {"description": "User not found"}},
)
def get_user_emails(
    user_id: int,
    session: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Maximum number of emails to return (default 10, max 100)",
        ),
    ] = 10,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Pagination offset (number of records to skip)",
        ),
    ] = 0,
    is_read: Annotated[
        bool | None,
        Query(description="Filter by read status (true or false)"),
    ] = None,
) -> EmailListResponse:
    """List paginated emails for the user."""
    service = EmailService(session)
    email_list = service.list_user_emails(
        user_id=user_id,
        offset=offset,
        limit=limit,
        is_read=is_read,
    )
    if email_list is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )
    return email_list


@router.get(
    "/{user_id}/emails/{email_id}",
    response_model=EmailMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Single User Email",
    description=(
        "Retrieves a single email message scoped strictly to its owner. Returns 404 "
        "if the user or email does not exist, or if the email belongs to another user. "
        "Never leaks cross-tenant information."
    ),
    responses={404: {"description": "User or email message not found"}},
)
def get_user_email_by_id(
    user_id: int,
    email_id: int,
    session: Annotated[Session, Depends(get_db)],
) -> EmailMessageResponse:
    """Fetch single email strictly verifying ownership."""
    service = EmailService(session)
    email = service.get_user_email(user_id=user_id, email_id=email_id)
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID {email_id} not found for user {user_id}",
        )
    return email
