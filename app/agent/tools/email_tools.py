"""Python-callable agent tool adapters for simulated email access in AEGIS-CORE.

==============================================================================
CRITICAL ARCHITECTURAL CONTEXT & ACCESS BOUNDARY NOTICE:
------------------------------------------------------------------------------
The `user_id` parameter across these tool adapters serves strictly as a local
simulation identity selector (inbox partitioner) within our research environment,
NOT a cryptographically authenticated session identity.

THESE ADAPTERS DO NOT PROVIDE PRODUCTION-GRADE AUTHORIZATION.
In upcoming roadmap milestones (Weeks 3-5), these tool adapters will be wrapped
and intercepted by the AEGIS-CORE execution firewall to enforce cryptographic
agent session tokens, permission manifests, and human-in-the-loop approvals.
==============================================================================
"""

from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.agent.schemas import (
    GetEmailDetailsInput,
    ReadInboxData,
    ReadInboxInput,
    SearchEmailsData,
    SearchEmailsInput,
    ToolError,
    ToolResult,
)
from app.db.session import SessionLocal
from app.schemas.email import EmailMessageResponse
from app.services.email import EmailService
from app.services.user import UserService


@contextmanager
def get_session_context(
    session: Session | None = None,
) -> Generator[Session, None, None]:
    """Provide a database session, reusing an existing session or creating a scoped SessionLocal.

    If an external session is provided (e.g. from a test fixture), the caller owns
    its lifecycle and this context manager will not close or dispose it.
    If no session is provided, a fresh SessionLocal session is created and closed on exit.
    """
    if session is not None:
        yield session
    else:
        with SessionLocal() as new_session:
            yield new_session


# ---------------------------------------------------------------------------
# Tool Specifications (JSON Schema standard for Agent Runtimes)
# ---------------------------------------------------------------------------

READ_INBOX_TOOL_SPEC: dict[str, Any] = {
    "name": "read_inbox",
    "description": (
        "Reads recent emails from the simulated user's inbox with pagination "
        "and optional read-status filtering. Results are strictly owner-scoped."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "user_id": {
                "type": "integer",
                "description": "Simulated user ID (local simulation identity selector)",
                "minimum": 1,
            },
            "limit": {
                "type": "integer",
                "description": "Number of emails to return (1-20, default 5)",
                "default": 5,
                "minimum": 1,
                "maximum": 20,
            },
            "offset": {
                "type": "integer",
                "description": "Offset pagination count (default 0)",
                "default": 0,
                "minimum": 0,
            },
            "is_read": {
                "type": "boolean",
                "description": "Optional filter: true for read, false for unread, null for all",
            },
        },
        "required": ["user_id"],
    },
}

GET_EMAIL_DETAILS_TOOL_SPEC: dict[str, Any] = {
    "name": "get_email_details",
    "description": (
        "Fetches the complete details and body text of a single simulated email by its ID. "
        "Returns EMAIL_NOT_FOUND if the email does not exist or belongs to another user."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "user_id": {
                "type": "integer",
                "description": "Simulated user ID (local simulation identity selector)",
                "minimum": 1,
            },
            "email_id": {
                "type": "integer",
                "description": "Unique integer ID of the email message to retrieve",
                "minimum": 1,
            },
        },
        "required": ["user_id", "email_id"],
    },
}

SEARCH_EMAILS_TOOL_SPEC: dict[str, Any] = {
    "name": "search_emails",
    "description": (
        "Searches the simulated user's emails by keyword across subject and body content. "
        "Performs case-insensitive matching with bound parameters and wildcard escaping."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "user_id": {
                "type": "integer",
                "description": "Simulated user ID (local simulation identity selector)",
                "minimum": 1,
            },
            "query": {
                "type": "string",
                "description": "Search keyword or phrase (supports English and Arabic UTF-8)",
                "minLength": 1,
                "maxLength": 200,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of search results to return (1-10, default 5)",
                "default": 5,
                "minimum": 1,
                "maximum": 10,
            },
            "offset": {
                "type": "integer",
                "description": "Pagination offset count (default 0)",
                "default": 0,
                "minimum": 0,
            },
        },
        "required": ["user_id", "query"],
    },
}


def get_tool_specs() -> list[dict[str, Any]]:
    """Return JSON schema specifications for all available agent tools."""
    return [
        READ_INBOX_TOOL_SPEC,
        GET_EMAIL_DETAILS_TOOL_SPEC,
        SEARCH_EMAILS_TOOL_SPEC,
    ]


# ---------------------------------------------------------------------------
# Tool Adapter Implementations
# ---------------------------------------------------------------------------


def read_inbox(
    user_id: int,
    limit: int = 5,
    offset: int = 0,
    is_read: bool | None = None,
    *,
    session: Session | None = None,
) -> ToolResult[ReadInboxData]:
    """Retrieve bounded, owner-scoped messages from the simulated user's inbox.

    Args:
        user_id: Simulated user ID (simulation selector).
        limit: Maximum number of messages to return (1-20, default 5).
        offset: Number of messages to skip for pagination (default 0).
        is_read: Optional filter for read (True), unread (False), or all (None).
        session: Optional SQLAlchemy Session. If omitted, a managed session is used.

    Returns:
        ToolResult with ReadInboxData on success, or ToolError on validation/lookup failure.
    """
    try:
        validated = ReadInboxInput(
            user_id=user_id,
            limit=limit,
            offset=offset,
            is_read=is_read,
        )
    except ValidationError as err:
        return ToolResult(
            success=False,
            tool_name="read_inbox",
            error=ToolError(
                code="VALIDATION_ERROR",
                message=f"Invalid arguments for read_inbox: {err.error_count()} error(s)",
                details=err.errors(include_url=False),
            ),
        )

    with get_session_context(session) as db:
        email_service = EmailService(db)
        email_list = email_service.list_user_emails(
            user_id=validated.user_id,
            offset=validated.offset,
            limit=validated.limit,
            is_read=validated.is_read,
        )
        if email_list is None:
            return ToolResult(
                success=False,
                tool_name="read_inbox",
                error=ToolError(
                    code="USER_NOT_FOUND",
                    message=f"User with ID {validated.user_id} not found",
                ),
            )

        return ToolResult(
            success=True,
            tool_name="read_inbox",
            data=ReadInboxData(
                emails=email_list.items,
                count=len(email_list.items),
                total=email_list.total,
                owner_id=validated.user_id,
                limit=validated.limit,
                offset=validated.offset,
            ),
        )


def get_email_details(
    user_id: int,
    email_id: int,
    *,
    session: Session | None = None,
) -> ToolResult[EmailMessageResponse]:
    """Fetch complete details and body text for a single email, strictly verifying ownership.

    Returns an error if the email does not exist or if it belongs to another user,
    preventing cross-tenant metadata revelation.

    Args:
        user_id: Simulated user ID (simulation selector).
        email_id: Unique integer ID of the email message to retrieve.
        session: Optional SQLAlchemy Session. If omitted, a managed session is used.

    Returns:
        ToolResult with EmailMessageResponse on success, or ToolError on failure.
    """
    try:
        validated = GetEmailDetailsInput(
            user_id=user_id,
            email_id=email_id,
        )
    except ValidationError as err:
        return ToolResult(
            success=False,
            tool_name="get_email_details",
            error=ToolError(
                code="VALIDATION_ERROR",
                message=f"Invalid arguments for get_email_details: {err.error_count()} error(s)",
                details=err.errors(include_url=False),
            ),
        )

    with get_session_context(session) as db:
        user_service = UserService(db)
        if user_service.get_user_by_id(validated.user_id) is None:
            return ToolResult(
                success=False,
                tool_name="get_email_details",
                error=ToolError(
                    code="USER_NOT_FOUND",
                    message=f"User with ID {validated.user_id} not found",
                ),
            )

        email_service = EmailService(db)
        email = email_service.get_user_email(
            user_id=validated.user_id,
            email_id=validated.email_id,
        )
        if email is None:
            return ToolResult(
                success=False,
                tool_name="get_email_details",
                error=ToolError(
                    code="EMAIL_NOT_FOUND",
                    message=f"Email with ID {validated.email_id} not found for user {validated.user_id}",
                ),
            )

        return ToolResult(
            success=True,
            tool_name="get_email_details",
            data=email,
        )


def search_emails(
    user_id: int,
    query: str,
    limit: int = 5,
    offset: int = 0,
    *,
    session: Session | None = None,
) -> ToolResult[SearchEmailsData]:
    """Perform case-insensitive keyword search over subject and body within the user's inbox.

    Uses bound parameters and escapes SQL LIKE wildcard characters (%, _, /).
    Guarantees strict owner isolation: foreign messages are never searched or returned.

    Args:
        user_id: Simulated user ID (simulation selector).
        query: Search string or keyword (supports English and Arabic).
        limit: Maximum results to return (1-10, default 5).
        offset: Offset for pagination (default 0).
        session: Optional SQLAlchemy Session. If omitted, a managed session is used.

    Returns:
        ToolResult with SearchEmailsData on success, or ToolError on validation/lookup failure.
    """
    try:
        validated = SearchEmailsInput(
            user_id=user_id,
            query=query,
            limit=limit,
            offset=offset,
        )
    except ValidationError as err:
        return ToolResult(
            success=False,
            tool_name="search_emails",
            error=ToolError(
                code="VALIDATION_ERROR",
                message=f"Invalid arguments for search_emails: {err.error_count()} error(s)",
                details=err.errors(include_url=False),
            ),
        )

    with get_session_context(session) as db:
        email_service = EmailService(db)
        results = email_service.search_user_emails(
            user_id=validated.user_id,
            query=validated.query,
            limit=validated.limit,
            offset=validated.offset,
        )
        if results is None:
            return ToolResult(
                success=False,
                tool_name="search_emails",
                error=ToolError(
                    code="USER_NOT_FOUND",
                    message=f"User with ID {validated.user_id} not found",
                ),
            )

        total = email_service.count_search_user_emails(
            user_id=validated.user_id,
            query=validated.query,
        )

        return ToolResult(
            success=True,
            tool_name="search_emails",
            data=SearchEmailsData(
                emails=results,
                count=len(results),
                total=total or 0,
                owner_id=validated.user_id,
                query=validated.query,
                limit=validated.limit,
                offset=validated.offset,
            ),
        )


EMAIL_TOOLS: dict[str, Callable[..., ToolResult[Any]]] = {
    "read_inbox": read_inbox,
    "get_email_details": get_email_details,
    "search_emails": search_emails,
}
