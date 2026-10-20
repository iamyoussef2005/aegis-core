"""Tools package for AEGIS-CORE Mini AI Agent."""

from app.agent.tools.email_tools import (
    EMAIL_TOOLS,
    GET_EMAIL_DETAILS_TOOL_SPEC,
    READ_INBOX_TOOL_SPEC,
    SEARCH_EMAILS_TOOL_SPEC,
    get_email_details,
    get_session_context,
    get_tool_specs,
    read_inbox,
    search_emails,
)

__all__ = [
    "EMAIL_TOOLS",
    "GET_EMAIL_DETAILS_TOOL_SPEC",
    "READ_INBOX_TOOL_SPEC",
    "SEARCH_EMAILS_TOOL_SPEC",
    "get_email_details",
    "get_session_context",
    "get_tool_specs",
    "read_inbox",
    "search_emails",
]
