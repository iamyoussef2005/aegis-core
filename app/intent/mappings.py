"""Deterministic Intent-to-Permission Mapping Engine for AEGIS-CORE.

==============================================================================
CRITICAL SECURITY INVARIANTS:
------------------------------------------------------------------------------
1. Strict allowlisted tool mappings:
   - READ_LATEST_EMAILS      -> read_inbox (max_limit=N, max_offset=0)
   - SUMMARIZE_RECENT_EMAILS -> read_inbox (max_limit=N, max_offset=0)
   - SEARCH_EMAILS           -> search_emails (max_limit=5, max_offset=0, allowed_search_terms={query})
   - READ_EMAIL_DETAILS      -> get_email_details (allowed_email_ids={id})
2. Exact argument constraints: No wildcards, no broad offset ranges.
3. Separation of presentation language: response_language specifies presentation
   only and confers ZERO additional tool access.
4. Fail-closed: Ambiguous, compound, or unlisted intents produce ZERO proposals.
5. Zero side-effects: No database sessions, no network calls, zero tool adapter executions.
==============================================================================
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from app.intent.exceptions import ProposalSecurityError
from app.intent.proposals import (
    PermissionProposal,
    ProposalStatus,
)
from app.intent.schemas import IntentType, TaskIntent
from app.security.schemas import (
    GetEmailDetailsConstraint,
    ReadInboxConstraint,
    SearchEmailsConstraint,
)

# Standard small bound for proposed search limit (Defense in Depth)
DEFAULT_SEARCH_PROPOSAL_LIMIT: int = 5

# Default time-to-live for proposals before expiration (5 minutes)
DEFAULT_PROPOSAL_TTL_SECONDS: int = 300


def map_intent_to_proposal(
    intent: TaskIntent,
    user_id: int,
    task_id: str | None = None,
    ttl_seconds: int = DEFAULT_PROPOSAL_TTL_SECONDS,
) -> PermissionProposal:
    """Deterministically map a validated TaskIntent to a minimal PermissionProposal.

    Args:
        intent: Validated, unambiguous TaskIntent.
        user_id: Server-controlled simulated user identity.
        task_id: Optional correlation task ID. If omitted, generates a unique ID.
        ttl_seconds: Time-to-live in seconds before the proposal expires.

    Returns:
        An immutable, unapproved PermissionProposal in PENDING status.

    Raises:
        ProposalSecurityError: If intent is ambiguous, unsupported, or violates constraints.
        ValueError: If user_id < 1 or parameters are invalid.
    """
    if user_id < 1:
        raise ValueError(f"user_id must be a positive integer, got: {user_id}")

    if intent.is_ambiguous or intent.requires_clarification:
        raise ProposalSecurityError(
            "Cannot generate a permission proposal for an ambiguous or unclarified intent. "
            f"Clarification prompt: '{intent.clarification_prompt}'"
        )

    if not intent.is_valid:
        raise ProposalSecurityError(
            f"Cannot generate a permission proposal for invalid intent of type '{intent.intent_type}'."
        )

    # Generate unforgeable proposal ID and bound timestamps
    proposal_id = f"prop_{secrets.token_hex(16)}"
    effective_task_id = task_id or f"task_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(seconds=ttl_seconds)

    match intent.intent_type:
        case IntentType.READ_LATEST_EMAILS:
            count = intent.requested_count
            if count is None or count < 1 or count > 20:
                raise ProposalSecurityError(
                    f"Invalid requested count ({count}) for READ_LATEST_EMAILS."
                )

            tool_name = "read_inbox"
            constraint = ReadInboxConstraint(
                max_limit=count,
                max_offset=0,
                allowed_is_read=None,
            )
            summary = f"Read latest {count} emails from user inbox (offset=0)."
            rationale = (
                f"Directly derived from user request to read {count} latest emails. "
                f"Scoped strictly to limit={count} and offset=0 under least privilege."
            )

        case IntentType.SUMMARIZE_RECENT_EMAILS:
            count = intent.requested_count
            if count is None or count < 1 or count > 20:
                raise ProposalSecurityError(
                    f"Invalid requested count ({count}) for SUMMARIZE_RECENT_EMAILS."
                )

            tool_name = "read_inbox"
            constraint = ReadInboxConstraint(
                max_limit=count,
                max_offset=0,
                allowed_is_read=None,
            )
            summary = f"Read latest {count} emails from user inbox for summarization (offset=0)."
            rationale = (
                f"Summarization requires reading recent emails. Scoped strictly to limit={count} "
                f"and offset=0. Requested presentation language ('{intent.response_language}') "
                "grants zero additional tool permissions."
            )

        case IntentType.SEARCH_EMAILS:
            query = intent.search_query
            if not query or not query.strip():
                raise ProposalSecurityError(
                    "Missing or empty search query for SEARCH_EMAILS proposal."
                )
            clean_query = query.strip()
            if len(clean_query) > 200:
                raise ProposalSecurityError(
                    f"Search query exceeds maximum limit of 200 characters ({len(clean_query)})."
                )

            tool_name = "search_emails"
            constraint = SearchEmailsConstraint(
                max_limit=DEFAULT_SEARCH_PROPOSAL_LIMIT,
                max_offset=0,
                allowed_search_terms=frozenset({clean_query}),
                max_query_length=max(len(clean_query) + 20, 50),
            )
            summary = (
                f"Search user emails matching exact term '{clean_query}' "
                f"(max {DEFAULT_SEARCH_PROPOSAL_LIMIT} results, offset=0)."
            )
            rationale = (
                f"User requested search for keyword '{clean_query}'. Scoped strictly to "
                f"allowed_search_terms matching exact term, max_limit={DEFAULT_SEARCH_PROPOSAL_LIMIT}, "
                "and offset=0 under least privilege."
            )

        case IntentType.READ_EMAIL_DETAILS:
            email_id = intent.requested_email_id
            if email_id is None or email_id < 1:
                raise ProposalSecurityError(
                    f"Invalid email_id ({email_id}) for READ_EMAIL_DETAILS proposal."
                )

            tool_name = "get_email_details"
            constraint = GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({email_id}),
                max_email_id=email_id,
            )
            summary = f"Inspect email details strictly for email ID {email_id}."
            rationale = (
                f"User requested inspection of specific email ID {email_id}. "
                f"Scoped allowed_email_ids allowlist to exact single ID {{{email_id}}}."
            )

        case _:
            raise ProposalSecurityError(
                f"Unsupported intent type for permission proposal: '{intent.intent_type}'."
            )

    return PermissionProposal(
        proposal_id=proposal_id,
        task_id=effective_task_id,
        user_id=user_id,
        normalized_intent=intent,
        requested_tool=tool_name,
        requested_constraints={tool_name: constraint},
        human_readable_summary=summary,
        rationale=rationale,
        created_at=created_at,
        expires_at=expires_at,
        status=ProposalStatus.PENDING,
        proposal_version="1.0.0",
    )
