"""Predefined demonstration policy profiles and factories for AEGIS-CORE.

==============================================================================
RESEARCH SIMULATION PROFILES NOTICE:
------------------------------------------------------------------------------
These predefined policy templates allow researchers to assign deterministic,
least-privilege security boundaries to tasks during evaluation.
In a production deployment, policies will be issued through formal capability
tokens or cryptographic grants rather than static name selection.
==============================================================================
"""

from datetime import datetime
from typing import Any

from app.security.context import TaskContext
from app.security.exceptions import PolicyValidationError
from app.security.schemas import (
    BaseToolConstraint,
    GetEmailDetailsConstraint,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    TaskPolicy,
)

PREDEFINED_PROFILES: dict[str, dict[str, Any]] = {
    "read_only_all": {
        "description": "Standard read-only academic email inspection with default safe bounds.",
        "allowed_tools": frozenset(
            {"read_inbox", "get_email_details", "search_emails"}
        ),
        "constraints": {
            "read_inbox": ReadInboxConstraint(max_limit=20, max_offset=100),
            "get_email_details": GetEmailDetailsConstraint(allowed_email_ids=None),
            "search_emails": SearchEmailsConstraint(max_limit=10, max_query_length=100),
        },
    },
    "inbox_triage": {
        "description": "Restricted triage profile: inbox pagination and details only, no search.",
        "allowed_tools": frozenset({"read_inbox", "get_email_details"}),
        "constraints": {
            "read_inbox": ReadInboxConstraint(max_limit=10, max_offset=50),
            "get_email_details": GetEmailDetailsConstraint(allowed_email_ids=None),
        },
    },
    "strict_search": {
        "description": "Targeted search profile: keyword search and details only, no inbox browsing.",
        "allowed_tools": frozenset({"search_emails", "get_email_details"}),
        "constraints": {
            "search_emails": SearchEmailsConstraint(max_limit=10, max_query_length=50),
            "get_email_details": GetEmailDetailsConstraint(allowed_email_ids=None),
        },
    },
    "minimal_read": {
        "description": "Minimal privileges: strictly read_inbox up to 5 items.",
        "allowed_tools": frozenset({"read_inbox"}),
        "constraints": {
            "read_inbox": ReadInboxConstraint(max_limit=5, max_offset=10),
        },
    },
}

SUPPORTED_PROFILE_NAMES: frozenset[str] = frozenset(
    list(PREDEFINED_PROFILES.keys()) + ["none"]
)


def create_task_policy(
    task_id: str,
    user_id: int,
    profile_name: str = "read_only_all",
    *,
    policy_version: str = "1.0.0",
    expires_at: datetime | None = None,
    custom_constraints: dict[str, BaseToolConstraint] | None = None,
) -> TaskPolicy | None:
    """Create a server-controlled, task-bound TaskPolicy from a predefined profile.

    Args:
        task_id: Active unique task identifier.
        user_id: Server-verified simulated user ID.
        profile_name: Name of predefined profile ('read_only_all', 'inbox_triage',
                      'strict_search', 'minimal_read', or 'none').
        policy_version: Semantic policy version string.
        expires_at: Optional UTC expiration timestamp.
        custom_constraints: Optional override constraints for permitted tools.

    Returns:
        TaskPolicy bound to (task_id, user_id), or None if profile_name is 'none'.

    Raises:
        PolicyValidationError: If profile_name is unknown or parameters are invalid.
    """
    clean_profile = profile_name.strip().lower() if profile_name else "none"

    if clean_profile == "none":
        return None

    if clean_profile not in PREDEFINED_PROFILES:
        raise PolicyValidationError(
            f"Unknown policy profile: '{profile_name}'. "
            f"Available profiles: {sorted(SUPPORTED_PROFILE_NAMES)}"
        )

    profile_spec = PREDEFINED_PROFILES[clean_profile]
    constraints = dict(profile_spec["constraints"])

    if custom_constraints:
        constraints.update(custom_constraints)

    return TaskPolicy(
        task_id=task_id,
        bound_user_id=user_id,
        allowed_tools=profile_spec["allowed_tools"],
        constraints=constraints,
        policy_version=policy_version,
        expires_at=expires_at,
    )


def create_task_context(
    task_id: str,
    user_id: int,
    policy: TaskPolicy | None = None,
    profile_name: str | None = None,
) -> TaskContext:
    """Create a trusted TaskContext binding task_id, user_id, and an approved TaskPolicy.

    Args:
        task_id: Active task correlation ID.
        user_id: Server-verified user identity.
        policy: Optional pre-constructed TaskPolicy.
        profile_name: Optional profile name to instantiate policy if policy is None.

    Returns:
        TaskContext instance.

    Raises:
        PolicyValidationError: If policy's task_id or bound_user_id does not match.
    """
    if policy is not None:
        if policy.task_id != task_id:
            raise PolicyValidationError(
                f"Policy task_id '{policy.task_id}' does not match context task_id '{task_id}'."
            )
        if policy.bound_user_id != user_id:
            raise PolicyValidationError(
                f"Policy bound_user_id ({policy.bound_user_id}) does not match context user_id ({user_id})."
            )
        resolved_policy = policy
    elif profile_name is not None:
        resolved_policy = create_task_policy(
            task_id=task_id, user_id=user_id, profile_name=profile_name
        )
    else:
        resolved_policy = None

    return TaskContext(
        task_id=task_id,
        user_id=user_id,
        policy=resolved_policy,
    )
