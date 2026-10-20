"""Table-driven unit tests for deterministic task-scoped tool authorization in AEGIS-CORE.

Covers all 20 required verification scenarios:
1. Valid permitted tool calls.
2. Tool not in allowlist.
3. Case variations in tool names.
4. Limit above policy maximum.
5. Negative offsets.
6. Missing required arguments.
7. Unknown arguments.
8. Omitted defaults.
9. Disallowed email IDs.
10. Foreign-user email lookup.
11. Search query constraints.
12. Unicode and Arabic search.
13. Expired policies.
14. Invalid task IDs.
15. Invalid users.
16. Unexpected constraint keys.
17. Unauthorized escalation attempts.
18. Empty allowed tool list.
19. Missing policy.
20. Malformed policy payloads.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.security import (
    GetEmailDetailsConstraint,
    PolicyAction,
    PolicyEngine,
    PolicyReasonCode,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    TaskPolicy,
    ToolExecutionRequest,
)

TASK_ID = "task_table_test_001"
USER_ID = 1


def make_policy(
    task_id: str = TASK_ID,
    bound_user_id: int = USER_ID,
    allowed_tools: set[str] | frozenset[str] | list[str] | None = None,
    constraints: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
) -> TaskPolicy:
    """Helper factory for constructing valid TaskPolicy instances."""
    return TaskPolicy(
        task_id=task_id,
        bound_user_id=bound_user_id,
        allowed_tools=allowed_tools or {"read_inbox"},
        constraints=constraints or {},
        expires_at=expires_at,
    )


def make_req(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    task_id: str = TASK_ID,
    user_id: int = USER_ID,
) -> ToolExecutionRequest:
    """Helper factory for constructing ToolExecutionRequest instances."""
    return ToolExecutionRequest(
        task_id=task_id,
        tool_name=tool_name,
        validated_arguments=arguments or {},
        user_id=user_id,
    )


# ===========================================================================
# 1. Valid Permitted Tool Calls
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "policy_tools", "constraints", "arguments"),
    [
        (
            "read_inbox",
            {"read_inbox"},
            {},
            {},
        ),
        (
            "read_inbox",
            {"read_inbox"},
            {"read_inbox": ReadInboxConstraint(max_limit=10, max_offset=20)},
            {"limit": 5, "offset": 10, "is_read": True},
        ),
        (
            "get_email_details",
            {"get_email_details"},
            {},
            {"email_id": 1},
        ),
        (
            "get_email_details",
            {"get_email_details"},
            {
                "get_email_details": GetEmailDetailsConstraint(
                    allowed_email_ids=frozenset({1, 2, 3})
                )
            },
            {"email_id": 2},
        ),
        (
            "search_emails",
            {"search_emails"},
            {},
            {"query": "syllabus"},
        ),
        (
            "search_emails",
            {"search_emails"},
            {
                "search_emails": SearchEmailsConstraint(
                    max_limit=5, allowed_search_terms=frozenset({"grades", "exam"})
                )
            },
            {"query": "grades", "limit": 3, "offset": 0},
        ),
    ],
)
def test_valid_permitted_tool_calls(
    tool_name: str,
    policy_tools: set[str],
    constraints: dict[str, Any],
    arguments: dict[str, Any],
) -> None:
    """Permitted tool calls satisfying all schemas and constraints evaluate to ALLOW."""
    engine = PolicyEngine()
    policy = make_policy(allowed_tools=policy_tools, constraints=constraints)
    req = make_req(tool_name=tool_name, arguments=arguments)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.ALLOW
    assert decision.reason_code == PolicyReasonCode.ALLOW
    assert decision.is_allowed


# ===========================================================================
# 2. Tool Not in Allowlist
# ===========================================================================


@pytest.mark.parametrize(
    ("requested_tool", "allowed_tools"),
    [
        ("get_email_details", {"read_inbox"}),
        ("search_emails", {"read_inbox"}),
        ("read_inbox", {"get_email_details"}),
        ("search_emails", {"get_email_details"}),
        ("read_inbox", {"search_emails"}),
        ("execute_shell", {"read_inbox", "get_email_details", "search_emails"}),
        ("send_email", {"read_inbox"}),
        ("delete_email", {"read_inbox"}),
    ],
)
def test_tool_not_in_allowlist(requested_tool: str, allowed_tools: set[str]) -> None:
    """Tools not explicitly permitted in policy or system registry are denied with TOOL_NOT_ALLOWED."""
    engine = PolicyEngine()
    policy = make_policy(allowed_tools=allowed_tools)
    req = make_req(tool_name=requested_tool, arguments={"email_id": 1, "query": "test"})

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED


# ===========================================================================
# 3. Case Variations in Tool Names
# ===========================================================================


@pytest.mark.parametrize(
    "cased_tool_name",
    [
        "Read_Inbox",
        "READ_INBOX",
        "read_Inbox",
        "read_inbox ",
        " read_inbox",
        "read_inbox_v2",
        "read_",
        "Get_Email_Details",
        "GET_EMAIL_DETAILS",
        "Search_Emails",
        "SEARCH_EMAILS",
    ],
)
def test_case_variations_in_tool_names(cased_tool_name: str) -> None:
    """Exact case-sensitive matching is strictly enforced; variations or prefixes are denied."""
    engine = PolicyEngine()
    policy = make_policy(
        allowed_tools={"read_inbox", "get_email_details", "search_emails"}
    )
    req = make_req(tool_name=cased_tool_name, arguments={})

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED


# ===========================================================================
# 4. Limit Above Policy Maximum
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "policy_max_limit", "requested_limit", "extra_args"),
    [
        ("read_inbox", 5, 6, {}),
        ("read_inbox", 1, 2, {}),
        ("read_inbox", 10, 15, {}),
        ("search_emails", 3, 4, {"query": "test"}),
        ("search_emails", 1, 5, {"query": "test"}),
        ("search_emails", 5, 10, {"query": "test"}),
    ],
)
def test_limit_above_policy_maximum(
    tool_name: str,
    policy_max_limit: int,
    requested_limit: int,
    extra_args: dict[str, Any],
) -> None:
    """Requests with limits exceeding policy max_limit are denied with CONSTRAINT_VIOLATION."""
    engine = PolicyEngine()
    constraint: Any
    if tool_name == "read_inbox":
        constraint = ReadInboxConstraint(max_limit=policy_max_limit)
    else:
        constraint = SearchEmailsConstraint(max_limit=policy_max_limit)

    policy = make_policy(allowed_tools={tool_name}, constraints={tool_name: constraint})
    args = dict(extra_args)
    args["limit"] = requested_limit
    req = make_req(tool_name=tool_name, arguments=args)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert f"exceeds policy maximum limit ({policy_max_limit})" in decision.explanation


# ===========================================================================
# 5. Negative Offsets
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "negative_offset", "extra_args"),
    [
        ("read_inbox", -1, {}),
        ("read_inbox", -10, {}),
        ("search_emails", -1, {"query": "syllabus"}),
        ("search_emails", -5, {"query": "grades"}),
    ],
)
def test_negative_offsets(
    tool_name: str, negative_offset: int, extra_args: dict[str, Any]
) -> None:
    """Tool calls with negative offset fail schema validation and are denied with ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = make_policy(allowed_tools={"read_inbox", "search_emails"})
    args = dict(extra_args)
    args["offset"] = negative_offset
    req = make_req(tool_name=tool_name, arguments=args)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID
    assert "offset" in decision.explanation


# ===========================================================================
# 6. Missing Required Arguments
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "empty_arguments", "missing_field"),
    [
        ("get_email_details", {}, "email_id"),
        ("search_emails", {}, "query"),
        ("search_emails", {"limit": 5, "offset": 0}, "query"),
        ("search_emails", {"query": ""}, "query"),
        ("search_emails", {"query": "   "}, "query"),
    ],
)
def test_missing_required_arguments(
    tool_name: str, empty_arguments: dict[str, Any], missing_field: str
) -> None:
    """Missing or empty required parameters are rejected with ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = make_policy(allowed_tools={"get_email_details", "search_emails"})
    req = make_req(tool_name=tool_name, arguments=empty_arguments)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID
    assert missing_field in decision.explanation


# ===========================================================================
# 7. Unknown Arguments
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "arguments_with_unknown"),
    [
        ("read_inbox", {"user_id": 2}),  # Model attempting to inject tenant override
        ("read_inbox", {"extra_param": "admin"}),
        ("get_email_details", {"email_id": 1, "owner_id": 2}),
        ("get_email_details", {"email_id": 1, "body_only": True}),
        ("search_emails", {"query": "exam", "fuzzy": True}),
        ("search_emails", {"query": "exam", "sql_injection": "' OR 1=1--"}),
    ],
)
def test_unknown_arguments(
    tool_name: str, arguments_with_unknown: dict[str, Any]
) -> None:
    """Unknown, unexpected, or injected arguments fail strict validation with ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = make_policy(
        allowed_tools={"read_inbox", "get_email_details", "search_emails"}
    )
    req = make_req(tool_name=tool_name, arguments=arguments_with_unknown)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID
    assert "Extra inputs are not permitted" in decision.explanation


# ===========================================================================
# 8. Omitted Defaults
# ===========================================================================


@pytest.mark.parametrize(
    (
        "tool_name",
        "provided_args",
        "policy_max_limit",
        "expected_action",
        "expected_reason",
    ),
    [
        # read_inbox default limit is 5. Policy max_limit is 10 -> 5 <= 10 -> ALLOW
        ("read_inbox", {}, 10, PolicyAction.ALLOW, PolicyReasonCode.ALLOW),
        # read_inbox default limit is 5. Policy max_limit is 3 -> 5 > 3 -> DENY (CONSTRAINT_VIOLATION)
        ("read_inbox", {}, 3, PolicyAction.DENY, PolicyReasonCode.CONSTRAINT_VIOLATION),
        # read_inbox with is_read=False, limit omitted. Policy max_limit is 3 -> 5 > 3 -> DENY
        (
            "read_inbox",
            {"is_read": False},
            3,
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # search_emails default limit is 5. Policy max_limit is 10 -> 5 <= 10 -> ALLOW
        (
            "search_emails",
            {"query": "test"},
            10,
            PolicyAction.ALLOW,
            PolicyReasonCode.ALLOW,
        ),
        # search_emails default limit is 5. Policy max_limit is 2 -> 5 > 2 -> DENY
        (
            "search_emails",
            {"query": "test"},
            2,
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
    ],
)
def test_omitted_defaults(
    tool_name: str,
    provided_args: dict[str, Any],
    policy_max_limit: int,
    expected_action: PolicyAction,
    expected_reason: PolicyReasonCode,
) -> None:
    """Omitted optional arguments are normalized to schema defaults before constraint evaluation."""
    engine = PolicyEngine()
    constraint: Any
    if tool_name == "read_inbox":
        constraint = ReadInboxConstraint(max_limit=policy_max_limit)
    else:
        constraint = SearchEmailsConstraint(max_limit=policy_max_limit)

    policy = make_policy(allowed_tools={tool_name}, constraints={tool_name: constraint})
    req = make_req(tool_name=tool_name, arguments=provided_args)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == expected_action
    assert decision.reason_code == expected_reason


# ===========================================================================
# 9. Disallowed Email IDs
# ===========================================================================


@pytest.mark.parametrize(
    ("allowed_ids", "denied_ids", "max_id", "requested_id", "expected_err_substring"),
    [
        (
            frozenset({1, 2, 3}),
            None,
            None,
            4,
            "not in the policy allowed_email_ids whitelist",
        ),
        (
            frozenset({1, 2, 3}),
            None,
            None,
            99,
            "not in the policy allowed_email_ids whitelist",
        ),
        (None, frozenset({5}), None, 5, "explicitly denied by policy blacklist"),
        (None, frozenset({10, 20}), None, 10, "explicitly denied by policy blacklist"),
        (None, None, 10, 11, "exceeds policy maximum email ID"),
        (frozenset(), None, None, 1, "allowed_email_ids whitelist is empty"),
    ],
)
def test_disallowed_email_ids(
    allowed_ids: frozenset[int] | None,
    denied_ids: frozenset[int] | None,
    max_id: int | None,
    requested_id: int,
    expected_err_substring: str,
) -> None:
    """Email inspection requests violating scoped ID restrictions are denied with CONSTRAINT_VIOLATION."""
    engine = PolicyEngine()
    constraint = GetEmailDetailsConstraint(
        allowed_email_ids=allowed_ids,
        denied_email_ids=denied_ids,
        max_email_id=max_id,
    )
    policy = make_policy(
        allowed_tools={"get_email_details"},
        constraints={"get_email_details": constraint},
    )
    req = make_req(tool_name="get_email_details", arguments={"email_id": requested_id})

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert expected_err_substring in decision.explanation


# ===========================================================================
# 10. Foreign-User Email Lookup
# ===========================================================================


def test_foreign_user_email_lookup_via_ownership_verifier() -> None:
    """Policy permitting an email ID does NOT override the tenant ownership boundary."""

    # Email 11 is owned by User 2, not User 1
    def mock_verifier(user_id: int, email_id: int) -> bool:
        ownership_map = {1: {1, 2, 3}, 2: {11, 12, 13}}
        return email_id in ownership_map.get(user_id, set())

    engine = PolicyEngine(ownership_verifier=mock_verifier)

    # Policy for User 1 maliciously or erroneously includes Email 11 in allowed_email_ids
    policy = make_policy(
        bound_user_id=1,
        allowed_tools={"get_email_details"},
        constraints={
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({11})
            )
        },
    )
    req = make_req(
        tool_name="get_email_details",
        arguments={"email_id": 11},
        user_id=1,
    )

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.USER_MISMATCH
    assert "Foreign-owned email lookup denied" in decision.explanation


def test_foreign_user_email_lookup_via_database_session(
    seeded_session: Session,
) -> None:
    """Database-backed repository boundary verification denies cross-tenant lookup."""
    engine = PolicyEngine()

    # In seeded_session: User 1 owns emails 1..10, User 2 owns emails 11..20
    # Attempting to fetch Email 11 as User 1
    policy = make_policy(
        bound_user_id=1,
        allowed_tools={"get_email_details"},
        constraints={
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({11})
            )
        },
    )
    req = make_req(
        tool_name="get_email_details",
        arguments={"email_id": 11},
        user_id=1,
    )

    decision = engine.evaluate(policy=policy, request=req, session=seeded_session)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.USER_MISMATCH
    assert "Foreign-owned email lookup denied" in decision.explanation


# ===========================================================================
# 11. Search Query Constraints
# ===========================================================================


@pytest.mark.parametrize(
    (
        "allowed_terms",
        "blocked_terms",
        "max_len",
        "min_len",
        "query",
        "expected_action",
        "expected_reason",
    ),
    [
        # Query exceeds max_query_length
        (
            None,
            None,
            10,
            None,
            "this query is 23 chars long",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Query below min_query_length
        (
            None,
            None,
            100,
            5,
            "hi",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Query not in allowed_search_terms whitelist
        (
            frozenset({"grades", "exam"}),
            None,
            100,
            None,
            "salary",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Query in allowed_search_terms whitelist -> ALLOW
        (
            frozenset({"grades", "exam"}),
            None,
            100,
            None,
            "exam",
            PolicyAction.ALLOW,
            PolicyReasonCode.ALLOW,
        ),
        # Query in blocked_search_terms blacklist -> DENY
        (
            None,
            frozenset({"password", "token"}),
            100,
            None,
            "get user token",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Empty allowed_search_terms whitelist -> DENY
        (
            frozenset(),
            None,
            100,
            None,
            "test",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
    ],
)
def test_search_query_constraints(
    allowed_terms: frozenset[str] | None,
    blocked_terms: frozenset[str] | None,
    max_len: int | None,
    min_len: int | None,
    query: str,
    expected_action: PolicyAction,
    expected_reason: PolicyReasonCode,
) -> None:
    """Search query parameter constraints are enforced deterministically."""
    engine = PolicyEngine()
    constraint = SearchEmailsConstraint(
        allowed_search_terms=allowed_terms,
        blocked_search_terms=blocked_terms,
        max_query_length=max_len,
        min_query_length=min_len,
    )
    policy = make_policy(
        allowed_tools={"search_emails"},
        constraints={"search_emails": constraint},
    )
    req = make_req(tool_name="search_emails", arguments={"query": query})

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == expected_action
    assert decision.reason_code == expected_reason


# ===========================================================================
# 12. Unicode and Arabic Search
# ===========================================================================


@pytest.mark.parametrize(
    ("allowed_terms", "blocked_terms", "query", "expected_action", "expected_reason"),
    [
        # Arabic query in allowed terms
        (
            frozenset({"جدول المحاضرات", "الامتحان"}),
            None,
            "جدول المحاضرات",
            PolicyAction.ALLOW,
            PolicyReasonCode.ALLOW,
        ),
        # Arabic query not in allowed terms
        (
            frozenset({"جدول المحاضرات"}),
            None,
            "تقرير المعمل",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Arabic query with blocked keyword
        (
            None,
            frozenset({"كلمة السر"}),
            "ما هي كلمة السر؟",
            PolicyAction.DENY,
            PolicyReasonCode.CONSTRAINT_VIOLATION,
        ),
        # Accented Unicode query
        (
            frozenset({"résumé", "café"}),
            None,
            "résumé",
            PolicyAction.ALLOW,
            PolicyReasonCode.ALLOW,
        ),
        # Accented Unicode query with different normalization form (NFKC matches)
        (
            frozenset({"cafe\u0301"}),
            None,
            "café",
            PolicyAction.ALLOW,
            PolicyReasonCode.ALLOW,
        ),
    ],
)
def test_unicode_and_arabic_search(
    allowed_terms: frozenset[str] | None,
    blocked_terms: frozenset[str] | None,
    query: str,
    expected_action: PolicyAction,
    expected_reason: PolicyReasonCode,
) -> None:
    """Arabic and Unicode queries are evaluated with canonical normalization without corruption."""
    engine = PolicyEngine()
    constraint = SearchEmailsConstraint(
        allowed_search_terms=allowed_terms,
        blocked_search_terms=blocked_terms,
    )
    policy = make_policy(
        allowed_tools={"search_emails"},
        constraints={"search_emails": constraint},
    )
    req = make_req(tool_name="search_emails", arguments={"query": query})

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == expected_action
    assert decision.reason_code == expected_reason


# ===========================================================================
# 13. Expired Policies
# ===========================================================================


def test_expired_policy_table() -> None:
    """Expired policies fail closed across all operations."""
    engine = PolicyEngine()
    base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
    expiry = base_time + timedelta(minutes=10)

    policy = TaskPolicy(
        task_id=TASK_ID,
        bound_user_id=USER_ID,
        allowed_tools={"read_inbox", "get_email_details"},
        issued_at=base_time,
        expires_at=expiry,
    )

    # Call at 5 mins -> ALLOW
    req = make_req("read_inbox", {})
    d1 = engine.evaluate(policy, req, current_time=base_time + timedelta(minutes=5))
    assert d1.decision == PolicyAction.ALLOW

    # Call at 11 mins -> DENY
    d2 = engine.evaluate(policy, req, current_time=base_time + timedelta(minutes=11))
    assert d2.decision == PolicyAction.DENY
    assert d2.reason_code == PolicyReasonCode.POLICY_EXPIRED


# ===========================================================================
# 14. Invalid Task IDs
# ===========================================================================


@pytest.mark.parametrize(
    ("policy_task_id", "request_task_id"),
    [
        ("task_abc", "task_xyz"),
        ("task_123", "task_123_forged"),
        ("task_user_1", "task_user_2"),
    ],
)
def test_invalid_task_ids(policy_task_id: str, request_task_id: str) -> None:
    """Mismatched task_id between request and policy is denied with TASK_MISMATCH."""
    engine = PolicyEngine()
    policy = make_policy(task_id=policy_task_id)
    req = make_req("read_inbox", {}, task_id=request_task_id)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.TASK_MISMATCH


# ===========================================================================
# 15. Invalid Users
# ===========================================================================


@pytest.mark.parametrize(
    ("policy_user_id", "request_user_id"),
    [
        (1, 2),
        (2, 1),
        (1, 999),
    ],
)
def test_invalid_users(policy_user_id: int, request_user_id: int) -> None:
    """Mismatched user_id between request and policy is denied with USER_MISMATCH."""
    engine = PolicyEngine()
    policy = make_policy(bound_user_id=policy_user_id)
    req = make_req("read_inbox", {}, user_id=request_user_id)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.USER_MISMATCH


# ===========================================================================
# 16. Unexpected Constraint Keys
# ===========================================================================


@pytest.mark.parametrize(
    ("tool_name", "bad_constraint_dict"),
    [
        ("read_inbox", {"max_limit": 5, "unknown_field": 123}),
        ("read_inbox", {"arbitrary_code": "import os"}),
        ("get_email_details", {"allow_all": True}),
        ("search_emails", {"regex_eval": ".*"}),
    ],
)
def test_unexpected_constraint_keys(
    tool_name: str, bad_constraint_dict: dict[str, Any]
) -> None:
    """Unexpected constraint keys are strictly rejected at policy creation time."""
    with pytest.raises(ValidationError):
        TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=USER_ID,
            allowed_tools={tool_name},
            constraints={tool_name: bad_constraint_dict},
        )


# ===========================================================================
# 17. Unauthorized Escalation Attempts
# ===========================================================================


@pytest.mark.parametrize(
    ("allowed_tools", "attack_tool", "attack_args", "expected_reason"),
    [
        # Tool escalation: Attempting to call unpermitted get_email_details
        (
            {"read_inbox"},
            "get_email_details",
            {"email_id": 1},
            PolicyReasonCode.TOOL_NOT_ALLOWED,
        ),
        # Tenant injection in arguments: Attempting to pass user_id in params
        (
            {"read_inbox"},
            "read_inbox",
            {"user_id": 2},
            PolicyReasonCode.ARGUMENT_INVALID,
        ),
        # System command injection attempt
        (
            {"read_inbox"},
            "execute_shell",
            {"command": "whoami"},
            PolicyReasonCode.TOOL_NOT_ALLOWED,
        ),
        # Admin override parameter injection
        (
            {"search_emails"},
            "search_emails",
            {"query": "test", "admin": True},
            PolicyReasonCode.ARGUMENT_INVALID,
        ),
    ],
)
def test_unauthorized_escalation_attempts(
    allowed_tools: set[str],
    attack_tool: str,
    attack_args: dict[str, Any],
    expected_reason: PolicyReasonCode,
) -> None:
    """Escalation vectors are blocked deterministically by the policy engine."""
    engine = PolicyEngine()
    policy = make_policy(allowed_tools=allowed_tools)
    req = make_req(tool_name=attack_tool, arguments=attack_args)

    decision = engine.evaluate(policy=policy, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == expected_reason


# ===========================================================================
# 18. Empty Allowed Tool List
# ===========================================================================


def test_empty_allowed_tool_list_rejected_in_policy() -> None:
    """Policy with empty allowed_tools is rejected at construction time."""
    with pytest.raises(ValidationError):
        TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=USER_ID,
            allowed_tools=set(),
        )


# ===========================================================================
# 19. Missing Policy
# ===========================================================================


def test_missing_policy() -> None:
    """None policy fails closed with POLICY_MISSING."""
    engine = PolicyEngine()
    req = make_req("read_inbox", {})

    decision = engine.evaluate(policy=None, request=req)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.POLICY_MISSING
    assert not decision.is_allowed


# ===========================================================================
# 20. Malformed Policy Payloads
# ===========================================================================


@pytest.mark.parametrize(
    "malformed_payload",
    [
        {"task_id": "", "bound_user_id": 1, "allowed_tools": ["read_inbox"]},
        {"task_id": "t1", "bound_user_id": -5, "allowed_tools": ["read_inbox"]},
        {"task_id": "t1", "bound_user_id": 1, "allowed_tools": ["*"]},
        {"task_id": "t1", "bound_user_id": 1, "allowed_tools": "read_inbox"},
        {
            "task_id": "t1",
            "bound_user_id": 1,
            "allowed_tools": ["read_inbox"],
            "extra_top_level": True,
        },
    ],
)
def test_malformed_policy_payloads(malformed_payload: dict[str, Any]) -> None:
    """Malformed policy dictionaries fail Pydantic model validation."""
    with pytest.raises(ValidationError):
        TaskPolicy.model_validate(malformed_payload)


def test_corrupted_policy_object_evaluated() -> None:
    """Non-TaskPolicy instance passed to evaluate returns DENY with POLICY_INVALID."""
    engine = PolicyEngine()
    req = make_req("read_inbox", {})

    decision = engine.evaluate(policy={"corrupt": "data"}, request=req)  # type: ignore[arg-type]
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.POLICY_INVALID
