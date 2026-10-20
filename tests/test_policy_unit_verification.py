"""Phase A — Policy Unit Security Verification Suite for AEGIS-CORE.

==============================================================================
SECURITY REQUIREMENTS VERIFIED:
------------------------------------------------------------------------------
1. Missing policy fails closed (POLICY_MISSING).
2. Expired policy fails closed (POLICY_EXPIRED).
3. Wrong task ID is denied (TASK_MISMATCH).
4. Wrong user ID is denied (USER_MISMATCH).
5. Tool not allowed is denied (TOOL_NOT_ALLOWED).
6. Malformed arguments are denied (ARGUMENT_INVALID).
7. Invalid limits are denied (CONSTRAINT_VIOLATION / ARGUMENT_INVALID).
8. Invalid email ID is denied (CONSTRAINT_VIOLATION / ARGUMENT_INVALID).
9. Unrecognized constraints are rejected at policy construction.
10. Mutated policy attempts fail (TaskPolicy immutability enforced).
11. Allowed legitimate operations evaluate to ALLOW.
12. Arabic and Unicode queries are evaluated strictly against length/keyword rules.
13. Multiple independent evaluations maintain stateless determinism with zero leakage.
==============================================================================
"""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.security import (
    GetEmailDetailsConstraint,
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
    PolicyReasonCode,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    TaskPolicy,
    ToolExecutionRequest,
)

TASK_ID = "task_unit_verify_001"
USER_ID = 1


def _create_policy(
    task_id: str = TASK_ID,
    user_id: int = USER_ID,
    allowed_tools: frozenset[str] | set[str] | None = None,
    constraints: dict | None = None,
    expires_at: datetime | None = None,
) -> TaskPolicy:
    return TaskPolicy(
        task_id=task_id,
        bound_user_id=user_id,
        allowed_tools=frozenset(allowed_tools or {"read_inbox"}),
        constraints=constraints or {},
        expires_at=expires_at,
    )


def _create_request(
    task_id: str = TASK_ID,
    user_id: int = USER_ID,
    tool_name: str = "read_inbox",
    arguments: dict | None = None,
) -> ToolExecutionRequest:
    return ToolExecutionRequest(
        task_id=task_id,
        user_id=user_id,
        tool_name=tool_name,
        validated_arguments=arguments or {"limit": 5},
    )


# ==============================================================================
# 1. Missing Policy
# ==============================================================================


def test_unit_missing_policy_fails_closed() -> None:
    """Requirement 1: Passing policy=None evaluates to DENY with POLICY_MISSING."""
    engine = PolicyEngine()
    req = _create_request()
    decision = engine.evaluate(policy=None, request=req)

    assert isinstance(decision, PolicyDecision)
    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.POLICY_MISSING
    assert "default-deny" in decision.explanation.lower()
    assert decision.task_id == TASK_ID


# ==============================================================================
# 2. Expired Policy
# ==============================================================================


def test_unit_expired_policy_fails_closed() -> None:
    """Requirement 2: Expired policy evaluates to DENY with POLICY_EXPIRED."""
    engine = PolicyEngine()
    now = datetime.now(UTC)
    policy = TaskPolicy(
        task_id=TASK_ID,
        bound_user_id=USER_ID,
        allowed_tools=frozenset({"read_inbox"}),
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    req = _create_request()
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.POLICY_EXPIRED
    assert "expired" in decision.explanation.lower()


# ==============================================================================
# 3. Wrong Task
# ==============================================================================


def test_unit_wrong_task_id_denied() -> None:
    """Requirement 3: Mismatched task_id evaluates to DENY with TASK_MISMATCH."""
    engine = PolicyEngine()
    policy = _create_policy(task_id="task_original_001")
    req = _create_request(task_id="task_forged_999")
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.TASK_MISMATCH
    assert "does not match" in decision.explanation


# ==============================================================================
# 4. Wrong User
# ==============================================================================


def test_unit_wrong_user_id_denied() -> None:
    """Requirement 4: Mismatched user_id evaluates to DENY with USER_MISMATCH."""
    engine = PolicyEngine()
    policy = _create_policy(user_id=1)
    req = _create_request(user_id=2)
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.USER_MISMATCH
    assert "user_id" in decision.explanation


# ==============================================================================
# 5. Tool Not Allowed
# ==============================================================================


@pytest.mark.parametrize(
    "requested_tool",
    [
        "search_emails",
        "delete_email",
        "os_system",
        "send_email",
        "READ_INBOX",  # Case variation must be denied
        "read_inbox_v2",
    ],
)
def test_unit_tool_not_allowed_denied(requested_tool: str) -> None:
    """Requirement 5: Tools outside policy allowlist evaluate to TOOL_NOT_ALLOWED."""
    engine = PolicyEngine()
    policy = _create_policy(allowed_tools={"read_inbox"})
    req = _create_request(tool_name=requested_tool, arguments={})
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED


# ==============================================================================
# 6. Malformed Arguments
# ==============================================================================


@pytest.mark.parametrize(
    "tool_name,bad_args",
    [
        ("read_inbox", {"limit": "not_an_int"}),
        ("read_inbox", {"extra_illegal_key": 123}),
        ("get_email_details", {"email_id": "bad_id"}),
        ("get_email_details", {}),  # Missing required email_id
        ("search_emails", {"query": ""}),  # Empty query
        ("search_emails", {"query": "   "}),  # Whitespace query
    ],
)
def test_unit_malformed_arguments_denied(tool_name: str, bad_args: dict) -> None:
    """Requirement 6: Malformed arguments evaluate to DENY with ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"read_inbox", "get_email_details", "search_emails"}
    )
    req = _create_request(tool_name=tool_name, arguments=bad_args)
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID


# ==============================================================================
# 7. Invalid Limits
# ==============================================================================


def test_unit_limit_above_policy_maximum_denied() -> None:
    """Requirement 7: Limit above policy-scoped maximum evaluates to CONSTRAINT_VIOLATION."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"read_inbox"},
        constraints={"read_inbox": ReadInboxConstraint(max_limit=5)},
    )
    # limit=10 is schema-valid (<= 20) but policy-invalid (> 5)
    req = _create_request(tool_name="read_inbox", arguments={"limit": 10})
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert "exceeds policy maximum limit" in decision.explanation


def test_unit_negative_limit_denied_as_schema_invalid() -> None:
    """Requirement 7b: Negative limit is rejected as ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = _create_policy(allowed_tools={"read_inbox"})
    req = _create_request(tool_name="read_inbox", arguments={"limit": -1})
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID


# ==============================================================================
# 8. Invalid Email ID
# ==============================================================================


def test_unit_disallowed_email_id_denied() -> None:
    """Requirement 8: email_id not in policy allowed list evaluates to CONSTRAINT_VIOLATION."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"get_email_details"},
        constraints={
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({1, 2})
            )
        },
    )
    req = _create_request(tool_name="get_email_details", arguments={"email_id": 99})
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert "not in the policy allowed_email_ids" in decision.explanation


def test_unit_non_positive_email_id_denied() -> None:
    """Requirement 8b: email_id < 1 is rejected by schema as ARGUMENT_INVALID."""
    engine = PolicyEngine()
    policy = _create_policy(allowed_tools={"get_email_details"})
    req = _create_request(tool_name="get_email_details", arguments={"email_id": 0})
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID


# ==============================================================================
# 9. Unrecognized Constraints
# ==============================================================================


def test_unit_unrecognized_constraints_rejected_at_policy_construction() -> None:
    """Requirement 9: Unknown constraint keys are rejected with ValidationError."""
    with pytest.raises(ValidationError):
        TaskPolicy(
            task_id="task_bad_constraint",
            bound_user_id=1,
            allowed_tools=frozenset({"read_inbox"}),
            constraints={
                "read_inbox": {
                    "max_limit": 5,
                    "unrecognized_arbitrary_key": "injected_value",
                }
            },
        )


def test_unit_constraint_for_unpermitted_tool_rejected() -> None:
    """Requirement 9b: Constraint for tool not in allowed_tools is rejected."""
    with pytest.raises(ValidationError, match="not in allowed_tools"):
        TaskPolicy(
            task_id="task_mismatched_constraint",
            bound_user_id=1,
            allowed_tools=frozenset({"read_inbox"}),
            constraints={
                "search_emails": SearchEmailsConstraint(max_limit=5),
            },
        )


# ==============================================================================
# 10. Mutated Policy Attempts (Immutability)
# ==============================================================================


def test_unit_policy_immutability_enforced() -> None:
    """Requirement 10: Attempting to modify TaskPolicy fields raises ValidationError."""
    policy = _create_policy(
        allowed_tools={"read_inbox"},
        user_id=1,
    )

    with pytest.raises(ValidationError):
        # frozen=True forbids attribute assignment
        policy.bound_user_id = 999  # type: ignore[misc]

    with pytest.raises(ValidationError):
        policy.allowed_tools = frozenset({"read_inbox", "execute_shell"})  # type: ignore[misc]

    # Verify original values remain intact
    assert policy.bound_user_id == 1
    assert policy.allowed_tools == frozenset({"read_inbox"})


# ==============================================================================
# 11. Allowed Legitimate Operations
# ==============================================================================


def test_unit_allowed_legitimate_operations_evaluate_to_allow() -> None:
    """Requirement 11: Legitimate operations meeting all constraints evaluate to ALLOW."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"read_inbox", "get_email_details", "search_emails"},
        constraints={
            "read_inbox": ReadInboxConstraint(max_limit=10),
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({1, 2, 3})
            ),
            "search_emails": SearchEmailsConstraint(max_limit=5, max_query_length=50),
        },
    )

    # 1. read_inbox within bounds
    d1 = engine.evaluate(
        policy=policy,
        request=_create_request(tool_name="read_inbox", arguments={"limit": 5}),
    )
    assert d1.decision == PolicyAction.ALLOW
    assert d1.reason_code == PolicyReasonCode.ALLOW

    # 2. get_email_details for allowed ID
    d2 = engine.evaluate(
        policy=policy,
        request=_create_request(
            tool_name="get_email_details", arguments={"email_id": 2}
        ),
    )
    assert d2.decision == PolicyAction.ALLOW
    assert d2.reason_code == PolicyReasonCode.ALLOW

    # 3. search_emails within query length and limit
    d3 = engine.evaluate(
        policy=policy,
        request=_create_request(
            tool_name="search_emails",
            arguments={"query": "machine learning", "limit": 3},
        ),
    )
    assert d3.decision == PolicyAction.ALLOW
    assert d3.reason_code == PolicyReasonCode.ALLOW


# ==============================================================================
# 12. Arabic and Unicode Values
# ==============================================================================


@pytest.mark.parametrize(
    "arabic_query",
    [
        "مشروع التخرج",
        "درجات التكليف الأول",
        "الذكاء الاصطناعي و الأمن السيبراني",
        "جامعة الملك عبد الله",
    ],
)
def test_unit_arabic_and_unicode_queries_allowed(arabic_query: str) -> None:
    """Requirement 12: Legitimate Arabic queries within length bounds are permitted."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"search_emails"},
        constraints={"search_emails": SearchEmailsConstraint(max_query_length=100)},
    )
    req = _create_request(
        tool_name="search_emails",
        arguments={"query": arabic_query, "limit": 5},
    )
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.ALLOW
    assert decision.reason_code == PolicyReasonCode.ALLOW


def test_unit_arabic_query_exceeding_max_length_denied() -> None:
    """Requirement 12b: Arabic query exceeding policy max_query_length is denied."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"search_emails"},
        constraints={"search_emails": SearchEmailsConstraint(max_query_length=20)},
    )
    long_arabic_query = (
        "هذا استعلام بحث أكاديمي طويل جدا يتجاوز الحد المسموح به في السياسة الأمنية"
    )
    req = _create_request(
        tool_name="search_emails",
        arguments={"query": long_arabic_query, "limit": 2},
    )
    decision = engine.evaluate(policy=policy, request=req)

    assert decision.decision == PolicyAction.DENY
    assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert "exceeds policy maximum length" in decision.explanation


# ==============================================================================
# 13. Multiple Independent Evaluations (Stateless Determinism)
# ==============================================================================


def test_unit_multiple_independent_evaluations_zero_state_leakage() -> None:
    """Requirement 13: 100 alternating evaluations in loop exhibit zero state leakage."""
    engine = PolicyEngine()
    policy = _create_policy(
        allowed_tools={"read_inbox"},
        constraints={"read_inbox": ReadInboxConstraint(max_limit=5)},
    )

    req_valid = _create_request(tool_name="read_inbox", arguments={"limit": 3})
    req_invalid_tool = _create_request(
        tool_name="search_emails", arguments={"query": "test"}
    )
    req_violating_limit = _create_request(
        tool_name="read_inbox", arguments={"limit": 10}
    )

    for i in range(100):
        if i % 3 == 0:
            d = engine.evaluate(policy=policy, request=req_valid)
            assert d.decision == PolicyAction.ALLOW
            assert d.reason_code == PolicyReasonCode.ALLOW
        elif i % 3 == 1:
            d = engine.evaluate(policy=policy, request=req_invalid_tool)
            assert d.decision == PolicyAction.DENY
            assert d.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED
        else:
            d = engine.evaluate(policy=policy, request=req_violating_limit)
            assert d.decision == PolicyAction.DENY
            assert d.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
