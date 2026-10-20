"""Comprehensive unit tests for the AEGIS-CORE security policy engine.

Validates the security contracts, policy schemas, immutability, argument
constraints, fail-closed mechanics, and deterministic evaluation behavior.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.security import (
    FORBIDDEN_WILDCARDS,
    KNOWN_SYSTEM_TOOLS,
    GenericToolConstraint,
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

# ---------------------------------------------------------------------------
# Test Fixtures & Constants
# ---------------------------------------------------------------------------

TASK_ID = "task_test_sec_001"
BOUND_USER_ID = 1


def make_valid_policy(
    task_id: str = TASK_ID,
    bound_user_id: int = BOUND_USER_ID,
    allowed_tools: set[str] | frozenset[str] | list[str] | None = None,
    constraints: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
) -> TaskPolicy:
    """Helper factory for constructing valid TaskPolicy instances in tests."""
    return TaskPolicy(
        task_id=task_id,
        bound_user_id=bound_user_id,
        allowed_tools=allowed_tools or {"read_inbox"},
        constraints=constraints or {},
        expires_at=expires_at,
    )


def make_request(
    task_id: str = TASK_ID,
    tool_name: str = "read_inbox",
    arguments: dict[str, Any] | None = None,
    user_id: int = BOUND_USER_ID,
) -> ToolExecutionRequest:
    """Helper factory for constructing ToolExecutionRequest instances in tests."""
    return ToolExecutionRequest(
        task_id=task_id,
        tool_name=tool_name,
        validated_arguments=arguments or {},
        user_id=user_id,
    )


# ===========================================================================
# 1. Valid Policy Construction Tests
# ===========================================================================


class TestValidPolicyConstruction:
    """Tests verifying correct construction and defaults for TaskPolicy."""

    def test_minimal_valid_policy(self) -> None:
        """A minimal policy with task_id, user_id, and allowed_tools constructs cleanly."""
        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox"},
        )
        assert policy.task_id == TASK_ID
        assert policy.bound_user_id == BOUND_USER_ID
        assert policy.allowed_tools == frozenset({"read_inbox"})
        assert policy.constraints == {}
        assert policy.policy_version == "1.0.0"
        assert policy.expires_at is None
        assert policy.issued_at.tzinfo == UTC
        assert not policy.is_expired()

    def test_policy_with_all_known_tools(self) -> None:
        """Policy can authorize all currently registered system tools."""
        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools=KNOWN_SYSTEM_TOOLS,
        )
        assert policy.allowed_tools == KNOWN_SYSTEM_TOOLS

    def test_policy_with_typed_constraints(self) -> None:
        """Policy accepts typed per-tool constraint instances."""
        inbox_c = ReadInboxConstraint(
            max_limit=10, max_offset=20, allowed_is_read=False
        )
        email_c = GetEmailDetailsConstraint(
            allowed_email_ids=frozenset({1, 2, 3}), max_email_id=50
        )
        search_c = SearchEmailsConstraint(
            max_limit=5, blocked_keywords=frozenset({"password", "token"})
        )

        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox", "get_email_details", "search_emails"},
            constraints={
                "read_inbox": inbox_c,
                "get_email_details": email_c,
                "search_emails": search_c,
            },
        )
        assert policy.constraints["read_inbox"] == inbox_c
        assert policy.constraints["get_email_details"] == email_c
        assert policy.constraints["search_emails"] == search_c

    def test_policy_coerces_dict_constraints_to_typed_models(self) -> None:
        """Policy cleanly maps raw dictionaries into typed tool constraint models."""
        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox", "get_email_details", "search_emails"},
            constraints={
                "read_inbox": {"max_limit": 5, "allowed_is_read": True},
                "get_email_details": {"allowed_email_ids": [1, 2, 3]},
                "search_emails": {"max_limit": 3, "blocked_keywords": ["secret"]},
            },
        )
        assert isinstance(policy.constraints["read_inbox"], ReadInboxConstraint)
        assert policy.constraints["read_inbox"].max_limit == 5
        assert policy.constraints["read_inbox"].allowed_is_read is True
        assert isinstance(
            policy.constraints["get_email_details"], GetEmailDetailsConstraint
        )
        assert policy.constraints["get_email_details"].allowed_email_ids == frozenset(
            {1, 2, 3}
        )
        assert isinstance(policy.constraints["search_emails"], SearchEmailsConstraint)
        assert policy.constraints["search_emails"].blocked_keywords == frozenset(
            {"secret"}
        )

    def test_policy_with_future_expiration(self) -> None:
        """Policy with future expires_at is accepted and not expired."""
        future = datetime.now(UTC) + timedelta(hours=1)
        policy = make_valid_policy(expires_at=future)
        assert policy.expires_at == future
        assert not policy.is_expired()

    def test_policy_immutability(self) -> None:
        """TaskPolicy instances are frozen and cannot be mutated by caller or agent."""
        policy = make_valid_policy()
        with pytest.raises(ValidationError):
            policy.bound_user_id = 999  # type: ignore[misc]

        with pytest.raises(ValidationError):
            policy.allowed_tools = frozenset({"search_emails"})  # type: ignore[misc]

        with pytest.raises(ValidationError):
            policy.task_id = "task_tampered"  # type: ignore[misc]


# ===========================================================================
# 2. Invalid Policy Construction Rejection Tests
# ===========================================================================


class TestInvalidPolicyRejection:
    """Tests verifying that malformed or insecure policies fail construction."""

    @pytest.mark.parametrize("wildcard", list(FORBIDDEN_WILDCARDS))
    def test_reject_wildcards_in_allowed_tools(self, wildcard: str) -> None:
        """Wildcard tokens are strictly forbidden in allowed_tools."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={wildcard},
            )
        assert "Wildcard permission" in str(exc.value)

    def test_reject_partial_wildcards(self) -> None:
        """Partial wildcards (e.g. read_*) are rejected."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_*"},
            )
        assert "Wildcard permission" in str(exc.value)

    def test_reject_empty_allowed_tools(self) -> None:
        """Policy without any allowed tools cannot be constructed."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools=set(),
            )
        assert "allowed_tools cannot be empty" in str(exc.value)

    def test_reject_string_as_allowed_tools(self) -> None:
        """Passing a raw string instead of a collection for allowed_tools is rejected."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools="read_inbox",  # type: ignore[arg-type]
            )
        assert "must be a set, list, or frozenset" in str(exc.value)

    @pytest.mark.parametrize("empty_task", ["", "   ", "\t\n"])
    def test_reject_empty_task_id(self, empty_task: str) -> None:
        """Empty or whitespace-only task_id is rejected."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=empty_task,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
            )
        assert "task_id cannot be empty" in str(exc.value)

    @pytest.mark.parametrize("bad_user_id", [0, -1, -99])
    def test_reject_non_positive_user_id(self, bad_user_id: int) -> None:
        """Simulated bound_user_id must be >= 1."""
        with pytest.raises(ValidationError):
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=bad_user_id,
                allowed_tools={"read_inbox"},
            )

    def test_reject_unknown_tool_in_policy(self) -> None:
        """Policy cannot authorize a tool not registered in KNOWN_SYSTEM_TOOLS."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"execute_shell"},
            )
        assert "not a recognized system tool" in str(exc.value)

    def test_reject_expiration_in_past_relative_to_issuance(self) -> None:
        """expires_at <= issued_at is strictly rejected at construction."""
        past = datetime.now(UTC) - timedelta(minutes=10)
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                issued_at=datetime.now(UTC),
                expires_at=past,
            )
        assert "strictly after issued_at" in str(exc.value)

    def test_reject_constraint_for_unpermitted_tool(self) -> None:
        """Policy cannot declare constraints for tools not present in allowed_tools."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                constraints={
                    "search_emails": SearchEmailsConstraint(max_limit=5),
                },
            )
        assert "not in allowed_tools" in str(exc.value)

    def test_reject_extra_fields(self) -> None:
        """Extra undeclared fields in TaskPolicy are forbidden."""
        with pytest.raises(ValidationError):
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                unauthorized_admin_flag=True,  # type: ignore[call-arg]
            )


# ===========================================================================
# 3. Invalid Constraints Rejection Tests
# ===========================================================================


class TestInvalidConstraintsRejection:
    """Tests verifying parameter validation on individual tool constraint models."""

    @pytest.mark.parametrize("bad_limit", [0, -1, 25])
    def test_reject_invalid_read_inbox_limits(self, bad_limit: int) -> None:
        """read_inbox limit constraint must be within 1..20."""
        with pytest.raises(ValidationError):
            ReadInboxConstraint(max_limit=bad_limit)

    def test_reject_negative_read_inbox_offset(self) -> None:
        """read_inbox offset constraint must be >= 0."""
        with pytest.raises(ValidationError):
            ReadInboxConstraint(max_offset=-1)

    def test_reject_non_positive_email_id_in_whitelist(self) -> None:
        """Email IDs in GetEmailDetailsConstraint must be positive integers."""
        with pytest.raises(ValidationError):
            GetEmailDetailsConstraint(allowed_email_ids=frozenset({0}))

        with pytest.raises(ValidationError):
            GetEmailDetailsConstraint(denied_email_ids=frozenset({-5}))

    def test_reject_overlapping_email_id_white_and_blacklist(self) -> None:
        """An email_id cannot simultaneously be whitelisted and blacklisted."""
        with pytest.raises(ValidationError) as exc:
            GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({1, 2, 3}),
                denied_email_ids=frozenset({3, 4, 5}),
            )
        assert "cannot appear in both allowed and denied sets" in str(exc.value)

    @pytest.mark.parametrize("bad_limit", [0, -1, 15])
    def test_reject_invalid_search_emails_limits(self, bad_limit: int) -> None:
        """search_emails limit constraint must be within 1..10."""
        with pytest.raises(ValidationError):
            SearchEmailsConstraint(max_limit=bad_limit)

    @pytest.mark.parametrize("bad_kw", ["", "   "])
    def test_reject_empty_blocked_search_keyword(self, bad_kw: str) -> None:
        """Blocked keywords list cannot contain empty strings."""
        with pytest.raises(ValidationError):
            SearchEmailsConstraint(blocked_keywords=frozenset({bad_kw}))

    def test_reject_invalid_query_length_bound(self) -> None:
        """max_query_length must be within 1..200."""
        with pytest.raises(ValidationError):
            SearchEmailsConstraint(max_query_length=0)
        with pytest.raises(ValidationError):
            SearchEmailsConstraint(max_query_length=300)


# ===========================================================================
# 4. ToolExecutionRequest Schema Tests
# ===========================================================================


class TestToolExecutionRequestValidation:
    """Tests verifying construction, validation, and aliases for ToolExecutionRequest."""

    def test_valid_request(self) -> None:
        """ToolExecutionRequest validates required fields."""
        req = ToolExecutionRequest(
            task_id=TASK_ID,
            tool_name="read_inbox",
            validated_arguments={"limit": 5},
            user_id=BOUND_USER_ID,
        )
        assert req.task_id == TASK_ID
        assert req.tool_name == "read_inbox"
        assert req.validated_arguments == {"limit": 5}
        assert req.arguments == {"limit": 5}
        assert req.user_id == BOUND_USER_ID
        assert req.bound_user_id == BOUND_USER_ID

    def test_request_aliases(self) -> None:
        """Supports arguments and bound_user_id aliases during construction."""
        req = ToolExecutionRequest(
            task_id=TASK_ID,
            tool_name="read_inbox",
            arguments={"limit": 3},  # alias
            bound_user_id=2,  # alias
        )
        assert req.validated_arguments == {"limit": 3}
        assert req.user_id == 2

    def test_request_immutability(self) -> None:
        """ToolExecutionRequest cannot be tampered with once created."""
        req = make_request()
        with pytest.raises(ValidationError):
            req.user_id = 999  # type: ignore[misc]

    @pytest.mark.parametrize("empty_str", ["", "   "])
    def test_reject_empty_request_strings(self, empty_str: str) -> None:
        """task_id and tool_name cannot be empty."""
        with pytest.raises(ValidationError):
            ToolExecutionRequest(
                task_id=empty_str,
                tool_name="read_inbox",
                user_id=BOUND_USER_ID,
            )
        with pytest.raises(ValidationError):
            ToolExecutionRequest(
                task_id=TASK_ID,
                tool_name=empty_str,
                user_id=BOUND_USER_ID,
            )


# ===========================================================================
# 5. Core Policy Evaluation Invariant Tests
# ===========================================================================


class TestPolicyEngineEvaluationInvariants:
    """Tests verifying PolicyEngine core evaluation rules and fail-closed behaviors."""

    def setup_method(self) -> None:
        self.engine = PolicyEngine()

    def test_missing_policy_fails_closed(self) -> None:
        """When no policy is provided, engine returns DENY with POLICY_MISSING."""
        req = make_request()
        decision = self.engine.evaluate(policy=None, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.POLICY_MISSING
        assert decision.is_denied
        assert not decision.is_allowed
        assert "default-deny" in decision.explanation

    def test_invalid_policy_type_fails_closed(self) -> None:
        """If a non-TaskPolicy object is passed, engine returns DENY with POLICY_INVALID."""
        req = make_request()
        decision = self.engine.evaluate(policy="malformed_policy_string", request=req)  # type: ignore[arg-type]

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.POLICY_INVALID
        assert decision.is_denied

    def test_expired_policy_fails_closed(self) -> None:
        """When a policy has expired, engine returns DENY with POLICY_EXPIRED."""
        # Policy issued in past and expired 1 minute ago
        past_issuance = datetime.now(UTC) - timedelta(hours=2)
        past_expiry = datetime.now(UTC) - timedelta(minutes=1)

        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox"},
            issued_at=past_issuance,
            expires_at=past_expiry,
        )
        req = make_request()
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.POLICY_EXPIRED
        assert decision.is_denied
        assert "Policy expired" in decision.explanation

    def test_expired_policy_with_injected_current_time(self) -> None:
        """Evaluation with explicit current_time detects expiration deterministically."""
        base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox"},
            issued_at=base_time,
            expires_at=base_time + timedelta(minutes=30),
        )
        req = make_request()

        # Before expiration -> ALLOW
        before = base_time + timedelta(minutes=15)
        d_before = self.engine.evaluate(policy=policy, request=req, current_time=before)
        assert d_before.decision == PolicyAction.ALLOW

        # After expiration -> DENY
        after = base_time + timedelta(minutes=31)
        d_after = self.engine.evaluate(policy=policy, request=req, current_time=after)
        assert d_after.decision == PolicyAction.DENY
        assert d_after.reason_code == PolicyReasonCode.POLICY_EXPIRED

    def test_wrong_task_id_fails_closed(self) -> None:
        """Request presenting a mismatched task_id is denied with TASK_MISMATCH."""
        policy = make_valid_policy(task_id="task_original_123")
        req = make_request(task_id="task_forged_999")
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.TASK_MISMATCH
        assert "does not match policy task_id" in decision.explanation

    def test_wrong_user_id_fails_closed(self) -> None:
        """Request presenting a mismatched user_id is denied with USER_MISMATCH."""
        policy = make_valid_policy(bound_user_id=1)
        req = make_request(user_id=2)  # Attempt cross-tenant execution
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.USER_MISMATCH
        assert "does not match policy bound_user_id" in decision.explanation

    def test_unknown_system_tool_fails_closed(self) -> None:
        """Tool not recognized by system registry returns DENY with UNKNOWN_TOOL."""
        policy = make_valid_policy(allowed_tools={"read_inbox"})
        req = make_request(tool_name="execute_shell")
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.UNKNOWN_TOOL
        assert "not a recognized system tool" in decision.explanation

    def test_missing_permission_for_known_tool_fails_closed(self) -> None:
        """Tool recognized by system but not permitted by this policy returns TOOL_NOT_PERMITTED."""
        # Policy only permits read_inbox
        policy = make_valid_policy(allowed_tools={"read_inbox"})
        # Request asks for search_emails (a valid tool, but unpermitted)
        req = make_request(tool_name="search_emails", arguments={"query": "test"})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.TOOL_NOT_PERMITTED
        assert "not permitted by policy" in decision.explanation

    def test_invalid_request_type_denied(self) -> None:
        """Passing non-ToolExecutionRequest to engine returns DENY."""
        policy = make_valid_policy()
        decision = self.engine.evaluate(policy=policy, request="not_a_request")  # type: ignore[arg-type]
        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.INVALID_ARGUMENTS

    def test_engine_unhandled_exception_fails_closed(self) -> None:
        """If an unexpected exception occurs inside evaluate, it produces DENY with EVALUATION_ERROR."""
        req = make_request()

        # Mock policy.is_expired to raise an unexpected runtime error
        mock_policy = MagicMock(spec=TaskPolicy)
        mock_policy.task_id = TASK_ID
        mock_policy.bound_user_id = BOUND_USER_ID
        mock_policy.policy_version = "1.0.0"
        mock_policy.is_expired.side_effect = RuntimeError(
            "Catastrophic disk corruption"
        )

        decision = self.engine.evaluate(policy=mock_policy, request=req)
        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.EVALUATION_ERROR
        assert "Catastrophic disk corruption" in decision.explanation


# ===========================================================================
# 6. Tool-Specific Parameter Constraints Evaluation Tests
# ===========================================================================


class TestToolConstraintsEvaluation:
    """Tests evaluating parameter bounds across read_inbox, get_email_details, and search_emails."""

    def setup_method(self) -> None:
        self.engine = PolicyEngine()

    # --- read_inbox Constraints ---

    def test_read_inbox_excessive_limit_denied(self) -> None:
        """Request exceeding policy max_limit is denied."""
        policy = make_valid_policy(
            allowed_tools={"read_inbox"},
            constraints={"read_inbox": ReadInboxConstraint(max_limit=5)},
        )
        req = make_request(tool_name="read_inbox", arguments={"limit": 10})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "exceeds policy maximum limit (5)" in decision.explanation

    def test_read_inbox_excessive_offset_denied(self) -> None:
        """Request exceeding policy max_offset is denied."""
        policy = make_valid_policy(
            allowed_tools={"read_inbox"},
            constraints={"read_inbox": ReadInboxConstraint(max_offset=20)},
        )
        req = make_request(tool_name="read_inbox", arguments={"offset": 50})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "exceeds policy maximum offset (20)" in decision.explanation

    def test_read_inbox_disallowed_is_read_filter_denied(self) -> None:
        """Request specifying a read-status filter forbidden by policy is denied."""
        policy = make_valid_policy(
            allowed_tools={"read_inbox"},
            constraints={"read_inbox": ReadInboxConstraint(allowed_is_read=False)},
        )
        req = make_request(tool_name="read_inbox", arguments={"is_read": True})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "does not match policy enforced value (False)" in decision.explanation

    # --- get_email_details Constraints ---

    def test_get_email_details_unwhitelisted_id_denied(self) -> None:
        """Request inspecting an email_id not in allowed_email_ids whitelist is denied."""
        policy = make_valid_policy(
            allowed_tools={"get_email_details"},
            constraints={
                "get_email_details": GetEmailDetailsConstraint(
                    allowed_email_ids=frozenset({1, 2, 3})
                )
            },
        )
        req = make_request(tool_name="get_email_details", arguments={"email_id": 99})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "not in the policy allowed_email_ids whitelist" in decision.explanation

    def test_get_email_details_blacklisted_id_denied(self) -> None:
        """Request inspecting an email_id in denied_email_ids is explicitly denied."""
        policy = make_valid_policy(
            allowed_tools={"get_email_details"},
            constraints={
                "get_email_details": GetEmailDetailsConstraint(
                    denied_email_ids=frozenset({10})
                )
            },
        )
        req = make_request(tool_name="get_email_details", arguments={"email_id": 10})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "explicitly denied by policy blacklist" in decision.explanation

    def test_get_email_details_max_id_exceeded_denied(self) -> None:
        """Request inspecting an email_id exceeding max_email_id is denied."""
        policy = make_valid_policy(
            allowed_tools={"get_email_details"},
            constraints={
                "get_email_details": GetEmailDetailsConstraint(max_email_id=50)
            },
        )
        req = make_request(tool_name="get_email_details", arguments={"email_id": 100})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "exceeds policy maximum email ID (50)" in decision.explanation

    def test_get_email_details_missing_arg_denied(self) -> None:
        """Request to get_email_details without email_id argument fails schema argument validation."""
        policy = make_valid_policy(
            allowed_tools={"get_email_details"},
            constraints={
                "get_email_details": GetEmailDetailsConstraint(max_email_id=50)
            },
        )
        req = make_request(tool_name="get_email_details", arguments={})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.ARGUMENT_INVALID
        assert (
            "Field required" in decision.explanation
            or "Missing" in decision.explanation
        )

    # --- search_emails Constraints ---

    def test_search_emails_blocked_keyword_denied(self) -> None:
        """Search query containing a policy-blocked keyword is denied (case-insensitive)."""
        policy = make_valid_policy(
            allowed_tools={"search_emails"},
            constraints={
                "search_emails": SearchEmailsConstraint(
                    blocked_keywords=frozenset({"password", "token", "credential"})
                )
            },
        )
        req = make_request(
            tool_name="search_emails",
            arguments={"query": "Find the admin PaSsWoRd please"},
        )
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "contains forbidden keyword 'password'" in decision.explanation

    def test_search_emails_query_length_exceeded_denied(self) -> None:
        """Search query exceeding max_query_length is denied."""
        policy = make_valid_policy(
            allowed_tools={"search_emails"},
            constraints={"search_emails": SearchEmailsConstraint(max_query_length=20)},
        )
        req = make_request(
            tool_name="search_emails",
            arguments={"query": "this search query is way too long for the policy"},
        )
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "exceeds policy maximum length (20)" in decision.explanation

    def test_search_emails_limit_exceeded_denied(self) -> None:
        """Search limit exceeding max_limit is denied."""
        policy = make_valid_policy(
            allowed_tools={"search_emails"},
            constraints={"search_emails": SearchEmailsConstraint(max_limit=3)},
        )
        req = make_request(
            tool_name="search_emails", arguments={"query": "exam", "limit": 5}
        )
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert (
            "Requested search limit (5) exceeds policy maximum limit (3)"
            in decision.explanation
        )

    # --- GenericToolConstraint ---

    def test_generic_tool_constraint_evaluation(self) -> None:
        """Generic constraint evaluates numeric bounds, allowed values, and blocked values."""
        g_constraint = GenericToolConstraint(
            max_numeric_values={"threshold": 100.0},
            allowed_values={"mode": ["safe", "audit"]},
            blocked_values={"secret_token": ["bad_val"]},
        )

        # 1. Numeric limit exceeded
        valid, msg = g_constraint.validate_arguments({"threshold": 150.0})
        assert not valid
        assert "exceeds policy maximum allowed value" in (msg or "")

        # 2. Disallowed mode
        valid, msg = g_constraint.validate_arguments({"mode": "raw"})
        assert not valid
        assert "not in policy allowed values" in (msg or "")

        # 3. Blocked value present
        valid, msg = g_constraint.validate_arguments({"secret_token": "bad_val"})
        assert not valid
        assert "has forbidden value" in (msg or "")

        # 4. Valid arguments pass
        valid, msg = g_constraint.validate_arguments(
            {"threshold": 50.0, "mode": "safe", "secret_token": "safe_val"}
        )
        assert valid
        assert msg is None


# ===========================================================================
# 7. Allowed Read-Only Operations Tests
# ===========================================================================


class TestAllowedReadOnlyOperations:
    """Tests verifying that compliant operations evaluate strictly to ALLOW."""

    def setup_method(self) -> None:
        self.engine = PolicyEngine()

    def test_allowed_read_inbox_within_limits(self) -> None:
        """read_inbox request satisfying all constraints is authorized with POLICY_ALLOW."""
        policy = make_valid_policy(
            allowed_tools={"read_inbox"},
            constraints={
                "read_inbox": ReadInboxConstraint(
                    max_limit=10, max_offset=20, allowed_is_read=False
                )
            },
        )
        req = make_request(
            tool_name="read_inbox",
            arguments={"limit": 5, "offset": 0, "is_read": False},
        )
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.ALLOW
        assert decision.reason_code == PolicyReasonCode.POLICY_ALLOW
        assert decision.is_allowed
        assert not decision.is_denied
        assert decision.task_id == TASK_ID
        assert decision.policy_version == "1.0.0"

    def test_allowed_get_email_details(self) -> None:
        """get_email_details request for whitelisted email_id is authorized."""
        policy = make_valid_policy(
            allowed_tools={"get_email_details"},
            constraints={
                "get_email_details": GetEmailDetailsConstraint(
                    allowed_email_ids=frozenset({1, 5, 12}),
                    denied_email_ids=frozenset({10, 20}),
                    max_email_id=100,
                )
            },
        )
        req = make_request(tool_name="get_email_details", arguments={"email_id": 5})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.ALLOW
        assert decision.reason_code == PolicyReasonCode.POLICY_ALLOW
        assert decision.is_allowed

    def test_allowed_search_emails(self) -> None:
        """search_emails request with benign query and bounded limit is authorized."""
        policy = make_valid_policy(
            allowed_tools={"search_emails"},
            constraints={
                "search_emails": SearchEmailsConstraint(
                    max_limit=5,
                    max_offset=10,
                    blocked_keywords=frozenset({"password", "token"}),
                    max_query_length=50,
                )
            },
        )
        req = make_request(
            tool_name="search_emails",
            arguments={"query": "syllabus CS101", "limit": 3, "offset": 0},
        )
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.ALLOW
        assert decision.reason_code == PolicyReasonCode.POLICY_ALLOW
        assert decision.is_allowed

    def test_allowed_tool_without_explicit_constraints(self) -> None:
        """A tool declared in allowed_tools without specific constraints is authorized."""
        policy = make_valid_policy(allowed_tools={"read_inbox"}, constraints={})
        req = make_request(tool_name="read_inbox", arguments={"limit": 5})
        decision = self.engine.evaluate(policy=policy, request=req)

        assert decision.decision == PolicyAction.ALLOW
        assert decision.reason_code == PolicyReasonCode.POLICY_ALLOW


# ===========================================================================
# 8. Policy Decision Properties and Representation Tests
# ===========================================================================


class TestPolicyDecisionProperties:
    """Tests verifying helper properties and serialization of PolicyDecision."""

    def test_decision_aliases_and_properties(self) -> None:
        """PolicyDecision exposes human_readable_explanation and reason properties."""
        decision = PolicyDecision(
            decision=PolicyAction.DENY,
            reason_code=PolicyReasonCode.TASK_MISMATCH,
            explanation="Task scope violated.",
            task_id=TASK_ID,
            policy_version="1.0.0",
        )
        assert decision.human_readable_explanation == "Task scope violated."
        assert decision.reason == "Task scope violated."
        assert decision.is_denied is True
        assert decision.is_allowed is False

    def test_decision_immutability(self) -> None:
        """PolicyDecision cannot be modified after creation."""
        decision = PolicyDecision(
            decision=PolicyAction.ALLOW,
            reason_code=PolicyReasonCode.POLICY_ALLOW,
            explanation="Authorized.",
            task_id=TASK_ID,
        )
        with pytest.raises(ValidationError):
            decision.decision = PolicyAction.DENY  # type: ignore[misc]


# ===========================================================================
# 9. Exceptions and Advanced Edge Cases Tests
# ===========================================================================


class TestSecurityExceptionsAndEdgeCases:
    """Tests verifying error classes, string representations, and schema corner cases."""

    def test_policy_denial_error_representation(self) -> None:
        """PolicyDenialError formats reason_code and explanation cleanly."""
        from app.security.exceptions import PolicyDenialError

        err = PolicyDenialError(
            reason_code="UNKNOWN_TOOL", explanation="Tool is not allowed."
        )
        assert err.reason_code == "UNKNOWN_TOOL"
        assert err.explanation == "Tool is not allowed."
        assert "[UNKNOWN_TOOL] Tool is not allowed." in str(err)

    def test_base_tool_constraint_default_validate(self) -> None:
        """BaseToolConstraint.validate_arguments returns (True, None) by default."""
        from app.security.schemas import BaseToolConstraint

        base_c = BaseToolConstraint()
        is_valid, msg = base_c.validate_arguments({"anything": 123})
        assert is_valid is True
        assert msg is None

    def test_search_emails_excessive_offset_denied(self) -> None:
        """search_emails offset exceeding max_offset is denied."""
        engine = PolicyEngine()
        policy = make_valid_policy(
            allowed_tools={"search_emails"},
            constraints={"search_emails": SearchEmailsConstraint(max_offset=5)},
        )
        req = make_request(
            tool_name="search_emails",
            arguments={"query": "test", "offset": 10},
        )
        decision = engine.evaluate(policy=policy, request=req)
        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
        assert "exceeds policy maximum offset (5)" in decision.explanation

    def test_coerce_frozenset_invalid_type_raises(self) -> None:
        """Passing non-iterable to allowed_email_ids raises ValidationError."""
        with pytest.raises(ValidationError) as exc:
            GetEmailDetailsConstraint(allowed_email_ids=123)  # type: ignore[arg-type]
        assert "must be an iterable of integers" in str(exc.value)

    def test_coerce_blocked_keywords_invalid_type_raises(self) -> None:
        """Passing non-iterable to blocked_keywords raises ValidationError."""
        with pytest.raises(ValidationError) as exc:
            SearchEmailsConstraint(blocked_keywords=123)  # type: ignore[arg-type]
        assert "must be an iterable of strings" in str(exc.value)

    def test_parse_constraints_non_dict_raises(self) -> None:
        """Passing a non-dict to constraints in TaskPolicy raises ValidationError."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                constraints=["not_a_dict"],  # type: ignore[arg-type]
            )
        assert "must be a dictionary" in str(exc.value)

    def test_parse_constraints_empty_tool_name_raises(self) -> None:
        """Empty tool name key in constraints dictionary raises ValidationError."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                constraints={"   ": {"max_limit": 5}},
            )
        assert "must be a non-empty string" in str(exc.value)

    def test_parse_constraints_invalid_value_type_raises(self) -> None:
        """Invalid value type in constraints dictionary raises ValidationError."""
        with pytest.raises(ValidationError) as exc:
            TaskPolicy(
                task_id=TASK_ID,
                bound_user_id=BOUND_USER_ID,
                allowed_tools={"read_inbox"},
                constraints={"read_inbox": 12345},  # type: ignore[dict-item]
            )
        assert "Invalid constraint type for tool 'read_inbox'" in str(exc.value)

    def test_ensure_utc_for_naive_datetime(self) -> None:
        """Naive datetimes for issued_at or expires_at are normalized to UTC."""
        naive_issued = datetime(2026, 10, 20, 10, 0, 0)
        naive_expires = datetime(2026, 10, 20, 11, 0, 0)
        policy = TaskPolicy(
            task_id=TASK_ID,
            bound_user_id=BOUND_USER_ID,
            allowed_tools={"read_inbox"},
            issued_at=naive_issued,
            expires_at=naive_expires,
        )
        assert policy.issued_at.tzinfo == UTC
        assert policy.expires_at is not None
        assert policy.expires_at.tzinfo == UTC
