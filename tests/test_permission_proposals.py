"""Unit and security verification test suite for AEGIS-CORE permission proposals.

Tests cover:
- Mapping of all supported simple intents to exact minimal permissions.
- Scoping of read_inbox limit=N and offset=0.
- Decoupling of response_language from tool authorization.
- Exact search term allowlist scoping (no wildcard, no forbidden_substrings substitute).
- Exact email ID scoping (single allowed ID).
- Fail-closed behavior on ambiguous or unsupported intents.
- Proposal immutability (frozen=True, extra="forbid").
- Proposal unforgeability (CSPRNG prop_<hex> format).
- Tool name validation against known system registry.
- Zero execution and zero tool adapter invocations during proposal generation.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.intent.mappings import (
    DEFAULT_SEARCH_PROPOSAL_LIMIT,
    map_intent_to_proposal,
)
from app.intent.parser import parse_intent
from app.intent.proposals import (
    PermissionProposal,
    ProposalSecurityError,
    ProposalStatus,
)
from app.intent.schemas import ActionType, IntentType, ResourceType, TaskIntent
from app.security.policy_engine import PolicyEngine
from app.security.schemas import (
    GetEmailDetailsConstraint,
    PolicyAction,
    PolicyReasonCode,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    TaskPolicy,
    ToolExecutionRequest,
)

# ---------------------------------------------------------------------------
# 1. Supported Intent Mapping Verification
# ---------------------------------------------------------------------------


class TestSupportedIntentMappings:
    def test_read_latest_emails_mapping(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        proposal = map_intent_to_proposal(intent, user_id=1, task_id="task_test_01")

        assert proposal.status == ProposalStatus.PENDING
        assert proposal.is_pending is True
        assert proposal.user_id == 1
        assert proposal.task_id == "task_test_01"
        assert proposal.proposal_id.startswith("prop_")
        assert len(proposal.proposal_id) >= 20

        # Exact single tool mapping
        assert proposal.requested_tool == "read_inbox"
        assert list(proposal.requested_constraints.keys()) == ["read_inbox"]

        # Exact minimal constraint
        constraint = proposal.requested_constraints["read_inbox"]
        assert isinstance(constraint, ReadInboxConstraint)
        assert constraint.max_limit == 3
        assert constraint.max_offset == 0
        assert constraint.allowed_is_read is None

        # Verify constraint behavior
        valid, _ = constraint.validate_arguments({"limit": 3, "offset": 0})
        assert valid is True

        # Limits cannot be exceeded
        invalid_limit, msg = constraint.validate_arguments({"limit": 4, "offset": 0})
        assert invalid_limit is False
        assert "exceeds policy maximum limit (3)" in msg

        # Offsets cannot be exceeded
        invalid_offset, msg = constraint.validate_arguments({"limit": 3, "offset": 1})
        assert invalid_offset is False
        assert "exceeds policy maximum offset (0)" in msg

    def test_summarize_recent_emails_mapping_decouples_language(self) -> None:
        intent = parse_intent("Summarize my latest 2 emails in Arabic.")
        proposal = map_intent_to_proposal(intent, user_id=2)

        assert proposal.requested_tool == "read_inbox"
        assert list(proposal.requested_constraints.keys()) == ["read_inbox"]

        constraint = proposal.requested_constraints["read_inbox"]
        assert isinstance(constraint, ReadInboxConstraint)
        assert constraint.max_limit == 2
        assert constraint.max_offset == 0

        # Language is preserved on intent for presentation but confers 0 extra tools
        assert proposal.normalized_intent.response_language == "ar"
        assert "search_emails" not in proposal.requested_constraints
        assert "get_email_details" not in proposal.requested_constraints
        assert "zero additional tool permissions" in proposal.rationale

    def test_search_emails_exact_term_scoping(self) -> None:
        intent = parse_intent("Search emails for assignment.")
        proposal = map_intent_to_proposal(intent, user_id=1)

        assert proposal.requested_tool == "search_emails"
        assert list(proposal.requested_constraints.keys()) == ["search_emails"]

        constraint = proposal.requested_constraints["search_emails"]
        assert isinstance(constraint, SearchEmailsConstraint)
        assert constraint.max_limit == DEFAULT_SEARCH_PROPOSAL_LIMIT
        assert constraint.max_offset == 0
        assert constraint.allowed_search_terms == frozenset({"assignment"})

        # Exact query match allows
        valid, _ = constraint.validate_arguments(
            {"query": "assignment", "limit": 5, "offset": 0}
        )
        assert valid is True

        # Case-insensitive normalized query match allows
        valid_case, _ = constraint.validate_arguments(
            {"query": "Assignment", "limit": 5, "offset": 0}
        )
        assert valid_case is True

        # Different query MUST be denied by exact whitelist
        denied_query, msg = constraint.validate_arguments(
            {"query": "passwords", "limit": 5, "offset": 0}
        )
        assert denied_query is False
        assert "not in policy allowed_search_terms whitelist" in msg

        # Limit expansion denied
        denied_limit, msg = constraint.validate_arguments(
            {"query": "assignment", "limit": 6, "offset": 0}
        )
        assert denied_limit is False
        assert "exceeds policy maximum limit (5)" in msg

    def test_read_email_details_exact_id_scoping(self) -> None:
        intent = parse_intent("Show email 7.")
        proposal = map_intent_to_proposal(intent, user_id=3)

        assert proposal.requested_tool == "get_email_details"
        assert list(proposal.requested_constraints.keys()) == ["get_email_details"]

        constraint = proposal.requested_constraints["get_email_details"]
        assert isinstance(constraint, GetEmailDetailsConstraint)
        assert constraint.allowed_email_ids == frozenset({7})
        assert constraint.max_email_id == 7

        # Exact ID authorized
        valid, _ = constraint.validate_arguments({"email_id": 7})
        assert valid is True

        # Other IDs strictly denied
        denied_other, msg = constraint.validate_arguments({"email_id": 8})
        assert denied_other is False
        assert "not in the policy allowed_email_ids whitelist" in msg

        denied_lower, msg = constraint.validate_arguments({"email_id": 1})
        assert denied_lower is False
        assert "not in the policy allowed_email_ids whitelist" in msg

    def test_arabic_supported_intent_proposals(self) -> None:
        # Arabic Summarize
        intent_sum = parse_intent("لخص آخر 3 إيميلات بالعربي.")
        proposal_sum = map_intent_to_proposal(intent_sum, user_id=1)
        assert proposal_sum.requested_tool == "read_inbox"
        assert proposal_sum.requested_constraints["read_inbox"].max_limit == 3

        # Arabic Search
        intent_search = parse_intent("ابحث عن إيميلات فيها كلمة امتحان.")
        proposal_search = map_intent_to_proposal(intent_search, user_id=1)
        assert proposal_search.requested_tool == "search_emails"
        assert proposal_search.requested_constraints[
            "search_emails"
        ].allowed_search_terms == frozenset({"امتحان"})

        # Arabic Show
        intent_show = parse_intent("اعرض الإيميل رقم 7.")
        proposal_show = map_intent_to_proposal(intent_show, user_id=1)
        assert proposal_show.requested_tool == "get_email_details"
        assert proposal_show.requested_constraints[
            "get_email_details"
        ].allowed_email_ids == frozenset({7})


# ---------------------------------------------------------------------------
# 2. Security Boundaries & Fail-Closed Invariants
# ---------------------------------------------------------------------------


class TestProposalSecurityBoundaries:
    def test_ambiguous_intent_cannot_generate_proposal(self) -> None:
        intent = parse_intent("Read emails.")
        assert intent.is_ambiguous is True
        assert intent.requires_clarification is True

        with pytest.raises(
            ProposalSecurityError, match="Cannot generate a permission proposal"
        ):
            map_intent_to_proposal(intent, user_id=1)

    def test_arabic_ambiguous_intent_cannot_generate_proposal(self) -> None:
        intent = parse_intent("شوف الرسائل")
        assert intent.is_ambiguous is True

        with pytest.raises(
            ProposalSecurityError, match="Cannot generate a permission proposal"
        ):
            map_intent_to_proposal(intent, user_id=1)

    def test_invalid_or_unsupported_intent_fails_closed(self) -> None:
        # Construct ambiguous intent manually
        ambig_intent = TaskIntent(
            intent_type=IntentType.AMBIGUOUS,
            resource_type=ResourceType.UNKNOWN,
            requested_action=ActionType.UNKNOWN,
            is_ambiguous=True,
            requires_clarification=True,
            clarification_prompt="Need clarification",
            source_request="Vague input",
        )
        with pytest.raises(ProposalSecurityError):
            map_intent_to_proposal(ambig_intent, user_id=1)

    def test_proposal_immutability(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        proposal = map_intent_to_proposal(intent, user_id=1)

        with pytest.raises(ValidationError):
            proposal.status = ProposalStatus.APPROVED  # type: ignore[misc]

        with pytest.raises(ValidationError):
            proposal.requested_tool = "delete_all"  # type: ignore[misc]

        with pytest.raises(ValidationError):
            proposal.user_id = 999  # type: ignore[misc]

    def test_proposal_forbids_extra_fields(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(ValidationError):
            PermissionProposal(
                proposal_id="prop_" + ("a" * 32),
                task_id="task_01",
                user_id=1,
                normalized_intent=intent,
                requested_tool="read_inbox",
                requested_constraints={"read_inbox": ReadInboxConstraint(max_limit=3)},
                human_readable_summary="Summary",
                rationale="Rationale",
                extra_malicious_field="attack",  # type: ignore[call-arg]
            )

    def test_proposal_id_unforgeability_format(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(ValidationError, match="not a valid unforgeable format"):
            PermissionProposal(
                proposal_id="admin_forged_id_12345",
                task_id="task_01",
                user_id=1,
                normalized_intent=intent,
                requested_tool="read_inbox",
                requested_constraints={"read_inbox": ReadInboxConstraint(max_limit=3)},
                human_readable_summary="Summary",
                rationale="Rationale",
            )

    def test_proposal_rejects_unallowlisted_tool(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(
            ValidationError, match="not recognized in allowed system tools"
        ):
            PermissionProposal(
                proposal_id="prop_" + ("b" * 32),
                task_id="task_01",
                user_id=1,
                normalized_intent=intent,
                requested_tool="execute_shell",  # forbidden
                requested_constraints={"read_inbox": ReadInboxConstraint(max_limit=3)},
                human_readable_summary="Summary",
                rationale="Rationale",
            )

    def test_proposal_rejects_multi_tool_bundling(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(ValidationError, match="must constrain exactly one tool"):
            PermissionProposal(
                proposal_id="prop_" + ("c" * 32),
                task_id="task_01",
                user_id=1,
                normalized_intent=intent,
                requested_tool="read_inbox",
                requested_constraints={
                    "read_inbox": ReadInboxConstraint(max_limit=3),
                    "search_emails": SearchEmailsConstraint(max_limit=5),
                },
                human_readable_summary="Summary",
                rationale="Rationale",
            )

    def test_proposal_rejects_mismatched_constraints_tool(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(
            ValidationError, match="must contain constraints for requested tool"
        ):
            PermissionProposal(
                proposal_id="prop_" + ("d" * 32),
                task_id="task_01",
                user_id=1,
                normalized_intent=intent,
                requested_tool="read_inbox",
                requested_constraints={
                    "search_emails": SearchEmailsConstraint(max_limit=5),
                },
                human_readable_summary="Summary",
                rationale="Rationale",
            )

    def test_proposal_expiration_lifecycle(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        proposal = map_intent_to_proposal(intent, user_id=1, ttl_seconds=60)

        # Active proposal
        assert proposal.is_expired() is False

        # Past expiration
        future_time = datetime.now(UTC) + timedelta(seconds=120)
        assert proposal.is_expired(now=future_time) is True

        # None expiration never expires
        no_expiry = PermissionProposal(
            proposal_id="prop_" + ("e" * 32),
            task_id="task_no_exp",
            user_id=1,
            normalized_intent=intent,
            requested_tool="read_inbox",
            requested_constraints={"read_inbox": ReadInboxConstraint(max_limit=3)},
            human_readable_summary="Summary",
            rationale="Rationale",
            expires_at=None,
        )
        assert no_expiry.is_expired() is False

        # Expiration before creation is forbidden
        past_time = datetime.now(UTC) - timedelta(seconds=60)
        with pytest.raises(ValidationError, match="must be strictly after creation"):
            PermissionProposal(
                proposal_id="prop_" + ("f" * 32),
                task_id="task_past",
                user_id=1,
                normalized_intent=intent,
                requested_tool="read_inbox",
                requested_constraints={"read_inbox": ReadInboxConstraint(max_limit=3)},
                human_readable_summary="Summary",
                rationale="Rationale",
                expires_at=past_time,
            )

    def test_default_task_id_generated(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        proposal = map_intent_to_proposal(intent, user_id=1, task_id=None)
        assert proposal.task_id.startswith("task_")
        assert len(proposal.task_id) > 10

    def test_invalid_user_id_rejected(self) -> None:
        intent = parse_intent("Read my latest 3 emails.")
        with pytest.raises(ValueError, match="positive integer"):
            map_intent_to_proposal(intent, user_id=0)

        with pytest.raises(ValueError, match="positive integer"):
            map_intent_to_proposal(intent, user_id=-5)


# ---------------------------------------------------------------------------
# 3. Trust Boundary & Zero Execution Guarantees
# ---------------------------------------------------------------------------


class TestTrustBoundaryAndZeroExecution:
    def test_proposal_is_never_an_active_policy(self) -> None:
        """A PermissionProposal is NOT a TaskPolicy and cannot authorize tool execution."""
        intent = parse_intent("Read my latest 3 emails.")
        proposal = map_intent_to_proposal(intent, user_id=1)

        assert not isinstance(proposal, TaskPolicy)
        assert proposal.status == ProposalStatus.PENDING

        # Verify that PolicyEngine denies evaluation if a proposal is passed as a policy
        engine = PolicyEngine()
        request = ToolExecutionRequest(
            task_id=proposal.task_id,
            tool_name="read_inbox",
            validated_arguments={"limit": 3, "offset": 0},
            user_id=1,
        )

        decision = engine.evaluate(
            policy=proposal,  # type: ignore[arg-type]
            request=request,
        )
        # PolicyEngine expects TaskPolicy, encounters type mismatch and evaluates to DENY
        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code in (
            PolicyReasonCode.POLICY_INVALID,
            PolicyReasonCode.EVALUATION_ERROR,
        )

    def test_zero_tool_adapter_invocations_during_proposal_generation(self) -> None:
        """Generating a proposal must invoke underlying tool adapters ZERO times."""
        with (
            patch("app.agent.tools.email_tools.read_inbox") as mock_read,
            patch("app.agent.tools.email_tools.search_emails") as mock_search,
            patch("app.agent.tools.email_tools.get_email_details") as mock_details,
        ):
            intent_read = parse_intent("Read my latest 3 emails.")
            map_intent_to_proposal(intent_read, user_id=1)

            intent_search = parse_intent("Search emails for assignment.")
            map_intent_to_proposal(intent_search, user_id=1)

            intent_details = parse_intent("Show email 7.")
            map_intent_to_proposal(intent_details, user_id=1)

            assert mock_read.call_count == 0
            assert mock_search.call_count == 0
            assert mock_details.call_count == 0


class TestMappingDefensiveBranches:
    def test_mocked_invalid_intent_branches(self) -> None:
        # Intent with is_valid=False
        class MockInvalidIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = False
            intent_type = IntentType.READ_LATEST_EMAILS

        with pytest.raises(ProposalSecurityError, match="invalid intent"):
            map_intent_to_proposal(MockInvalidIntent(), user_id=1)  # type: ignore[arg-type]

        # Intent with invalid count
        class MockBadCountIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = IntentType.READ_LATEST_EMAILS
            requested_count = 99  # excessive

        with pytest.raises(ProposalSecurityError, match="Invalid requested count"):
            map_intent_to_proposal(MockBadCountIntent(), user_id=1)  # type: ignore[arg-type]

        # Intent with invalid count for SUMMARIZE
        class MockBadSummCountIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = IntentType.SUMMARIZE_RECENT_EMAILS
            requested_count = 0  # non-positive
            response_language = "en"

        with pytest.raises(ProposalSecurityError, match="Invalid requested count"):
            map_intent_to_proposal(MockBadSummCountIntent(), user_id=1)  # type: ignore[arg-type]

        # Intent with empty search query
        class MockEmptySearchIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = IntentType.SEARCH_EMAILS
            search_query = "   "

        with pytest.raises(
            ProposalSecurityError, match="Missing or empty search query"
        ):
            map_intent_to_proposal(MockEmptySearchIntent(), user_id=1)  # type: ignore[arg-type]

        # Intent with oversized search query
        class MockOversizedSearchIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = IntentType.SEARCH_EMAILS
            search_query = "x" * 250

        with pytest.raises(ProposalSecurityError, match="exceeds maximum limit"):
            map_intent_to_proposal(MockOversizedSearchIntent(), user_id=1)  # type: ignore[arg-type]

        # Intent with invalid email_id
        class MockBadEmailIdIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = IntentType.READ_EMAIL_DETAILS
            requested_email_id = -1

        with pytest.raises(ProposalSecurityError, match="Invalid email_id"):
            map_intent_to_proposal(MockBadEmailIdIntent(), user_id=1)  # type: ignore[arg-type]

        # Unsupported intent type
        class MockUnsupportedTypeIntent:
            is_ambiguous = False
            requires_clarification = False
            is_valid = True
            intent_type = "unknown_action_type"

        with pytest.raises(ProposalSecurityError, match="Unsupported intent type"):
            map_intent_to_proposal(MockUnsupportedTypeIntent(), user_id=1)  # type: ignore[arg-type]
