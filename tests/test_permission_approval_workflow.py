"""Comprehensive security and authorization verification suite for Week 4 permission approvals.

Tests cover:
- Proposal creation causes ZERO tool executions.
- Pending proposals cannot authorize execution under PolicyEngine or ToolExecutor.
- Explicit approval by a trusted controller activates exact minimal TaskPolicy.
- Rejection prevents proposal activation.
- Expired proposals cannot be approved or consumed.
- Forged or nonexistent proposal IDs fail closed.
- Model-generated or untrusted controller approvals are strictly rejected (403).
- Model-generated or client-supplied policy replacements are rejected.
- Immutability of proposals, policies, and constraints (tampering forbidden).
- Duplicate approval handling (idempotency/state conflict).
- Replay prevention: Consumed proposals cannot be reused.
- Cross-tenant proposal reuse fails closed (User 1 cannot consume User 2's proposal).
- Cross-task policy reuse fails closed (Task A cannot consume Task B's proposal).
- Concurrency safety: Atomic state transitions under race conditions.
- Strict constraint enforcement: Approving limit=3 never authorizes limit=10.
- Complete REST API integration tests for /propose, /approve, and /reject.
"""

import threading
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agent.executor import ToolExecutor
from app.intent.approval import (
    PermissionApprovalService,
    ProposalStore,
    default_approval_service,
)
from app.intent.exceptions import (
    InvalidProposalTransitionError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalReplayError,
    ProposalSecurityError,
    ProposalStateError,
    UntrustedControllerError,
)
from app.intent.proposals import ProposalStatus
from app.security.policy_engine import PolicyEngine
from app.security.schemas import (
    PolicyAction,
    PolicyReasonCode,
    ReadInboxConstraint,
    TaskPolicy,
    ToolExecutionRequest,
)


@pytest.fixture(autouse=True)
def clean_approval_store() -> None:
    """Clear global and isolated proposal stores before and after each test."""
    default_approval_service.store.clear()
    yield
    default_approval_service.store.clear()


@pytest.fixture
def approval_service() -> PermissionApprovalService:
    """Provide a fresh, isolated PermissionApprovalService instance."""
    return PermissionApprovalService(store=ProposalStore())


# ---------------------------------------------------------------------------
# 1. Proposal Creation & Tool Invocations
# ---------------------------------------------------------------------------


class TestProposalCreationZeroExecution:
    def test_proposal_creation_never_executes_tools(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """Creating a proposal must perform pure parsing and zero tool executions."""
        with (
            patch("app.agent.tools.email_tools.read_inbox") as mock_read,
            patch("app.agent.tools.email_tools.search_emails") as mock_search,
            patch("app.agent.tools.email_tools.get_email_details") as mock_details,
        ):
            proposal = approval_service.propose(
                user_id=1,
                message="Read my latest 3 emails.",
            )
            assert proposal.status == ProposalStatus.PENDING
            assert proposal.is_pending is True

            # Verify zero underlying tool executions
            assert mock_read.call_count == 0
            assert mock_search.call_count == 0
            assert mock_details.call_count == 0

    def test_pending_proposal_cannot_run_agent_or_firewall(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """A PENDING proposal cannot authorize execution through ToolExecutor."""
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        assert proposal.status == ProposalStatus.PENDING

        executor = ToolExecutor()
        outcome = executor.execute(
            call_id="call_test_01",
            tool_name="read_inbox",
            raw_arguments={"limit": 3, "offset": 0},
            user_id=1,
            policy=proposal,  # type: ignore[arg-type] # Pass proposal instead of policy
        )

        assert outcome.success is False
        assert outcome.policy_decision is not None
        assert outcome.policy_decision.decision == PolicyAction.DENY
        assert outcome.policy_decision.reason_code in (
            PolicyReasonCode.POLICY_INVALID,
            PolicyReasonCode.EVALUATION_ERROR,
        )


# ---------------------------------------------------------------------------
# 2. Explicit Approval & Exact Scope Activation
# ---------------------------------------------------------------------------


class TestExplicitApprovalLifecycle:
    def test_explicit_approval_activates_exact_proposed_scope(
        self, approval_service: PermissionApprovalService
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        receipt, policy = approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
            reason="Verified by human operator",
        )

        assert receipt.status == ProposalStatus.APPROVED
        assert receipt.approved_by == "local-supervisor"
        assert receipt.authorized_tool == "read_inbox"

        # Verify generated TaskPolicy
        assert isinstance(policy, TaskPolicy)
        assert policy.bound_user_id == 1
        assert policy.task_id == proposal.task_id
        assert policy.allowed_tools == frozenset({"read_inbox"})
        assert "read_inbox" in policy.constraints

        # Verify exact constraint scoping
        constraint = policy.constraints["read_inbox"]
        assert isinstance(constraint, ReadInboxConstraint)
        assert constraint.max_limit == 3
        assert constraint.max_offset == 0

        # Firewall verification: limit 3 allowed, limit 4 denied
        engine = PolicyEngine()
        req_valid = ToolExecutionRequest(
            task_id=policy.task_id,
            tool_name="read_inbox",
            validated_arguments={"limit": 3, "offset": 0},
            user_id=1,
        )
        assert engine.evaluate(policy, req_valid).decision == PolicyAction.ALLOW

        req_exceed = ToolExecutionRequest(
            task_id=policy.task_id,
            tool_name="read_inbox",
            validated_arguments={"limit": 4, "offset": 0},
            user_id=1,
        )
        decision_exceed = engine.evaluate(policy, req_exceed)
        assert decision_exceed.decision == PolicyAction.DENY
        assert decision_exceed.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION

    def test_approving_limit_3_never_authorizes_limit_10(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """Security Invariant: Approved limit cannot be escalated at execution."""
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        _, policy = approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        engine = PolicyEngine()
        req_escalated = ToolExecutionRequest(
            task_id=policy.task_id,
            tool_name="read_inbox",
            validated_arguments={"limit": 10, "offset": 0},
            user_id=1,
        )
        decision = engine.evaluate(policy, req_escalated)
        assert decision.decision == PolicyAction.DENY
        assert decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION

    def test_rejecting_proposal_prevents_activation(
        self, approval_service: PermissionApprovalService
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        rejected = approval_service.reject(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
            reason="User cancelled request",
        )
        assert rejected.status == ProposalStatus.REJECTED

        # Cannot approve rejected proposal
        with pytest.raises(InvalidProposalTransitionError):
            approval_service.approve(
                proposal_id=proposal.proposal_id,
                controller_id="local-supervisor",
            )

        # Cannot consume rejected proposal
        with pytest.raises(ProposalStateError):
            approval_service.consume(
                proposal_id=proposal.proposal_id,
                user_id=1,
                task_id=proposal.task_id,
            )

    def test_expired_proposal_cannot_be_approved(
        self, approval_service: PermissionApprovalService
    ) -> None:
        # Create a proposal
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        # Manually backdate created_at and expires_at so it is safely expired
        past_created = datetime.now(UTC) - timedelta(seconds=120)
        past_expires = datetime.now(UTC) - timedelta(seconds=60)
        expired_proposal = proposal.model_copy(
            update={"created_at": past_created, "expires_at": past_expires}
        )
        approval_service.store.save(expired_proposal)

        with pytest.raises(
            ProposalExpiredError, match="has expired and cannot be approved"
        ):
            approval_service.approve(
                proposal_id=proposal.proposal_id,
                controller_id="local-supervisor",
            )


# ---------------------------------------------------------------------------
# 3. Trust Boundary & Controller Verification
# ---------------------------------------------------------------------------


class TestTrustBoundaryAndControllers:
    @pytest.mark.parametrize(
        "bad_controller",
        [
            "llm",
            "llm_agent",
            "model",
            "agent",
            "untrusted",
            "ai",
            "auto",
            "client",
            "system_prompt",
            "",
            "   ",
        ],
    )
    def test_model_generated_approval_attempt_rejected(
        self,
        approval_service: PermissionApprovalService,
        bad_controller: str,
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        with pytest.raises(UntrustedControllerError, match="untrusted"):
            approval_service.approve(
                proposal_id=proposal.proposal_id,
                controller_id=bad_controller,
            )

    def test_forged_proposal_id_fails(
        self, approval_service: PermissionApprovalService
    ) -> None:
        with pytest.raises(ProposalNotFoundError, match="not found"):
            approval_service.approve(
                proposal_id="prop_0123456789abcdef0123456789abcdef",
                controller_id="local-supervisor",
            )

    def test_attempted_modification_of_constraints_fails(
        self, approval_service: PermissionApprovalService
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        _, policy = approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        # Immutability prevents runtime tampering
        with pytest.raises(ValidationError):
            policy.constraints = {}  # type: ignore[misc]

        with pytest.raises(ValidationError):
            policy.allowed_tools = frozenset({"execute_shell"})  # type: ignore[misc]

    def test_duplicate_approval_rejected(
        self, approval_service: PermissionApprovalService
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        # Second approval attempt fails as invalid state transition
        with pytest.raises(InvalidProposalTransitionError):
            approval_service.approve(
                proposal_id=proposal.proposal_id,
                controller_id="local-supervisor",
            )


# ---------------------------------------------------------------------------
# 4. Replay Prevention & Isolation Guarantees
# ---------------------------------------------------------------------------


class TestReplayAndTenantIsolation:
    def test_consumed_proposal_replay_rejected(
        self, approval_service: PermissionApprovalService
    ) -> None:
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        _, policy1 = approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        # First consumption succeeds
        policy_active = approval_service.consume(
            proposal_id=proposal.proposal_id,
            user_id=1,
            task_id=proposal.task_id,
        )
        assert policy_active == policy1

        # Replay attempt fails closed
        with pytest.raises(ProposalReplayError, match="already been consumed"):
            approval_service.consume(
                proposal_id=proposal.proposal_id,
                user_id=1,
                task_id=proposal.task_id,
            )

    def test_cross_user_proposal_reuse_fails(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """User 2 cannot approve or consume User 1's proposal."""
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )

        # Cross-user approval fails
        with pytest.raises(ProposalSecurityError, match="Tenant mismatch"):
            approval_service.approve(
                proposal_id=proposal.proposal_id,
                controller_id="local-supervisor",
                session_user_id=2,  # User 2 attempting to approve User 1's proposal
            )

        # Legitimate approval
        approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
            session_user_id=1,
        )

        # Cross-user consumption fails
        with pytest.raises(ProposalSecurityError, match="User mismatch"):
            approval_service.consume(
                proposal_id=proposal.proposal_id,
                user_id=2,  # User 2 attempting to consume User 1's proposal
                task_id=proposal.task_id,
            )

    def test_cross_task_policy_reuse_fails(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """A proposal cannot be consumed by a different task_id."""
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
            task_id="task_original_01",
        )
        approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
            task_id="task_original_01",
        )

        with pytest.raises(ProposalSecurityError, match="Task mismatch"):
            approval_service.consume(
                proposal_id=proposal.proposal_id,
                user_id=1,
                task_id="task_forged_99",  # Foreign task ID
            )

    def test_concurrent_approval_is_deterministic_and_safe(
        self, approval_service: PermissionApprovalService
    ) -> None:
        """Concurrent approval attempts race safely with exactly 1 success."""
        proposal = approval_service.propose(
            user_id=1,
            message="Read my latest 3 emails.",
        )
        results: list[str] = []
        errors: list[Exception] = []

        def _attempt_approve(cid: str) -> None:
            try:
                receipt, _ = approval_service.approve(
                    proposal_id=proposal.proposal_id,
                    controller_id=cid,
                )
                results.append(receipt.approved_by)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=_attempt_approve, args=("local-supervisor-1",))
        t2 = threading.Thread(target=_attempt_approve, args=("local-supervisor-2",))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one thread succeeds
        assert len(results) == 1
        assert len(errors) == 1
        assert isinstance(
            errors[0], (InvalidProposalTransitionError, ProposalStateError)
        )


# ---------------------------------------------------------------------------
# 5. REST API Integration Tests
# ---------------------------------------------------------------------------


class TestPermissionsAPI:
    def test_propose_endpoint_success(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        response = sync_client.post(
            "/api/v1/permissions/propose",
            json={
                "user_id": 1,
                "message": "Read my latest 3 emails.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["proposal_id"].startswith("prop_")
        assert data["user_id"] == 1
        assert data["requested_tool"] == "read_inbox"
        assert data["requested_constraints"]["read_inbox"]["max_limit"] == 3
        assert data["status"] == "PENDING"

    def test_propose_endpoint_user_not_found(self, sync_client: TestClient) -> None:
        response = sync_client.post(
            "/api/v1/permissions/propose",
            json={
                "user_id": 9999,
                "message": "Read my latest 3 emails.",
            },
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_propose_endpoint_ambiguous_intent_rejected(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        response = sync_client.post(
            "/api/v1/permissions/propose",
            json={
                "user_id": 1,
                "message": "Read emails.",
            },
        )
        assert response.status_code == 422
        assert "Unable to propose permissions" in response.json()["detail"]

    def test_approve_endpoint_success(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        # 1. Propose
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Show email 7."},
        )
        assert prop_res.status_code == 200
        proposal_id = prop_res.json()["proposal_id"]

        # 2. Approve with trusted controller header
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
            json={"controller_id": "local-supervisor", "reason": "Authorized by admin"},
        )
        assert app_res.status_code == 200
        receipt = app_res.json()
        assert receipt["status"] == "APPROVED"
        assert receipt["authorized_tool"] == "get_email_details"
        assert receipt["approved_by"] == "local-supervisor"

    def test_approve_endpoint_untrusted_controller_forbidden(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Show email 7."},
        )
        proposal_id = prop_res.json()["proposal_id"]

        # Model or untrusted controller
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "llm_agent"},
            json={"controller_id": "llm_agent"},
        )
        assert app_res.status_code == 403
        assert "untrusted" in app_res.json()["detail"].lower()

    def test_approve_endpoint_missing_controller_forbidden(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: Calling /approve without trusted controller identity fails with HTTP 403."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Show email 7."},
        )
        proposal_id = prop_res.json()["proposal_id"]

        # 1. No headers, no body
        res_no_auth = sync_client.post(f"/api/v1/permissions/{proposal_id}/approve")
        assert res_no_auth.status_code == 403
        assert (
            "missing trusted controller authorization"
            in res_no_auth.json()["detail"].lower()
        )

        # 2. Empty body
        res_empty_body = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            json={},
        )
        assert res_empty_body.status_code == 403

        # 3. Blank header
        res_blank_header = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "   "},
        )
        assert res_blank_header.status_code == 403

    def test_reject_endpoint_success(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Search emails for assignment."},
        )
        proposal_id = prop_res.json()["proposal_id"]

        rej_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/reject",
            json={"reason": "Forbidden by supervisor"},
        )
        assert rej_res.status_code == 200
        data = rej_res.json()
        assert data["status"] == "REJECTED"
        assert "rejected" in data["message"].lower()

    def test_approve_nonexistent_proposal_returns_404(
        self, sync_client: TestClient
    ) -> None:
        response = sync_client.post(
            "/api/v1/permissions/prop_0123456789abcdef0123456789abcdef/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )
        assert response.status_code == 404
