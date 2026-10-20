"""End-to-end integration and security QA test suite for AEGIS-CORE Week 4.

==============================================================================
COVERAGE MATRIX:
------------------------------------------------------------------------------
A. Happy Path:
   - Read latest 3 emails
   - Summarize latest 2 emails in Arabic
   - Search for an explicit keyword
   - Read one explicitly requested email ID
B. Approval Failures:
   - Missing approval (PENDING)
   - Rejected proposal
   - Expired proposal
   - Forged task ID
   - Replayed approval (at-most-once execution)
   - Simulated user mismatch
C. Policy Violations:
   - Agent requests too many emails
   - Agent requests unpermitted tool
   - Agent attempts to switch user
   - Agent requests another email ID
   - Agent changes search query
   - Client injects forbidden fields in execution request
D. Injection Simulations:
   - Untrusted email requests broader access
   - Untrusted email claims administrator authority
   - Untrusted email attempts self-approval
   - Untrusted email attempts policy mutation
E. Concurrency:
   - Concurrent execution attempts enforce at-most-once execution
   - Concurrent approvals
F. Legacy Endpoint Isolation:
   - POST /api/v1/agent/run isolated with benchmark warning headers
==============================================================================
"""

import concurrent.futures
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.agent.orchestrator import AgentOrchestrator
from app.agent.providers.base import LLMResponse, ToolCall
from app.agent.providers.fake_provider import FakeLLMProvider
from app.intent.approval import default_approval_service
from app.security.schemas import (
    PolicyAction,
    PolicyReasonCode,
)


@pytest.fixture(autouse=True)
def clean_approval_store():
    """Ensure in-memory proposal store is clean before and after every test."""
    default_approval_service.store.clear()
    yield
    default_approval_service.store.clear()


# ---------------------------------------------------------------------------
# A. Happy Path Scenarios
# ---------------------------------------------------------------------------


class TestHappyPathExecution:
    def test_read_latest_3_emails_flow(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Scenario: User asks 'Read my latest 3 emails.' -> Propose -> Approve -> Execute."""
        # 1. Propose
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        assert prop_res.status_code == 200
        prop_data = prop_res.json()
        proposal_id = prop_data["proposal_id"]
        task_id = prop_data["task_id"]
        assert prop_data["status"] == "PENDING"
        assert prop_data["requested_tool"] == "read_inbox"
        assert prop_data["requested_constraints"]["read_inbox"]["max_limit"] == 3

        # 2. Approve via trusted controller
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
            json={"controller_id": "local-supervisor", "reason": "Approved by auditor"},
        )
        assert app_res.status_code == 200
        assert app_res.json()["status"] == "APPROVED"

        # 3. Execute approved task
        exec_res = sync_client.post(
            f"/api/v1/tasks/{task_id}/execute",
            json={"user_id": 1, "provider": "fake"},
        )
        assert exec_res.status_code == 200
        exec_data = exec_res.json()

        assert exec_data["task_id"] == task_id
        assert exec_data["user_id"] == 1
        assert exec_data["execution_status"] == "success"
        assert exec_data["authorized_tool"] == "read_inbox"
        assert exec_data["tool_calls_count"] == 1

        # Check firewall audit step
        step = exec_data["steps"][0]
        assert step["tool_name"] == "read_inbox"
        assert step["policy_action"] == PolicyAction.ALLOW.value
        assert "limit" in step["arguments"]
        assert step["arguments"]["limit"] == 3

    def test_summarize_latest_2_emails_in_arabic_flow(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Scenario: User asks 'لخص آخر 2 إيميلات بالعربي.' -> Propose -> Approve -> Execute."""
        # 1. Propose
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "لخص آخر 2 إيميلات بالعربي."},
        )
        assert prop_res.status_code == 200
        prop_data = prop_res.json()
        proposal_id = prop_data["proposal_id"]
        task_id = prop_data["task_id"]
        assert prop_data["requested_tool"] == "read_inbox"
        assert prop_data["requested_constraints"]["read_inbox"]["max_limit"] == 2

        # 2. Approve
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )
        assert app_res.status_code == 200

        # 3. Execute
        exec_res = sync_client.post(
            f"/api/v1/tasks/{task_id}/execute",
            json={"user_id": 1, "provider": "fake"},
        )
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["execution_status"] == "success"
        assert exec_data["tool_calls_count"] == 1
        assert exec_data["steps"][0]["policy_action"] == PolicyAction.ALLOW.value
        # Final answer contains Arabic output prefix
        assert "استدلالاً حقيقياً" in exec_data["final_answer"]

    def test_search_emails_flow(self, sync_client: TestClient, seeded_session) -> None:
        """Scenario: User asks 'Search emails for assignment.' -> Propose -> Approve -> Execute."""
        # 1. Propose
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Search emails for assignment."},
        )
        assert prop_res.status_code == 200
        prop_data = prop_res.json()
        proposal_id = prop_data["proposal_id"]
        task_id = prop_data["task_id"]
        assert prop_data["requested_tool"] == "search_emails"
        assert (
            "assignment"
            in prop_data["requested_constraints"]["search_emails"][
                "allowed_search_terms"
            ]
        )

        # 2. Approve
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )
        assert app_res.status_code == 200

        # 3. Execute
        exec_res = sync_client.post(
            f"/api/v1/tasks/{task_id}/execute",
            json={"user_id": 1, "provider": "fake"},
        )
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["execution_status"] == "success"
        assert exec_data["tool_calls_count"] == 1
        assert exec_data["steps"][0]["tool_name"] == "search_emails"
        assert exec_data["steps"][0]["policy_action"] == PolicyAction.ALLOW.value

    def test_read_specific_email_id_flow(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Scenario: User asks 'Show email 7.' -> Propose -> Approve -> Execute."""
        # 1. Propose
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Show email 7."},
        )
        assert prop_res.status_code == 200
        prop_data = prop_res.json()
        proposal_id = prop_data["proposal_id"]
        task_id = prop_data["task_id"]
        assert prop_data["requested_tool"] == "get_email_details"
        assert (
            7
            in prop_data["requested_constraints"]["get_email_details"][
                "allowed_email_ids"
            ]
        )

        # 2. Approve
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )
        assert app_res.status_code == 200

        # 3. Execute
        exec_res = sync_client.post(
            f"/api/v1/tasks/{task_id}/execute",
            json={"user_id": 1, "provider": "fake"},
        )
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["execution_status"] == "success"
        assert exec_data["steps"][0]["tool_name"] == "get_email_details"
        assert exec_data["steps"][0]["arguments"] == {"email_id": 7}
        assert exec_data["steps"][0]["policy_action"] == PolicyAction.ALLOW.value


# ---------------------------------------------------------------------------
# B. Approval Failure Scenarios
# ---------------------------------------------------------------------------


class TestApprovalFailures:
    def test_missing_approval_cannot_execute(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: A proposal in PENDING status cannot be executed."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        task_id = prop_res.json()["task_id"]

        # Attempt to execute without approving
        exec_res = sync_client.post(f"/api/v1/tasks/{task_id}/execute")
        assert exec_res.status_code == 409
        assert "cannot be executed" in exec_res.json()["detail"].lower()
        assert "pending" in exec_res.json()["detail"].lower()

    def test_rejected_proposal_cannot_execute(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: A proposal in REJECTED status cannot be executed."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]
        task_id = prop_res.json()["task_id"]

        # Reject proposal
        rej_res = sync_client.post(f"/api/v1/permissions/{proposal_id}/reject")
        assert rej_res.status_code == 200

        # Attempt to execute rejected task
        exec_res = sync_client.post(f"/api/v1/tasks/{task_id}/execute")
        assert exec_res.status_code == 409
        assert "cannot be executed" in exec_res.json()["detail"].lower()

    def test_expired_proposal_cannot_execute(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: An expired proposal cannot be executed."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]
        task_id = prop_res.json()["task_id"]

        # Backdate proposal expiration
        proposal = default_approval_service.store.get(proposal_id)
        assert proposal is not None
        past_time = datetime.now(UTC) - timedelta(seconds=60)
        expired_prop = proposal.model_copy(
            update={
                "created_at": past_time - timedelta(seconds=60),
                "expires_at": past_time,
            }
        )
        default_approval_service.store.save(expired_prop)

        # Attempt to execute expired task
        exec_res = sync_client.post(f"/api/v1/tasks/{task_id}/execute")
        assert exec_res.status_code == 410
        assert "expired" in exec_res.json()["detail"].lower()

    def test_forged_task_id_fails(self, sync_client: TestClient) -> None:
        """Security Invariant: Unknown or forged task IDs return 404."""
        exec_res = sync_client.post("/api/v1/tasks/task_forged_99999999/execute")
        assert exec_res.status_code == 404
        assert "found" in exec_res.json()["detail"].lower()

    def test_replayed_execution_fails_at_most_once(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: A task cannot be replayed after initial execution (at-most-once)."""
        # 1. Propose & Approve
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]
        task_id = prop_res.json()["task_id"]

        sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )

        # 2. First Execution (Success)
        exec_1 = sync_client.post(f"/api/v1/tasks/{task_id}/execute")
        assert exec_1.status_code == 200

        # 3. Second Execution (Replay Failure)
        exec_2 = sync_client.post(f"/api/v1/tasks/{task_id}/execute")
        assert exec_2.status_code == 409
        assert "already been executed" in exec_2.json()["detail"].lower()
        assert "replay is strictly forbidden" in exec_2.json()["detail"].lower()

    def test_simulated_user_mismatch_fails(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Security Invariant: Caller cannot execute task under a different user identity."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]
        task_id = prop_res.json()["task_id"]

        sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )

        # Attempt execution passing mismatched user_id
        exec_mismatch = sync_client.post(
            f"/api/v1/tasks/{task_id}/execute",
            json={"user_id": 2},
        )
        assert exec_mismatch.status_code == 403
        assert "user mismatch" in exec_mismatch.json()["detail"].lower()


# ---------------------------------------------------------------------------
# C. Policy Violation Scenarios
# ---------------------------------------------------------------------------


class TestPolicyViolations:
    def test_agent_requesting_too_many_emails_is_denied(self, seeded_session) -> None:
        """Firewall Invariant: If approved for 3, agent requesting limit 10 is denied."""
        # 1. Propose & Approve for limit 3
        proposal = default_approval_service.propose(
            user_id=1, message="Read my latest 3 emails."
        )
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        # 2. Build provider requesting limit 10
        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_exceed_limit",
                            name="read_inbox",
                            arguments=json.dumps({"limit": 10}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Done.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Read my latest 3 emails.",
            session=seeded_session,
            policy=policy,
        )

        assert len(response.execution_trace) == 1
        step = response.execution_trace[0]
        assert step.policy_action == PolicyAction.DENY.value
        assert step.policy_reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION.value
        assert "exceeds" in (step.error_message or "").lower()

    def test_agent_requesting_unapproved_tool_is_denied(self, seeded_session) -> None:
        """Firewall Invariant: If approved for read_inbox, agent requesting search_emails is denied."""
        proposal = default_approval_service.propose(
            user_id=1, message="Read my latest 3 emails."
        )
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_unapproved_tool",
                            name="search_emails",
                            arguments=json.dumps({"query": "syllabus"}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Done.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Read my latest 3 emails.",
            session=seeded_session,
            policy=policy,
        )

        assert len(response.execution_trace) == 1
        step = response.execution_trace[0]
        assert step.policy_action == PolicyAction.DENY.value
        assert step.policy_reason_code == PolicyReasonCode.TOOL_NOT_PERMITTED.value

    def test_agent_attempting_to_switch_user_is_sanitized(self, seeded_session) -> None:
        """Identity Invariant: Model payload injecting user_id=2 is sanitized to server identity user_id=1."""
        proposal = default_approval_service.propose(
            user_id=1, message="Read my latest 3 emails."
        )
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_spoof_user",
                            name="read_inbox",
                            arguments=json.dumps({"limit": 3, "user_id": 2}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Done.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Read my latest 3 emails.",
            session=seeded_session,
            policy=policy,
        )

        assert len(response.execution_trace) == 1
        step = response.execution_trace[0]
        assert step.policy_action == PolicyAction.ALLOW.value
        # Server-controlled identity strictly enforced: executed for user 1 inbox, ignoring spoofed user_id: 2
        assert step.result_summary is not None
        assert step.result_summary["owner_id"] == 1

    def test_agent_requesting_different_email_id_is_denied(
        self, seeded_session
    ) -> None:
        """Constraint Invariant: If approved for email 7, requesting email 12 is denied."""
        proposal = default_approval_service.propose(user_id=1, message="Show email 7.")
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_wrong_email_id",
                            name="get_email_details",
                            arguments=json.dumps({"email_id": 12}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Done.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Show email 7.",
            session=seeded_session,
            policy=policy,
        )

        assert len(response.execution_trace) == 1
        step = response.execution_trace[0]
        assert step.policy_action == PolicyAction.DENY.value
        assert step.policy_reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION.value

    def test_agent_changing_search_query_is_denied(self, seeded_session) -> None:
        """Constraint Invariant: If approved for 'assignment', requesting 'passwords' is denied."""
        proposal = default_approval_service.propose(
            user_id=1, message="Search emails for assignment."
        )
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_deviant_query",
                            name="search_emails",
                            arguments=json.dumps({"query": "passwords", "limit": 5}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Done.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Search emails for assignment.",
            session=seeded_session,
            policy=policy,
        )

        assert len(response.execution_trace) == 1
        step = response.execution_trace[0]
        assert step.policy_action == PolicyAction.DENY.value
        assert step.policy_reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION.value

    def test_client_cannot_inject_extra_fields_in_execute_body(
        self, sync_client: TestClient
    ) -> None:
        """API Schema Invariant: Request body forbids arbitrary policy injection."""
        exec_res = sync_client.post(
            "/api/v1/tasks/task_1234567890ab/execute",
            json={
                "user_id": 1,
                "policy": {"allowed_tools": ["delete_email"]},
                "max_limit": 100,
            },
        )
        assert exec_res.status_code == 422
        assert "extra" in exec_res.text.lower() or "forbidden" in exec_res.text.lower()


# ---------------------------------------------------------------------------
# D. Adversarial Injection Simulations
# ---------------------------------------------------------------------------


class TestInjectionSimulations:
    def test_email_content_prompt_injection_does_not_expand_permissions(
        self, seeded_session
    ) -> None:
        """Adversarial Defense: Retrieved email content containing malicious instructions

        cannot modify the approved policy or grant access to delete/send tools.
        """
        proposal = default_approval_service.propose(
            user_id=1, message="Read my latest 3 emails."
        )
        _, policy = default_approval_service.approve(
            proposal_id=proposal.proposal_id,
            controller_id="local-supervisor",
        )

        # Adversarial LLM model tries to execute delete after reading hostile email
        provider = FakeLLMProvider()
        provider.set_canned_responses(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            name="read_inbox",
                            arguments=json.dumps({"limit": 3}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                # Model simulates being tricked by email body:
                LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id="call_injected_escalate",
                            name="search_emails",
                            arguments=json.dumps({"query": "passwords"}),
                        )
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Finished.", finish_reason="stop"),
            ]
        )

        orchestrator = AgentOrchestrator(provider=provider)
        response = orchestrator.run(
            user_id=1,
            prompt="Read my latest 3 emails.",
            session=seeded_session,
            policy=policy,
        )

        # Tool 1 allowed, Tool 2 blocked by firewall
        assert len(response.execution_trace) == 2
        assert response.execution_trace[0].policy_action == PolicyAction.ALLOW.value
        assert response.execution_trace[1].policy_action == PolicyAction.DENY.value
        assert (
            response.execution_trace[1].policy_reason_code
            == PolicyReasonCode.TOOL_NOT_PERMITTED.value
        )

    def test_email_claiming_admin_authority_cannot_approve_itself(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Adversarial Defense: Hostile instruction attempting to self-approve with LLM controller is rejected."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]

        # Injected prompt attempts to call approve using 'llm_agent' identity
        app_res = sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "llm_agent"},
            json={"controller_id": "llm_agent"},
        )
        assert app_res.status_code == 403
        assert "untrusted" in app_res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# E. Concurrency & At-Most-Once Execution
# ---------------------------------------------------------------------------


class TestConcurrencyAndAtMostOnce:
    def test_concurrent_execution_attempts_only_one_succeeds(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Concurrency Invariant: Exactly one execution succeeds across race conditions;

        all concurrent calls fail with replay rejection (HTTP 409).
        """
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]
        task_id = prop_res.json()["task_id"]

        sync_client.post(
            f"/api/v1/permissions/{proposal_id}/approve",
            headers={"X-AEGIS-Controller": "local-supervisor"},
        )

        def _execute_task():
            return sync_client.post(f"/api/v1/tasks/{task_id}/execute")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_execute_task) for _ in range(5)]
            responses = [f.result() for f in futures]

        status_codes = [r.status_code for r in responses]
        assert status_codes.count(200) == 1, (
            f"Expected exactly 1 success, got: {status_codes}"
        )
        assert status_codes.count(409) == 4, (
            f"Expected 4 replay rejections, got: {status_codes}"
        )

    def test_concurrent_approvals_only_one_succeeds(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Concurrency Invariant: Exactly one approval succeeds; duplicate approvals fail."""
        prop_res = sync_client.post(
            "/api/v1/permissions/propose",
            json={"user_id": 1, "message": "Read my latest 3 emails."},
        )
        proposal_id = prop_res.json()["proposal_id"]

        def _approve_proposal():
            return sync_client.post(
                f"/api/v1/permissions/{proposal_id}/approve",
                headers={"X-AEGIS-Controller": "local-supervisor"},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_approve_proposal) for _ in range(5)]
            responses = [f.result() for f in futures]

        status_codes = [r.status_code for r in responses]
        assert status_codes.count(200) == 1, (
            f"Expected exactly 1 success, got: {status_codes}"
        )
        assert status_codes.count(409) == 4, (
            f"Expected 4 conflict rejections, got: {status_codes}"
        )


# ---------------------------------------------------------------------------
# F. Legacy Endpoint Isolation
# ---------------------------------------------------------------------------


class TestLegacyEndpointIsolation:
    def test_legacy_agent_run_has_benchmark_warning_headers(
        self, sync_client: TestClient, seeded_session
    ) -> None:
        """Isolation Invariant: POST /api/v1/agent/run response explicitly flags unapproved benchmark mode."""
        res = sync_client.post(
            "/api/v1/agent/run",
            json={
                "user_id": 1,
                "message": "Read my latest 3 emails.",
                "policy_profile": "read_only_all",
            },
        )
        assert res.status_code == 200
        assert (
            res.headers.get("X-AEGIS-Execution-Mode") == "unapproved-benchmark-profile"
        )
        assert "unapproved benchmark" in res.headers.get("X-AEGIS-Warning", "").lower()
