"""Permission approval service, store, and lifecycle management for AEGIS-CORE.

==============================================================================
CRITICAL SECURITY MODEL & LOCAL SIMULATION NOTICE:
------------------------------------------------------------------------------
1. A proposal is NOT an approved policy. It cannot directly authorize execution.
2. Only an explicit approval action by a trusted local demonstration controller
   can transition a proposal from PENDING to APPROVED.
3. Untrusted entities (such as LLMs, model agents, or unauthenticated clients)
   cannot approve proposals, substitute TaskPolicy objects, or widen limits.
4. An approved proposal is sealed into an immutable TaskPolicy strictly bound
   to the exact task ID, simulated user ID, and approved constraints.
5. Replay Defense: Consumed proposals cannot be reused to spawn new tasks.
6. Expiration: Expired proposals cannot be approved or consumed.
7. Concurrency Safety: All state transitions are guarded by atomic locking.
==============================================================================
"""

import threading
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from app.intent.exceptions import (
    EmptyRequestError,
    InvalidProposalTransitionError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalReplayError,
    ProposalSecurityError,
    ProposalStateError,
    UntrustedControllerError,
)
from app.intent.mappings import map_intent_to_proposal
from app.intent.parser import parse_intent
from app.intent.proposals import PermissionProposal, ProposalStatus
from app.security.schemas import TaskPolicy

# Valid proposal lifecycle state transitions
VALID_TRANSITIONS: dict[ProposalStatus, frozenset[ProposalStatus]] = {
    ProposalStatus.PENDING: frozenset(
        {ProposalStatus.APPROVED, ProposalStatus.REJECTED, ProposalStatus.EXPIRED}
    ),
    ProposalStatus.APPROVED: frozenset(
        {ProposalStatus.CONSUMED, ProposalStatus.EXPIRED}
    ),
    ProposalStatus.REJECTED: frozenset(),  # Terminal
    ProposalStatus.EXPIRED: frozenset(),  # Terminal
    ProposalStatus.CONSUMED: frozenset(),  # Terminal (Replay Prevention)
}

# Denied controller identifiers representing automated/untrusted entities
DISALLOWED_CONTROLLER_IDENTIFIERS: frozenset[str] = frozenset(
    {
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
    }
)


class ApprovalReceipt(BaseModel):
    """Auditable, immutable receipt issued upon explicit proposal approval."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str = Field(..., description="Approved proposal identifier")
    task_id: str = Field(..., description="Target task correlation identifier")
    user_id: int = Field(..., ge=1, description="Simulated user account identifier")
    status: ProposalStatus = Field(
        default=ProposalStatus.APPROVED,
        description="Updated lifecycle status (APPROVED)",
    )
    authorized_tool: str = Field(..., description="The single authorized tool name")
    approved_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of trusted approval",
    )
    approved_by: str = Field(
        ...,
        min_length=1,
        description="Identifier of trusted demonstration controller",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the approved authorization expires",
    )
    message: str = Field(
        default="Proposal successfully approved by trusted local controller.",
        description="Status message",
    )


class ProposalStore:
    """Thread-safe in-memory repository for PermissionProposals and active TaskPolicies."""

    def __init__(self) -> None:
        self._proposals: dict[str, PermissionProposal] = {}
        self._policies: dict[str, TaskPolicy] = {}
        self._receipts: dict[str, ApprovalReceipt] = {}
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        """Expose lock for multi-step atomic operations."""
        return self._lock

    def save(self, proposal: PermissionProposal) -> None:
        """Store or update a PermissionProposal."""
        with self._lock:
            self._proposals[proposal.proposal_id] = proposal

    def get(self, proposal_id: str) -> PermissionProposal | None:
        """Retrieve a PermissionProposal by its unforgeable ID."""
        with self._lock:
            return self._proposals.get(proposal_id)

    def save_policy(
        self,
        proposal_id: str,
        policy: TaskPolicy,
        receipt: ApprovalReceipt,
    ) -> None:
        """Store an approved TaskPolicy and its ApprovalReceipt."""
        with self._lock:
            self._policies[proposal_id] = policy
            self._receipts[proposal_id] = receipt

    def get_policy(self, proposal_id: str) -> TaskPolicy | None:
        """Retrieve the TaskPolicy generated for an approved proposal."""
        with self._lock:
            return self._policies.get(proposal_id)

    def get_receipt(self, proposal_id: str) -> ApprovalReceipt | None:
        """Retrieve the ApprovalReceipt issued for a proposal."""
        with self._lock:
            return self._receipts.get(proposal_id)

    def get_by_task_id(self, task_id: str) -> PermissionProposal | None:
        """Find the PermissionProposal bound to a task_id."""
        with self._lock:
            for proposal in self._proposals.values():
                if proposal.task_id == task_id:
                    return proposal
            return None

    def clear(self) -> None:
        """Clear all stored proposals and policies (for testing isolation)."""
        with self._lock:
            self._proposals.clear()
            self._policies.clear()
            self._receipts.clear()


class PermissionApprovalService:
    """Encapsulates the controlled proposal lifecycle, explicit approval, and policy generation."""

    def __init__(self, store: ProposalStore | None = None) -> None:
        self.store = store or ProposalStore()

    def _validate_transition(
        self, current_status: ProposalStatus, target_status: ProposalStatus
    ) -> None:
        """Ensure state transitions strictly adhere to valid lifecycle progression."""
        allowed = VALID_TRANSITIONS.get(current_status, frozenset())
        if target_status not in allowed:
            if current_status == ProposalStatus.CONSUMED:
                raise ProposalReplayError(
                    "Proposal has already been consumed (replay prevention). Cannot reuse."
                )
            if current_status == ProposalStatus.EXPIRED:
                raise ProposalExpiredError(
                    "Proposal has expired and cannot undergo further state transitions."
                )
            raise InvalidProposalTransitionError(
                f"Invalid proposal state transition: '{current_status}' -> '{target_status}'. "
                f"Allowed target states: {sorted(allowed)}"
            )

    def propose(
        self,
        user_id: int,
        message: str,
        task_id: str | None = None,
        ttl_seconds: int = 300,
    ) -> PermissionProposal:
        """Parse natural language request and generate a stored PermissionProposal.

        Guarantees:
        - Does NOT execute any tools.
        - Does NOT activate or install any TaskPolicy.
        - Stores the proposal in strictly PENDING status.
        """
        if user_id < 1:
            raise ValueError(f"user_id must be a positive integer, got: {user_id}")

        if not message or not message.strip():
            raise EmptyRequestError("User message cannot be empty or whitespace only.")

        # 1. Parse intent deterministically
        intent = parse_intent(message)

        if intent.is_ambiguous or intent.requires_clarification:
            raise ProposalSecurityError(
                "Cannot generate a permission proposal for an ambiguous or unclarified request. "
                f"Clarification required: {intent.clarification_prompt}"
            )

        # 2. Map intent to minimal permission proposal
        proposal = map_intent_to_proposal(
            intent=intent,
            user_id=user_id,
            task_id=task_id,
            ttl_seconds=ttl_seconds,
        )

        # 3. Store proposal server-side
        self.store.save(proposal)
        return proposal

    def get_proposal(self, proposal_id: str) -> PermissionProposal:
        """Fetch proposal and automatically transition to EXPIRED if lifetime elapsed."""
        with self.store.lock:
            proposal = self.store.get(proposal_id)
            if proposal is None:
                raise ProposalNotFoundError(
                    f"Permission proposal '{proposal_id}' not found."
                )

            # Lazy expiration transition
            if proposal.is_expired() and proposal.status in (
                ProposalStatus.PENDING,
                ProposalStatus.APPROVED,
            ):
                updated = proposal.model_copy(update={"status": ProposalStatus.EXPIRED})
                self.store.save(updated)
                return updated

            return proposal

    def approve(
        self,
        proposal_id: str,
        controller_id: str,
        reason: str = "Explicit supervisor review",
        expected_scope: str | None = None,
        session_user_id: int | None = None,
        task_id: str | None = None,
    ) -> tuple[ApprovalReceipt, TaskPolicy]:
        """Explicitly approve a pending proposal and seal it into an immutable TaskPolicy.

        Args:
            proposal_id: Unique proposal identifier.
            controller_id: Identifier of trusted local demonstration controller.
            reason: Auditable review rationale.
            expected_scope: Optional tool name check to prevent race conditions.
            session_user_id: Optional user ID for tenant isolation verification.
            task_id: Optional correlation task ID check.

        Returns:
            Tuple of (ApprovalReceipt, immutable TaskPolicy).

        Raises:
            UntrustedControllerError: If controller is unauthenticated or untrusted.
            ProposalNotFoundError: If proposal does not exist.
            ProposalExpiredError: If proposal is expired.
            ProposalStateError / ProposalReplayError: If status is not PENDING.
            ProposalSecurityError: If user or task mismatch is detected.
        """
        # Invariant: Disallow model-generated or untrusted controller identifiers
        clean_controller = controller_id.strip() if controller_id else ""
        if (
            not clean_controller
            or clean_controller.lower() in DISALLOWED_CONTROLLER_IDENTIFIERS
        ):
            raise UntrustedControllerError(
                f"Controller identifier '{controller_id}' is untrusted. "
                "Automated or model-generated approvals are strictly forbidden."
            )

        with self.store.lock:
            proposal = self.get_proposal(proposal_id)

            # Check expiration
            if proposal.is_expired():
                raise ProposalExpiredError(
                    f"Proposal '{proposal_id}' has expired and cannot be approved."
                )

            # Validate lifecycle transition (PENDING -> APPROVED)
            self._validate_transition(proposal.status, ProposalStatus.APPROVED)

            # Tenant Isolation Invariant
            if session_user_id is not None and session_user_id != proposal.user_id:
                raise ProposalSecurityError(
                    f"Tenant mismatch: proposal belongs to user_id={proposal.user_id}, "
                    f"but approval was requested for user_id={session_user_id}."
                )

            # Task Correlation Invariant
            if task_id is not None and task_id != proposal.task_id:
                raise ProposalSecurityError(
                    f"Task correlation mismatch: proposal belongs to task_id='{proposal.task_id}', "
                    f"but approval was requested for task_id='{task_id}'."
                )

            # Scope Invariant
            if expected_scope is not None and expected_scope != proposal.requested_tool:
                raise ProposalSecurityError(
                    f"Scope mismatch: proposal authorizes '{proposal.requested_tool}', "
                    f"but approval specified '{expected_scope}'."
                )

            # 1. Update proposal status to APPROVED
            approved_proposal = proposal.model_copy(
                update={"status": ProposalStatus.APPROVED}
            )
            self.store.save(approved_proposal)

            # 2. Construct trusted, immutable TaskPolicy
            # Preserves exact approved constraints without widening
            now = datetime.now(UTC)
            policy = TaskPolicy(
                task_id=approved_proposal.task_id,
                bound_user_id=approved_proposal.user_id,
                allowed_tools=frozenset({approved_proposal.requested_tool}),
                constraints=dict(approved_proposal.requested_constraints),
                policy_version=approved_proposal.proposal_version,
                issued_at=now,
                expires_at=approved_proposal.expires_at,
            )

            # 3. Issue auditable receipt
            receipt = ApprovalReceipt(
                proposal_id=approved_proposal.proposal_id,
                task_id=approved_proposal.task_id,
                user_id=approved_proposal.user_id,
                status=ProposalStatus.APPROVED,
                authorized_tool=approved_proposal.requested_tool,
                approved_at=now,
                approved_by=clean_controller,
                expires_at=approved_proposal.expires_at,
                message=f"Proposal approved by '{clean_controller}': {reason}",
            )

            self.store.save_policy(proposal_id, policy, receipt)
            return receipt, policy

    def reject(
        self,
        proposal_id: str,
        controller_id: str = "local-supervisor",
        reason: str = "Rejected by supervisor",
    ) -> PermissionProposal:
        """Explicitly reject a pending proposal."""
        with self.store.lock:
            proposal = self.get_proposal(proposal_id)

            # Validate lifecycle transition (PENDING -> REJECTED)
            self._validate_transition(proposal.status, ProposalStatus.REJECTED)

            rejected_proposal = proposal.model_copy(
                update={"status": ProposalStatus.REJECTED}
            )
            self.store.save(rejected_proposal)
            return rejected_proposal

    def consume(
        self,
        proposal_id: str,
        user_id: int,
        task_id: str,
    ) -> TaskPolicy:
        """Consume an approved proposal to activate its TaskPolicy for execution.

        Enforces Replay Prevention: Once CONSUMED, a proposal cannot be reused.
        """
        with self.store.lock:
            proposal = self.get_proposal(proposal_id)

            if proposal.status == ProposalStatus.CONSUMED:
                raise ProposalReplayError(
                    f"Proposal '{proposal_id}' has already been consumed (replay prevention)."
                )

            if proposal.status == ProposalStatus.EXPIRED or proposal.is_expired():
                raise ProposalExpiredError(
                    f"Proposal '{proposal_id}' has expired and cannot be executed."
                )

            if proposal.status != ProposalStatus.APPROVED:
                raise ProposalStateError(
                    f"Cannot consume proposal in state '{proposal.status}'. Must be APPROVED."
                )

            if user_id != proposal.user_id:
                raise ProposalSecurityError(
                    f"User mismatch on consumption: proposal belongs to user {proposal.user_id}, got {user_id}."
                )

            if task_id != proposal.task_id:
                raise ProposalSecurityError(
                    f"Task mismatch on consumption: proposal belongs to task '{proposal.task_id}', got '{task_id}'."
                )

            policy = self.store.get_policy(proposal_id)
            if policy is None:
                raise ProposalSecurityError(
                    f"Approved policy missing for proposal '{proposal_id}'."
                )

            # Mark proposal as CONSUMED to prevent replay
            consumed_proposal = proposal.model_copy(
                update={"status": ProposalStatus.CONSUMED}
            )
            self.store.save(consumed_proposal)

            return policy

    def get_proposal_by_task_id(self, task_id: str) -> PermissionProposal:
        """Fetch proposal for a given task_id, handling lazy expiration."""
        with self.store.lock:
            proposal = self.store.get_by_task_id(task_id)
            if proposal is None:
                raise ProposalNotFoundError(
                    f"No permission proposal found for task '{task_id}'."
                )

            # Lazy expiration transition
            if proposal.is_expired() and proposal.status in (
                ProposalStatus.PENDING,
                ProposalStatus.APPROVED,
            ):
                updated = proposal.model_copy(update={"status": ProposalStatus.EXPIRED})
                self.store.save(updated)
                return updated

            return proposal

    def consume_by_task_id(
        self,
        task_id: str,
        expected_user_id: int | None = None,
    ) -> tuple[PermissionProposal, TaskPolicy]:
        """Consume an approved proposal by task_id, asserting state and identity invariants.

        Enforces Replay Prevention: Once CONSUMED, a proposal cannot be reused.
        """
        with self.store.lock:
            proposal = self.get_proposal_by_task_id(task_id)
            user_id = (
                expected_user_id if expected_user_id is not None else proposal.user_id
            )
            policy = self.consume(
                proposal_id=proposal.proposal_id,
                user_id=user_id,
                task_id=task_id,
            )
            return proposal, policy


# Global default approval service singleton
default_approval_service = PermissionApprovalService()
