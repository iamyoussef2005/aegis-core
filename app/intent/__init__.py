"""AEGIS-CORE Structured Task Intent and Deterministic Parser Package.

Provides deterministic, rule-based natural language intent parsing
for English and Arabic user requests, enforcing least privilege and fail-closed
ambiguity rejection before dynamic policy proposals.
"""

from app.intent.approval import (
    DISALLOWED_CONTROLLER_IDENTIFIERS,
    VALID_TRANSITIONS,
    ApprovalReceipt,
    PermissionApprovalService,
    ProposalStore,
    default_approval_service,
)
from app.intent.exceptions import (
    AmbiguousIntentError,
    EmptyRequestError,
    IntentError,
    IntentParsingError,
    InvalidCountError,
    InvalidProposalTransitionError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalReplayError,
    ProposalStateError,
    UnsupportedIntentError,
    UntrustedControllerError,
)
from app.intent.mappings import (
    DEFAULT_PROPOSAL_TTL_SECONDS,
    DEFAULT_SEARCH_PROPOSAL_LIMIT,
    map_intent_to_proposal,
)
from app.intent.parser import (
    DeterministicIntentParser,
    default_intent_parser,
    parse_intent,
)
from app.intent.proposals import (
    PermissionProposal,
    ProposalSecurityError,
    ProposalStatus,
)
from app.intent.schemas import (
    ActionType,
    IntentType,
    ResourceType,
    TaskIntent,
)

__all__ = [
    "DEFAULT_PROPOSAL_TTL_SECONDS",
    "DEFAULT_SEARCH_PROPOSAL_LIMIT",
    "DISALLOWED_CONTROLLER_IDENTIFIERS",
    "VALID_TRANSITIONS",
    "ActionType",
    "AmbiguousIntentError",
    "ApprovalReceipt",
    "DeterministicIntentParser",
    "EmptyRequestError",
    "IntentError",
    "IntentParsingError",
    "IntentType",
    "InvalidCountError",
    "InvalidProposalTransitionError",
    "PermissionApprovalService",
    "PermissionProposal",
    "ProposalExpiredError",
    "ProposalNotFoundError",
    "ProposalReplayError",
    "ProposalSecurityError",
    "ProposalStateError",
    "ProposalStatus",
    "ProposalStore",
    "ResourceType",
    "TaskIntent",
    "UnsupportedIntentError",
    "UntrustedControllerError",
    "default_approval_service",
    "default_intent_parser",
    "map_intent_to_proposal",
    "parse_intent",
]
