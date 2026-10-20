"""Domain exceptions for AEGIS-CORE intent extraction and parsing.

Provides a structured exception hierarchy for deterministic natural-language
intent parsing, parameter boundary checks, and security rejection gates.
"""


class IntentError(Exception):
    """Base exception for all AEGIS-CORE intent parsing and validation errors."""


class IntentParsingError(IntentError):
    """Raised when an intent cannot be parsed or input is structurally invalid."""


class EmptyRequestError(IntentParsingError):
    """Raised when the user request is empty or pure whitespace."""


class UnsupportedIntentError(IntentParsingError):
    """Raised when the user requests an unsupported or forbidden action (e.g. send, delete, export)."""

    def __init__(self, action: str, message: str) -> None:
        super().__init__(message)
        self.action = action


class InvalidCountError(IntentParsingError):
    """Raised when the requested item count is non-positive or exceeds maximum allowed bounds."""

    def __init__(self, count: int, max_allowed: int, message: str) -> None:
        super().__init__(message)
        self.count = count
        self.max_allowed = max_allowed


class AmbiguousIntentError(IntentParsingError):
    """Raised when a request is ambiguous, conflicting, or requires explicit user clarification."""

    def __init__(
        self,
        message: str,
        clarification_prompt: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.clarification_prompt = clarification_prompt
        self.reason = reason


class ProposalSecurityError(IntentError):
    """Raised when proposal generation or validation violates security boundaries."""


class ProposalNotFoundError(IntentError):
    """Raised when a referenced proposal ID does not exist in the store."""


class ProposalStateError(IntentError):
    """Raised when an operation is invalid for the proposal's current lifecycle state."""


class ProposalExpiredError(ProposalStateError):
    """Raised when an operation is attempted on an expired proposal."""


class ProposalReplayError(ProposalStateError):
    """Raised when attempting to reuse or replay an already consumed proposal."""


class InvalidProposalTransitionError(ProposalStateError):
    """Raised when an invalid state transition is attempted on a proposal."""


class UntrustedControllerError(IntentError):
    """Raised when an unauthenticated or untrusted entity attempts an approval action."""
