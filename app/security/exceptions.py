"""Security policy domain exceptions for AEGIS-CORE.

Provides a structured exception hierarchy for security policy validation,
evaluation, and enforcement failures within the execution firewall.
"""


class SecurityPolicyError(Exception):
    """Base exception for all AEGIS-CORE security policy errors."""


class PolicyValidationError(SecurityPolicyError):
    """Raised when a security policy definition is structurally invalid or violates invariants."""


class PolicyEvaluationError(SecurityPolicyError):
    """Raised when an unrecoverable internal failure occurs during policy evaluation."""


class PolicyDenialError(SecurityPolicyError):
    """Raised when an agent tool execution request is explicitly denied by security policy."""

    def __init__(self, reason_code: str, explanation: str) -> None:
        super().__init__(f"[{reason_code}] {explanation}")
        self.reason_code = reason_code
        self.explanation = explanation
