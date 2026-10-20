"""AEGIS-CORE Security Package.

Provides deterministic security contracts, task policies, argument constraints,
trusted runtime contexts, predefined policy profiles, and the core policy evaluation engine.
"""

from app.security.context import TaskContext
from app.security.exceptions import (
    PolicyDenialError,
    PolicyEvaluationError,
    PolicyValidationError,
    SecurityPolicyError,
)
from app.security.policy_engine import PolicyEngine
from app.security.profiles import (
    PREDEFINED_PROFILES,
    SUPPORTED_PROFILE_NAMES,
    create_task_context,
    create_task_policy,
)
from app.security.schemas import (
    FORBIDDEN_WILDCARDS,
    KNOWN_SYSTEM_TOOLS,
    STRICT_TOOL_ARG_MODELS,
    BaseToolConstraint,
    GenericToolConstraint,
    GetEmailDetailsConstraint,
    PolicyAction,
    PolicyDecision,
    PolicyReasonCode,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    StrictGetEmailDetailsArgs,
    StrictReadInboxArgs,
    StrictSearchEmailsArgs,
    TaskPolicy,
    ToolConstraint,
    ToolExecutionRequest,
    normalize_tool_arguments,
)

__all__ = [
    "FORBIDDEN_WILDCARDS",
    "KNOWN_SYSTEM_TOOLS",
    "PREDEFINED_PROFILES",
    "STRICT_TOOL_ARG_MODELS",
    "SUPPORTED_PROFILE_NAMES",
    "BaseToolConstraint",
    "GenericToolConstraint",
    "GetEmailDetailsConstraint",
    "PolicyAction",
    "PolicyDecision",
    "PolicyDenialError",
    "PolicyEngine",
    "PolicyEvaluationError",
    "PolicyReasonCode",
    "PolicyValidationError",
    "ReadInboxConstraint",
    "SearchEmailsConstraint",
    "SecurityPolicyError",
    "StrictGetEmailDetailsArgs",
    "StrictReadInboxArgs",
    "StrictSearchEmailsArgs",
    "TaskContext",
    "TaskPolicy",
    "ToolConstraint",
    "ToolExecutionRequest",
    "create_task_context",
    "create_task_policy",
    "normalize_tool_arguments",
]
