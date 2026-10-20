"""Domain exceptions for the AEGIS-CORE Mini AI Agent Runtime."""


class AgentRuntimeError(Exception):
    """Base exception for all agent runtime failures."""


class UserNotFoundError(AgentRuntimeError):
    """Raised when the specified simulated user does not exist."""


class InvalidPromptError(AgentRuntimeError):
    """Raised when the agent request message or prompt is empty or invalid."""


class UnknownToolError(AgentRuntimeError):
    """Raised when an requested tool is not in the strict allowlist."""


class InvalidToolArgumentsError(AgentRuntimeError):
    """Raised when tool arguments fail JSON decoding or Pydantic validation."""


class ToolExecutionError(AgentRuntimeError):
    """Raised when tool execution produces an unexpected failure."""


class MaxToolCallsExceededError(AgentRuntimeError):
    """Raised when the agent reaches or exceeds the configured tool call ceiling."""


class ProviderExecutionError(AgentRuntimeError):
    """Raised when the upstream LLM provider encounters a network, timeout, or API failure."""


class InvalidProviderError(AgentRuntimeError):
    """Raised when an unsupported or unconfigured provider identifier is requested."""
