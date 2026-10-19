"""Business logic and domain services layer for AEGIS-CORE.

Coordinates policy evaluation, permission verification, provenance auditing,
health inspection, user accounts, and email operations.
"""

from app.services.email import EmailService
from app.services.health import (
    evaluate_system_health,
    get_uptime_seconds,
    set_start_time,
)
from app.services.user import UserService

__all__ = [
    "EmailService",
    "UserService",
    "evaluate_system_health",
    "get_uptime_seconds",
    "set_start_time",
]
