"""Business logic and domain services layer for AEGIS-CORE.

Coordinates policy evaluation, permission verification, provenance auditing,
and health inspection.
"""

from app.services.health import (
    evaluate_system_health,
    get_uptime_seconds,
    set_start_time,
)

__all__ = ["evaluate_system_health", "get_uptime_seconds", "set_start_time"]
