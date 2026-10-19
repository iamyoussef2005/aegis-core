"""Route handlers for v1 of AEGIS-CORE API."""

from app.api.v1.routes.health import router as health_router
from app.api.v1.routes.users import router as users_router

__all__ = ["health_router", "users_router"]
