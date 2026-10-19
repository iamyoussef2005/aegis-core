"""Route handlers for v1 of AEGIS-CORE API."""

from app.api.v1.routes.health import router as health_router

__all__ = ["health_router"]
