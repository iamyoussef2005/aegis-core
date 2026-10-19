"""V1 API Router assembly."""

from fastapi import APIRouter

from app.api.v1.routes.health import router as health_router

v1_router = APIRouter()
v1_router.include_router(health_router, tags=["Health"])

__all__ = ["v1_router"]
