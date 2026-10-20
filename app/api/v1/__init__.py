"""V1 API Router assembly."""

from fastapi import APIRouter

from app.api.v1.routes.agent import router as agent_router
from app.api.v1.routes.health import router as health_router
from app.api.v1.routes.permissions import router as permissions_router
from app.api.v1.routes.tasks import router as tasks_router
from app.api.v1.routes.users import router as users_router

v1_router = APIRouter()
v1_router.include_router(health_router, tags=["Health"])
v1_router.include_router(users_router)
v1_router.include_router(agent_router)
v1_router.include_router(permissions_router)
v1_router.include_router(tasks_router)

__all__ = ["v1_router"]
