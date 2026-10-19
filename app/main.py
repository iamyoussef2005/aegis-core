"""AEGIS-CORE FastAPI Application Factory.

Initializes the FastAPI application, lifespan management, middleware stack,
and v1 API routers for the AI agent security firewall.
"""

import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import v1_router
from app.core.config import Settings, get_settings
from app.core.logging import get_logger, setup_logging
from app.db.session import close_db, init_db
from app.services.health import set_start_time

logger = get_logger("aegis.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle events."""
    settings = app.state.settings
    setup_logging(settings)
    set_start_time(time.time())

    logger.info(
        "Starting %s v%s in %s mode...",
        settings.PROJECT_NAME,
        settings.VERSION,
        settings.ENVIRONMENT,
    )

    # Initialize database schemas
    init_db()

    logger.info("AEGIS-CORE security firewall initialized and ready for requests.")
    yield

    logger.info("Initiating graceful shutdown of AEGIS-CORE...")
    close_db()
    logger.info("AEGIS-CORE shutdown complete.")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory for configuring and instantiating the FastAPI application."""
    if settings is None:
        settings = get_settings()

    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=settings.DESCRIPTION,
        debug=settings.DEBUG,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Store settings in application state for dependency access
    application.state.settings = settings

    # Configure CORS Middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers and Request Provenance Middleware
    # Architectural hook for upcoming agent tool-call interception & audit tracking
    @application.middleware("http")
    async def security_provenance_middleware(request: Request, call_next) -> Response:
        # Assign a unique correlation ID for tracking provenance across agent interactions
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        start_timer = time.perf_counter()
        response = await call_next(request)
        process_time_ms = round((time.perf_counter() - start_timer) * 1000, 2)

        # Attach security & provenance headers
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Response-Time-MS"] = str(process_time_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        return response

    # Global Exception Handler
    @application.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        logger.error(
            "Unhandled exception processing request path=%s correlation_id=%s: %s",
            request.url.path,
            correlation_id,
            exc,
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred while processing the request.",
                "correlation_id": correlation_id,
            },
        )

    # Root informational route
    @application.get(
        "/",
        summary="Service Root",
        tags=["System"],
        include_in_schema=False,
    )
    async def root_info() -> dict[str, str]:
        return {
            "project": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "docs": "/docs" if not settings.is_production else "disabled",
            "health": f"{settings.API_V1_PREFIX}/health",
        }

    # Mount API v1 router
    application.include_router(v1_router, prefix=settings.API_V1_PREFIX)

    return application


# Global application entry point
app = create_app()
