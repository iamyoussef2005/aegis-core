"""Development server runner script for AEGIS-CORE."""

import uvicorn

from app.core.config import get_settings


def main() -> None:
    """Launch development server using Uvicorn with auto-reload enabled."""
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
