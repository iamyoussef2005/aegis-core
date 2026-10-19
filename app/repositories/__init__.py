"""Data repositories package for AEGIS-CORE.

Provides abstraction over storage operations, isolating domain logic from
database access patterns.
"""

from app.repositories.base import BaseRepository

__all__ = ["BaseRepository"]
