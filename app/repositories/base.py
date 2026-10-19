"""Generic base repository for AEGIS-CORE database operations.

Implements the repository pattern to decouple persistence logic from business services.
"""

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import Base


class BaseRepository[ModelType: Base]:
    """Base repository providing standard CRUD operations using modern SQLAlchemy 2.x."""

    def __init__(self, model: type[ModelType], session: Session) -> None:
        self.model = model
        self.session = session

    def get_by_id(self, id_: int | str) -> ModelType | None:
        """Fetch a single record by primary key."""
        return self.session.get(self.model, id_)

    def list_all(self, skip: int = 0, limit: int = 100) -> Sequence[ModelType]:
        """Fetch paginated records."""
        statement = select(self.model).offset(skip).limit(limit)
        return self.session.scalars(statement).all()

    def create(self, instance: ModelType) -> ModelType:
        """Add and flush a new record to the session."""
        self.session.add(instance)
        self.session.flush()
        return instance

    def delete(self, instance: ModelType) -> None:
        """Remove a record from the session."""
        self.session.delete(instance)
        self.session.flush()
