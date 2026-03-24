"""Baseline PostgreSQL schema (tables + pg_trgm + folder partial indexes).

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-03-24

For existing databases created with SQLAlchemy ``create_all`` + ``ensure_*`` helpers,
stamp this revision instead of upgrading::

    alembic stamp a1b2c3d4e5f6
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

from app.database import Base
from app import models  # noqa: F401 — register models with metadata

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    # Folder tree: partial unique indexes (not expressible as single SQLAlchemy UniqueConstraint).
    op.execute(text("ALTER TABLE folders DROP CONSTRAINT IF EXISTS uq_folders_owner_name"))
    op.execute(text("DROP INDEX IF EXISTS uq_folders_owner_name"))
    op.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_folder_owner_root_name "
            "ON folders (owner_id, name) WHERE parent_id IS NULL"
        )
    )
    op.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_folder_owner_parent_name "
            "ON folders (owner_id, parent_id, name) WHERE parent_id IS NOT NULL"
        )
    )
    op.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_documents_filename_trgm "
            "ON documents USING gin (filename gin_trgm_ops)"
        )
    )


def downgrade() -> None:
    op.execute(text("DROP INDEX IF EXISTS ix_documents_filename_trgm"))
    op.execute(text("DROP INDEX IF EXISTS uq_folder_owner_parent_name"))
    op.execute(text("DROP INDEX IF EXISTS uq_folder_owner_root_name"))
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
    # Extension may be required by other DBs; leave pg_trgm installed.
