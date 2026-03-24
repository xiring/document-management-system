import logging
from collections.abc import Generator

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(settings.database_url, pool_pre_ping=True)


def ensure_users_role_column() -> None:
    """For databases created before `users.role` existed (PostgreSQL)."""
    if not settings.database_url.startswith("postgresql"):
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'user'"
            )
        )


def ensure_folder_tree_schema() -> None:
    """Add folders.parent_id; replace flat unique with partial unique indexes (PostgreSQL)."""
    if not settings.database_url.startswith("postgresql"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE folders ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES folders(id)"))
            conn.execute(text("ALTER TABLE folders DROP CONSTRAINT IF EXISTS uq_folders_owner_name"))
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_folder_owner_root_name "
                    "ON folders (owner_id, name) WHERE parent_id IS NULL"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_folder_owner_parent_name "
                    "ON folders (owner_id, parent_id, name) WHERE parent_id IS NOT NULL"
                )
            )
    except Exception as e:
        logger.warning(
            "Folder tree schema (parent_id / unique indexes) could not be applied. Error: %s",
            e,
        )


def ensure_document_retention_columns() -> None:
    """Soft delete, legal hold, retention expiry columns on documents (PostgreSQL)."""
    if not settings.database_url.startswith("postgresql"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL"))
            conn.execute(
                text(
                    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT false"
                )
            )
            conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS retention_expires_at TIMESTAMPTZ NULL"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_documents_deleted_at ON documents (deleted_at)"))
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_documents_retention_expires ON documents (retention_expires_at)")
            )
    except Exception as e:
        logger.warning("Document retention columns could not be applied. Error: %s", e)


def ensure_organization_columns() -> None:
    """Add folder_id to documents if missing (PostgreSQL; folders table must exist)."""
    if not settings.database_url.startswith("postgresql"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS folder_id INTEGER "
                    "REFERENCES folders(id)"
                )
            )
    except Exception as e:
        logger.warning(
            "Could not add documents.folder_id (ensure folders table exists via migrations). Error: %s",
            e,
        )


def ensure_document_chain_columns() -> None:
    """FK columns on documents for per-tenant chain config and Merkle batch (PostgreSQL)."""
    if not settings.database_url.startswith("postgresql"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS chain_config_id INTEGER "
                    "REFERENCES chain_configs(id)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS merkle_batch_id INTEGER "
                    "REFERENCES merkle_batches(id)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS pending_merkle BOOLEAN NOT NULL DEFAULT false"
                )
            )
    except Exception as e:
        logger.warning(
            "Document chain / Merkle columns could not be applied (run migrations or create tables). Error: %s",
            e,
        )


def ensure_pg_trgm() -> None:
    """Enable pg_trgm for filename similarity search; add GIN index on documents.filename."""
    if not settings.database_url.startswith("postgresql"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_documents_filename_trgm "
                    "ON documents USING gin (filename gin_trgm_ops)"
                )
            )
    except Exception as e:
        logger.warning(
            "Could not enable pg_trgm or create trigram index (needs DB superuser or extension). "
            "Substring search still works; trigram mode may fail. Error: %s",
            e,
        )


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def promote_bootstrap_admin_if_configured() -> None:
    """
    If BOOTSTRAP_ADMIN_EMAIL matches an existing user, set their role to admin.
    Runs on startup so the first admin does not need raw SQL after roles were added.
    """
    from app.models import User
    from app.roles import Role

    email = (settings.bootstrap_admin_email or "").strip()
    if not email:
        return
    db = SessionLocal()
    try:
        user = db.execute(
            select(User).where(func.lower(User.email) == email.lower())
        ).scalar_one_or_none()
        if user is None or user.role == Role.admin.value:
            return
        user.role = Role.admin.value
        db.commit()
    finally:
        db.close()
