from collections.abc import Generator

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import settings

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
