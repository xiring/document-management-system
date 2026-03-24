"""Append-only activity / audit events for UI feeds."""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import ActivityEvent, Document, User
from app.permissions import has_permission


class ActivityAction:
    """Stable action strings for clients and filters."""

    DOCUMENT_UPLOAD = "document.upload"
    DOCUMENT_VERSION = "document.version"
    DOCUMENT_METADATA = "document.metadata"
    DOCUMENT_DELETE = "document.delete"
    DOCUMENT_RESTORE = "document.restore"
    DOCUMENT_VERIFY = "document.verify"

    USER_REGISTERED = "user.registered"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_ADMIN_CREATE = "user.admin_create"
    USER_ADMIN_UPDATE = "user.admin_update"
    USER_ADMIN_DELETE = "user.admin_delete"

    RETENTION_APPLIED = "retention.applied"


def log_activity(
    db: Session,
    *,
    actor_user_id: int | None,
    action: str,
    document_id: int | None = None,
    target_user_id: int | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    db.add(
        ActivityEvent(
            actor_user_id=actor_user_id,
            action=action,
            document_id=document_id,
            target_user_id=target_user_id,
            payload=payload,
        )
    )


def activity_visibility_filter(current_user: User) -> Any:
    """Events visible to this user when they do not have `documents:read_all`."""
    own_docs = select(Document.id).where(Document.owner_id == current_user.id)
    return or_(
        ActivityEvent.actor_user_id == current_user.id,
        ActivityEvent.target_user_id == current_user.id,
        ActivityEvent.document_id.in_(own_docs),
    )


def activity_where_clause(
    current_user: User,
    *,
    document_id: int | None = None,
    action: str | None = None,
) -> Any:
    parts: list[Any] = []
    if not has_permission(current_user, "documents:read_all"):
        parts.append(activity_visibility_filter(current_user))
    if document_id is not None:
        parts.append(ActivityEvent.document_id == document_id)
    if action:
        parts.append(ActivityEvent.action == action)
    if not parts:
        return True
    return and_(*parts)
