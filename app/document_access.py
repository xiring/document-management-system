"""Document ACL, share links, and lifecycle-aware read/write/verify checks."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Document, DocumentPermission, DocumentShareLink
from app.permissions import has_permission


class LifecycleState:
    DRAFT = "draft"
    REVIEW = "review"
    PUBLISHED = "published"


def has_acl_permission(db: Session, user_id: int, document_id: int, need: str) -> bool:
    """Check ACL row for user on document. `need`: read | write | verify | approve."""
    row = db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    p = row.permission
    if need == "read":
        return True
    if need == "approve":
        return p == "approve"
    if need == "write":
        return p in ("write", "approve")
    if need == "verify":
        return p in ("verify", "write", "approve")
    return False


def can_read_document(db: Session, user, doc: Document) -> bool:
    """Read metadata, list, activity, download path (subject to route rules)."""
    if doc.owner_id == user.id:
        return has_permission(user, "documents:read") or has_permission(user, "documents:read_all")
    if has_permission(user, "documents:read_all"):
        return True
    return has_acl_permission(db, user.id, doc.id, "read")


def can_write_document(db: Session, user, doc: Document) -> bool:
    """Patch metadata, new version, delete — owner always; collaborators only draft/review."""
    if doc.owner_id == user.id:
        return has_permission(user, "documents:write")
    if doc.lifecycle_state == LifecycleState.PUBLISHED:
        return False
    if doc.lifecycle_state not in (LifecycleState.DRAFT, LifecycleState.REVIEW):
        return False
    return has_acl_permission(db, user.id, doc.id, "write")


def can_verify_document(db: Session, user, doc: Document) -> bool:
    """Run content/hash verification."""
    if not can_read_document(db, user, doc):
        return False
    if has_acl_permission(db, user.id, doc.id, "verify"):
        return True
    return has_permission(user, "documents:verify")


def can_approve_lifecycle(db: Session, user, doc: Document) -> bool:
    """Approve or reject review transitions (not submit from draft)."""
    if doc.owner_id == user.id:
        return True
    return has_acl_permission(db, user.id, doc.id, "approve")


def can_submit_review(db: Session, user, doc: Document) -> bool:
    """draft → review: owner or collaborator with write."""
    if doc.owner_id == user.id:
        return has_permission(user, "documents:write")
    if doc.lifecycle_state != LifecycleState.DRAFT:
        return False
    return has_acl_permission(db, user.id, doc.id, "write")


def resolve_share_link(db: Session, token: str) -> DocumentShareLink | None:
    row = db.execute(select(DocumentShareLink).where(DocumentShareLink.token == token)).scalar_one_or_none()
    if row is None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        return None
    return row


def share_link_allows(row: DocumentShareLink, need: str) -> bool:
    p = row.permission
    if need == "read":
        return p in ("read", "verify")
    if need == "verify":
        return p == "verify"
    return False


# Backwards-compatible name used across the codebase
def can_access_document(db: Session, user, doc: Document) -> bool:
    return can_read_document(db, user, doc)
