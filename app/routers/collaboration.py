"""Document ACL, expiring share links, lifecycle transitions, and unauthenticated /shared routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.activity_log import ActivityAction, log_activity
from app.auth import get_current_user
from app.database import get_db
from app.document_output import document_to_out
from app.document_access import (
    LifecycleState,
    can_approve_lifecycle,
    can_read_document,
    can_submit_review,
    can_verify_document,
    can_write_document,
    resolve_share_link,
    share_link_allows,
)
from app.models import Document, DocumentPermission, DocumentShareLink, User
from app.permissions import RequirePermission, has_permission
from app.schemas import (
    DocumentOut,
    DocumentPermissionCreate,
    DocumentPermissionOut,
    DocumentShareLinkCreate,
    DocumentShareLinkOut,
    DocumentSharedOut,
    DocumentVerifyResult,
    LifecycleTransitionBody,
)
from app.verify_logic import run_document_verify

router = APIRouter(tags=["Collaboration"])


def _get_document_or_404(db: Session, document_id: int) -> Document:
    doc = db.execute(
        select(Document)
        .options(selectinload(Document.tags), selectinload(Document.collections))
        .where(Document.id == document_id)
    ).scalar_one_or_none()
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


def _require_owner(doc: Document, user: User) -> None:
    if doc.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Document not found")


@router.get("/documents/{document_id}/permissions", response_model=list[DocumentPermissionOut])
def list_document_permissions(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:read"))],
    db: Annotated[Session, Depends(get_db)],
) -> list[DocumentPermissionOut]:
    doc = _get_document_or_404(db, document_id)
    if not can_read_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    rows = db.execute(
        select(DocumentPermission, User.email)
        .join(User, User.id == DocumentPermission.user_id)
        .where(DocumentPermission.document_id == document_id)
        .order_by(DocumentPermission.id)
    ).all()
    out: list[DocumentPermissionOut] = []
    for perm, email in rows:
        out.append(
            DocumentPermissionOut(
                id=perm.id,
                document_id=perm.document_id,
                user_id=perm.user_id,
                user_email=email,
                permission=perm.permission,
            )
        )
    return out


@router.post(
    "/documents/{document_id}/permissions",
    response_model=DocumentPermissionOut,
    status_code=status.HTTP_201_CREATED,
)
def add_document_permission(
    document_id: int,
    body: DocumentPermissionCreate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentPermissionOut:
    doc = _get_document_or_404(db, document_id)
    if not can_write_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    if body.user_id == doc.owner_id:
        raise HTTPException(status_code=400, detail="Owner already has full access; remove ACL not needed.")
    target = db.get(User, body.user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == body.user_id,
        )
    ).scalar_one_or_none()
    if existing:
        existing.permission = body.permission
        perm = existing
    else:
        perm = DocumentPermission(
            document_id=document_id,
            user_id=body.user_id,
            permission=body.permission,
        )
        db.add(perm)
    db.flush()
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_ACL_SET,
        document_id=document_id,
        target_user_id=body.user_id,
        payload={"permission": body.permission},
    )
    db.commit()
    db.refresh(perm)
    return DocumentPermissionOut(
        id=perm.id,
        document_id=perm.document_id,
        user_id=perm.user_id,
        user_email=target.email,
        permission=perm.permission,
    )


@router.delete("/documents/{document_id}/permissions/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_document_permission(
    document_id: int,
    user_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    doc = _get_document_or_404(db, document_id)
    if not can_write_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    row = db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    db.delete(row)
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_ACL_DELETE,
        document_id=document_id,
        target_user_id=user_id,
    )
    db.commit()


@router.get("/documents/{document_id}/share-links", response_model=list[DocumentShareLinkOut])
def list_share_links(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:read"))],
    db: Annotated[Session, Depends(get_db)],
) -> list[DocumentShareLinkOut]:
    doc = _get_document_or_404(db, document_id)
    if not can_read_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    rows = db.execute(
        select(DocumentShareLink)
        .where(DocumentShareLink.document_id == document_id)
        .order_by(DocumentShareLink.id.desc())
    ).scalars().all()
    return [
        DocumentShareLinkOut(
            id=r.id,
            document_id=r.document_id,
            permission=r.permission,
            expires_at=r.expires_at,
            token=r.token,
            share_path=f"/shared/document?t={r.token}",
        )
        for r in rows
    ]


@router.post(
    "/documents/{document_id}/share-links",
    response_model=DocumentShareLinkOut,
    status_code=status.HTTP_201_CREATED,
)
def create_share_link(
    document_id: int,
    body: DocumentShareLinkCreate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentShareLinkOut:
    doc = _get_document_or_404(db, document_id)
    if not can_write_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    tok = token_urlsafe(32)
    exp = datetime.now(timezone.utc) + timedelta(hours=body.expires_in_hours)
    row = DocumentShareLink(
        document_id=document_id,
        token=tok,
        permission=body.permission,
        expires_at=exp,
        created_by_user_id=current_user.id,
    )
    db.add(row)
    db.flush()
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_SHARE_LINK,
        document_id=document_id,
        payload={"permission": body.permission, "expires_at": exp.isoformat()},
    )
    db.commit()
    db.refresh(row)
    return DocumentShareLinkOut(
        id=row.id,
        document_id=row.document_id,
        permission=row.permission,
        expires_at=row.expires_at,
        token=row.token,
        share_path=f"/shared/document?t={row.token}",
    )


@router.delete("/documents/{document_id}/share-links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_share_link(
    document_id: int,
    link_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    doc = _get_document_or_404(db, document_id)
    if not can_write_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    _require_owner(doc, current_user)
    row = db.get(DocumentShareLink, link_id)
    if row is None or row.document_id != document_id:
        raise HTTPException(status_code=404, detail="Share link not found")
    db.delete(row)
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_SHARE_LINK_DELETE,
        document_id=document_id,
        payload={"link_id": link_id},
    )
    db.commit()


@router.post("/documents/{document_id}/lifecycle", response_model=DocumentOut)
def transition_lifecycle(
    document_id: int,
    body: LifecycleTransitionBody,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = _get_document_or_404(db, document_id)
    if not can_read_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    tr = body.transition
    before = doc.lifecycle_state
    if tr == "submit_review":
        if doc.lifecycle_state != LifecycleState.DRAFT:
            raise HTTPException(status_code=400, detail="Only draft documents can be submitted for review.")
        if not can_submit_review(db, current_user, doc):
            raise HTTPException(status_code=403, detail="Not allowed to submit for review.")
        doc.lifecycle_state = LifecycleState.REVIEW
    elif tr == "approve":
        if doc.lifecycle_state != LifecycleState.REVIEW:
            raise HTTPException(status_code=400, detail="Only documents in review can be approved.")
        if not can_approve_lifecycle(db, current_user, doc):
            raise HTTPException(status_code=403, detail="Not allowed to approve.")
        doc.lifecycle_state = LifecycleState.PUBLISHED
    elif tr == "reject":
        if doc.lifecycle_state != LifecycleState.REVIEW:
            raise HTTPException(status_code=400, detail="Only documents in review can be rejected.")
        if not can_approve_lifecycle(db, current_user, doc):
            raise HTTPException(status_code=403, detail="Not allowed to reject.")
        doc.lifecycle_state = LifecycleState.DRAFT
    elif tr == "unpublish":
        if doc.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can unpublish.")
        if not has_permission(current_user, "documents:write"):
            raise HTTPException(status_code=403, detail="Missing permission: documents:write")
        if doc.lifecycle_state != LifecycleState.PUBLISHED:
            raise HTTPException(status_code=400, detail="Only published documents can be unpublished.")
        doc.lifecycle_state = LifecycleState.DRAFT
    else:
        raise HTTPException(status_code=400, detail="Unknown transition")
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_LIFECYCLE,
        document_id=document_id,
        payload={"transition": tr, "from": before, "to": doc.lifecycle_state},
    )
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@router.get("/shared/document", response_model=DocumentSharedOut)
def shared_document_metadata(
    db: Annotated[Session, Depends(get_db)],
    t: str = Query(..., description="Share token from POST .../share-links"),
) -> DocumentSharedOut:
    link = resolve_share_link(db, t)
    if link is None or not share_link_allows(link, "read"):
        raise HTTPException(status_code=404, detail="Invalid or expired share link")
    doc = db.get(Document, link.document_id)
    if doc is None or doc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Document not found")
    return DocumentSharedOut(
        id=doc.id,
        filename=doc.filename,
        owner_id=doc.owner_id,
        version=doc.version,
        upload_date=doc.upload_date,
        content_sha256_hex=doc.file_hash.hex()
        if isinstance(doc.file_hash, (bytes, bytearray))
        else str(doc.file_hash),
        lifecycle_state=doc.lifecycle_state,
    )


@router.get("/shared/verify", response_model=DocumentVerifyResult)
def shared_verify(
    db: Annotated[Session, Depends(get_db)],
    t: str = Query(..., description="Share token with verify permission"),
) -> DocumentVerifyResult:
    link = resolve_share_link(db, t)
    if link is None or not share_link_allows(link, "verify"):
        raise HTTPException(status_code=404, detail="Invalid, expired, or read-only share link")
    doc = db.get(Document, link.document_id)
    if doc is None or doc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Document not found")
    return run_document_verify(db, doc, actor_user_id=None, log_activity_events=False)
