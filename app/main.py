from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

load_dotenv()

from app.activity_log import ActivityAction, activity_where_clause, log_activity
from app.auth import create_access_token, get_current_user, hash_password, verify_password
from app.config import settings
from app.database import (
    Base,
    engine,
    ensure_folder_tree_schema,
    ensure_document_retention_columns,
    ensure_organization_columns,
    ensure_pg_trgm,
    ensure_users_role_column,
    get_db,
    promote_bootstrap_admin_if_configured,
)
from app.document_search import build_document_list_filters, document_count_query, document_list_query
from app.models import ActivityEvent, Collection, Document, Folder, Tag, User
from app.blockchain_service import get_on_chain_owner, is_notarization_configured, notarize_hash
from app.permissions import RequirePermission, can_access_document, has_permission
from app.roles import Role, normalize_role
from app.schemas import (
    ActivityEventOut,
    ActivityListResponse,
    AdminUserCreate,
    AdminUserUpdate,
    DocumentListResponse,
    DocumentMetadataUpdate,
    DocumentOut,
    DocumentVerifyResult,
    RetentionApplyOut,
    Token,
    UserCreate,
    UserOut,
    UserRoleUpdate,
)
from app.routers.organization import collection_router, folder_router, tag_router
from app.services.storage import read_stored_file, save_upload, sha256_bytes


def _activity_rows_to_out(db: Session, rows: list[ActivityEvent]) -> list[ActivityEventOut]:
    uids: set[int] = set()
    for e in rows:
        if e.actor_user_id is not None:
            uids.add(e.actor_user_id)
        if e.target_user_id is not None:
            uids.add(e.target_user_id)
    emails: dict[int, str] = {}
    if uids:
        users = db.execute(select(User).where(User.id.in_(uids))).scalars().all()
        emails = {u.id: u.email for u in users}
    out: list[ActivityEventOut] = []
    for e in rows:
        out.append(
            ActivityEventOut(
                id=e.id,
                created_at=e.created_at,
                action=e.action,
                actor_user_id=e.actor_user_id,
                actor_email=emails.get(e.actor_user_id) if e.actor_user_id is not None else None,
                document_id=e.document_id,
                target_user_id=e.target_user_id,
                target_email=emails.get(e.target_user_id) if e.target_user_id is not None else None,
                payload=e.payload,
            )
        )
    return out


def document_to_out(doc: Document) -> DocumentOut:
    tag_ids = [t.id for t in doc.tags] if getattr(doc, "tags", None) else []
    collection_ids = [c.id for c in doc.collections] if getattr(doc, "collections", None) else []
    return DocumentOut(
        id=doc.id,
        filename=doc.filename,
        owner_id=doc.owner_id,
        folder_id=doc.folder_id,
        tag_ids=tag_ids,
        collection_ids=collection_ids,
        upload_date=doc.upload_date,
        storage_uri=doc.storage_uri,
        content_sha256_hex=doc.file_hash.hex()
        if isinstance(doc.file_hash, (bytes, bytearray))
        else str(doc.file_hash),
        blockchain_tx_hash=doc.blockchain_tx_hash,
        version=doc.version,
        previous_version_id=doc.previous_version_id,
        deleted_at=doc.deleted_at,
        legal_hold=bool(doc.legal_hold),
        retention_expires_at=doc.retention_expires_at,
    )


def _resolve_folder_for_owner(db: Session, folder_id: int | None, owner_id: int) -> int | None:
    if folder_id is None:
        return None
    f = db.get(Folder, folder_id)
    if f is None or f.owner_id != owner_id:
        raise HTTPException(status_code=404, detail="Folder not found")
    return folder_id


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_users_role_column()
    ensure_organization_columns()
    ensure_document_retention_columns()
    ensure_folder_tree_schema()
    ensure_pg_trgm()
    promote_bootstrap_admin_if_configured()
    yield


app = FastAPI(title="DMS", lifespan=lifespan)
app.include_router(folder_router)
app.include_router(tag_router)
app.include_router(collection_router)


def _initial_role_for_email(email: str) -> str:
    if (
        settings.bootstrap_admin_email
        and email.lower() == settings.bootstrap_admin_email.strip().lower()
    ):
        return Role.admin.value
    return Role.user.value


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: UserCreate, db: Annotated[Session, Depends(get_db)]) -> UserOut:
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        role=_initial_role_for_email(body.email),
    )
    db.add(user)
    db.flush()
    log_activity(
        db,
        actor_user_id=user.id,
        action=ActivityAction.USER_REGISTERED,
        payload={"email": user.email},
    )
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@app.get("/auth/me", response_model=UserOut)
def auth_me(current_user: Annotated[User, Depends(get_current_user)]) -> UserOut:
    return UserOut.model_validate(current_user)


@app.post("/auth/token", response_model=Token)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    user = db.execute(select(User).where(User.email == form_data.username)).scalar_one_or_none()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    token = create_access_token(subject=user.email)
    return Token(access_token=token)


@app.post("/documents/upload", response_model=DocumentOut)
async def upload_document(
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
    folder_id: int | None = Form(default=None),
) -> DocumentOut:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    fid = _resolve_folder_for_owner(db, folder_id, current_user.id)
    storage_uri, digest = save_upload(content, file.filename or "unnamed")
    tx_hash = notarize_hash(digest)
    retention: datetime | None = None
    if settings.default_retention_days is not None and settings.default_retention_days > 0:
        retention = datetime.now(timezone.utc) + timedelta(days=settings.default_retention_days)
    doc = Document(
        filename=file.filename or "unnamed",
        owner_id=current_user.id,
        folder_id=fid,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=tx_hash,
        version=1,
        previous_version_id=None,
        retention_expires_at=retention,
    )
    db.add(doc)
    db.flush()
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_UPLOAD,
        document_id=doc.id,
        payload={"filename": doc.filename, "version": doc.version},
    )
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@app.get("/documents", response_model=DocumentListResponse)
def list_documents(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    q: str | None = Query(
        default=None,
        description="Search filename: substring (ILIKE) or trigram similarity, see search_mode.",
    ),
    search_mode: Literal["substring", "trigram"] = Query(
        default="substring",
        description="substring: case-insensitive contains. trigram: pg_trgm similarity (fuzzy).",
    ),
    owner_id: int | None = Query(
        default=None,
        description="Filter by owner user id (only allowed for manager/admin with read_all).",
    ),
    uploaded_after: datetime | None = Query(
        default=None,
        description="Include documents uploaded on or after this instant (ISO 8601).",
    ),
    uploaded_before: datetime | None = Query(
        default=None,
        description="Include documents uploaded on or before this instant (ISO 8601).",
    ),
    content_sha256_hex: str | None = Query(
        default=None,
        description="Exact match on stored SHA-256 content hash (64 hex chars).",
    ),
    version: int | None = Query(default=None, description="Exact version number."),
    version_min: int | None = Query(default=None, ge=1),
    version_max: int | None = Query(default=None, ge=1),
    skip: int = Query(default=0, ge=0),
    limit: int | None = Query(
        default=None,
        ge=1,
        le=5000,
        description="Max rows (default: no limit; use for pagination).",
    ),
    folder_id: int | None = Query(default=None, description="Filter by folder id."),
    tag_ids: list[int] | None = Query(
        default=None,
        description="Documents that have ALL of these tag ids (AND).",
    ),
    collection_id: int | None = Query(default=None, description="Filter by membership in this collection."),
    include_deleted: bool = Query(
        default=False,
        description="Include soft-deleted rows (managers/admins auditing).",
    ),
    trash_only: bool = Query(
        default=False,
        description="Only soft-deleted rows (trash).",
    ),
) -> DocumentListResponse:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if trash_only and include_deleted:
        raise HTTPException(
            status_code=400,
            detail="Cannot use trash_only=true together with include_deleted=true",
        )
    if (
        version_min is not None
        and version_max is not None
        and version_min > version_max
    ):
        raise HTTPException(
            status_code=400,
            detail="version_min cannot be greater than version_max",
        )
    read_all = has_permission(current_user, "documents:read_all")
    if folder_id is not None:
        f = db.get(Folder, folder_id)
        if f is None or (not read_all and f.owner_id != current_user.id):
            raise HTTPException(status_code=404, detail="Folder not found")
    if collection_id is not None:
        c = db.get(Collection, collection_id)
        if c is None or (not read_all and c.owner_id != current_user.id):
            raise HTTPException(status_code=404, detail="Collection not found")
    if tag_ids:
        for tid in tag_ids:
            t = db.get(Tag, tid)
            if t is None or (not read_all and t.owner_id != current_user.id):
                raise HTTPException(status_code=404, detail="Tag not found")
    if owner_id is not None and not read_all:
        if owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="owner_id filter requires documents:read_all or must match your user id.",
            )

    try:
        conditions = build_document_list_filters(
            read_all=read_all,
            current_user_id=current_user.id,
            owner_id=owner_id,
            q=q,
            search_mode=search_mode,
            uploaded_after=uploaded_after,
            uploaded_before=uploaded_before,
            content_sha256_hex=content_sha256_hex,
            version=version,
            version_min=version_min,
            version_max=version_max,
            folder_id=folder_id,
            tag_ids=tag_ids or None,
            collection_id=collection_id,
            include_deleted=include_deleted,
            trash_only=trash_only,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    total = db.execute(document_count_query(conditions)).scalar_one()
    rows = db.execute(document_list_query(conditions, skip=skip, limit=limit)).scalars().all()
    return DocumentListResponse(
        items=[document_to_out(d) for d in rows],
        total=int(total),
        skip=skip,
        limit=limit,
    )


@app.get("/activity", response_model=ActivityListResponse)
def list_activity_feed(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    document_id: int | None = Query(
        default=None,
        description="Only events for this document (must be allowed to access the document).",
    ),
    action: str | None = Query(
        default=None,
        description="Exact action string (e.g. document.upload, user.role_changed).",
    ),
) -> ActivityListResponse:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing permission: documents:read",
        )
    if document_id is not None:
        doc = db.get(Document, document_id)
        if doc is None or not can_access_document(current_user, doc):
            raise HTTPException(status_code=404, detail="Document not found")
    where = activity_where_clause(current_user, document_id=document_id, action=action)
    total = db.execute(select(func.count()).select_from(ActivityEvent).where(where)).scalar_one()
    rows = db.execute(
        select(ActivityEvent)
        .where(where)
        .order_by(ActivityEvent.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).scalars().all()
    return ActivityListResponse(
        items=_activity_rows_to_out(db, rows),
        total=int(total),
        skip=skip,
        limit=limit,
    )


@app.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    include_deleted: bool = Query(
        default=False,
        description="Return soft-deleted documents (e.g. trash inspection).",
    ),
) -> DocumentOut:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    doc = db.execute(
        select(Document)
        .options(
            selectinload(Document.tags),
            selectinload(Document.collections),
            selectinload(Document.folder),
        )
        .where(Document.id == document_id)
    ).scalar_one_or_none()
    if doc is None or not can_access_document(current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None and not include_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    return document_to_out(doc)


@app.get("/documents/{document_id}/activity", response_model=ActivityListResponse)
def list_document_activity_feed(
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    action: str | None = Query(default=None, description="Exact action filter."),
    include_deleted: bool = Query(
        default=False,
        description="Allow activity for a soft-deleted document.",
    ),
) -> ActivityListResponse:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing permission: documents:read",
        )
    doc = db.get(Document, document_id)
    if doc is None or not can_access_document(current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None and not include_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    where = activity_where_clause(current_user, document_id=document_id, action=action)
    total = db.execute(select(func.count()).select_from(ActivityEvent).where(where)).scalar_one()
    rows = db.execute(
        select(ActivityEvent)
        .where(where)
        .order_by(ActivityEvent.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).scalars().all()
    return ActivityListResponse(
        items=_activity_rows_to_out(db, rows),
        total=int(total),
        skip=skip,
        limit=limit,
    )


@app.patch("/documents/{document_id}", response_model=DocumentOut)
def update_document_metadata(
    document_id: int,
    body: DocumentMetadataUpdate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = db.execute(
        select(Document)
        .options(
            selectinload(Document.tags),
            selectinload(Document.collections),
        )
        .where(Document.id == document_id)
    ).scalar_one_or_none()
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None:
        raise HTTPException(status_code=409, detail="Document is deleted; restore before editing metadata")
    patch = body.model_dump(exclude_unset=True)
    if "folder_id" in patch:
        if patch["folder_id"] is None:
            doc.folder_id = None
        else:
            doc.folder_id = _resolve_folder_for_owner(db, patch["folder_id"], current_user.id)
    if "tag_ids" in patch:
        tids = patch["tag_ids"]
        if not tids:
            doc.tags = []
        else:
            tags = db.execute(
                select(Tag).where(Tag.id.in_(tids), Tag.owner_id == current_user.id)
            ).scalars().all()
            if len(tags) != len(set(tids)):
                raise HTTPException(status_code=400, detail="Invalid or duplicate tag ids")
            doc.tags = list(tags)
    if "collection_ids" in patch:
        cids = patch["collection_ids"]
        if not cids:
            doc.collections = []
        else:
            cols = db.execute(
                select(Collection).where(
                    Collection.id.in_(cids),
                    Collection.owner_id == current_user.id,
                )
            ).scalars().all()
            if len(cols) != len(set(cids)):
                raise HTTPException(status_code=400, detail="Invalid or duplicate collection ids")
            doc.collections = list(cols)
    if "legal_hold" in patch:
        doc.legal_hold = bool(patch["legal_hold"])
    if "retention_expires_at" in patch:
        doc.retention_expires_at = patch["retention_expires_at"]
    if patch:
        log_activity(
            db,
            actor_user_id=current_user.id,
            action=ActivityAction.DOCUMENT_METADATA,
            document_id=doc.id,
            payload={"fields": sorted(patch.keys())},
        )
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@app.delete("/documents/{document_id}", response_model=DocumentOut)
def soft_delete_document(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = db.get(Document, document_id)
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None:
        raise HTTPException(status_code=409, detail="Document is already deleted")
    if doc.legal_hold:
        raise HTTPException(
            status_code=409,
            detail="Document is under legal hold; clear legal_hold before delete.",
        )
    doc.deleted_at = datetime.now(timezone.utc)
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_DELETE,
        document_id=doc.id,
    )
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@app.post("/documents/{document_id}/restore", response_model=DocumentOut)
def restore_document(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = db.get(Document, document_id)
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is None:
        raise HTTPException(status_code=409, detail="Document is not deleted")
    doc.deleted_at = None
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_RESTORE,
        document_id=doc.id,
    )
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@app.post("/documents/{document_id}/versions", response_model=DocumentOut)
async def upload_new_version(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
) -> DocumentOut:
    parent = db.execute(
        select(Document)
        .options(selectinload(Document.tags), selectinload(Document.collections))
        .where(Document.id == document_id)
    ).scalar_one_or_none()
    if parent is None or parent.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if parent.deleted_at is not None:
        raise HTTPException(
            status_code=409,
            detail="Cannot upload a new version while the document is deleted; restore first.",
        )
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    storage_uri, digest = save_upload(content, file.filename or parent.filename)
    tx_hash = notarize_hash(digest)
    new_doc = Document(
        filename=file.filename or parent.filename,
        owner_id=current_user.id,
        folder_id=parent.folder_id,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=tx_hash,
        version=parent.version + 1,
        previous_version_id=parent.id,
        legal_hold=parent.legal_hold,
        retention_expires_at=parent.retention_expires_at,
    )
    db.add(new_doc)
    db.flush()
    new_doc.tags = list(parent.tags)
    new_doc.collections = list(parent.collections)
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_VERSION,
        document_id=new_doc.id,
        payload={
            "version": new_doc.version,
            "previous_version_id": parent.id,
            "filename": new_doc.filename,
        },
    )
    db.commit()
    db.refresh(new_doc)
    return document_to_out(new_doc)


def _newer_version_document_id(db: Session, doc: Document) -> int | None:
    return db.execute(
        select(Document.id).where(
            Document.previous_version_id == doc.id,
            Document.owner_id == doc.owner_id,
        ).limit(1)
    ).scalar_one_or_none()


@app.get("/documents/{document_id}/verify", response_model=DocumentVerifyResult)
def verify_document(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:verify"))],
    db: Annotated[Session, Depends(get_db)],
    include_deleted: bool = Query(
        default=False,
        description="Allow verifying a soft-deleted document (e.g. audit).",
    ),
) -> DocumentVerifyResult:
    doc = db.get(Document, document_id)
    if doc is None or not can_access_document(current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None and not include_deleted:
        raise HTTPException(status_code=404, detail="Document not found")

    successor_id = _newer_version_document_id(db, doc)
    is_latest = successor_id is None
    configured = is_notarization_configured()

    try:
        raw = read_stored_file(doc.storage_uri)
    except FileNotFoundError:
        stored_hex = doc.file_hash.hex() if isinstance(doc.file_hash, (bytes, bytearray)) else None
        log_activity(
            db,
            actor_user_id=current_user.id,
            action=ActivityAction.DOCUMENT_VERIFY,
            document_id=doc.id,
            payload={"outcome": "missing_file"},
        )
        db.commit()
        return DocumentVerifyResult(
            document_id=doc.id,
            content_matches_stored_hash=False,
            content_hash_matches_blockchain=None,
            stored_content_sha256_hex=stored_hex,
            computed_content_sha256_hex=None,
            notarization_configured=configured,
            is_latest_version=is_latest,
            newer_version_document_id=successor_id,
            message="Stored file missing; cannot recompute content hash from disk.",
        )

    current_hash = sha256_bytes(raw)
    stored_hex = doc.file_hash.hex() if isinstance(doc.file_hash, (bytes, bytearray)) else ""
    computed_hex = current_hash.hex()
    matches_record = current_hash == doc.file_hash
    chain_owner = get_on_chain_owner(doc.file_hash)

    parts: list[str] = []
    if matches_record:
        parts.append("SHA-256 of file bytes on disk matches the content hash stored at upload.")
    else:
        parts.append("SHA-256 of file bytes on disk does not match stored content hash (file was altered).")

    if successor_id is not None:
        parts.append(
            f"This row is not the latest version — verify document_id={successor_id} for the newest upload."
        )

    if not configured:
        matches_chain = None
        parts.append(
            "On-chain proof is unavailable: set ETH_RPC_URL, CONTRACT_ADDRESS, and PRIVATE_KEY, deploy DocumentNotary.sol, and restart."
        )
    elif doc.blockchain_tx_hash is None:
        matches_chain = None
        parts.append(
            "No notarization transaction was stored for this upload (notarization was skipped or failed at upload time)."
        )
    elif chain_owner is None:
        matches_chain = False
        parts.append(
            "Could not find this hash on-chain (wrong network, contract address, or RPC)."
        )
    else:
        matches_chain = matches_record
        if matches_record:
            parts.append("The stored hash is registered on-chain.")
        else:
            parts.append("The file no longer matches the hash that was notarized on-chain.")

    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.DOCUMENT_VERIFY,
        document_id=doc.id,
        payload={
            "outcome": "ok",
            "content_matches_stored_hash": matches_record,
            "content_hash_matches_blockchain": matches_chain,
            "is_latest_version": is_latest,
            "newer_version_document_id": successor_id,
        },
    )
    db.commit()
    return DocumentVerifyResult(
        document_id=doc.id,
        content_matches_stored_hash=matches_record,
        content_hash_matches_blockchain=matches_chain,
        stored_content_sha256_hex=stored_hex,
        computed_content_sha256_hex=computed_hex,
        notarization_configured=configured,
        is_latest_version=is_latest,
        newer_version_document_id=successor_id,
        message=" ".join(parts),
    )


def _count_users_with_role(db: Session, role: str) -> int:
    return db.execute(select(func.count()).select_from(User).where(User.role == role)).scalar_one()


def _count_documents_for_user(db: Session, user_id: int) -> int:
    return db.execute(
        select(func.count())
        .select_from(Document)
        .where(Document.owner_id == user_id, Document.deleted_at.is_(None))
    ).scalar_one()


def _assert_can_change_admin_role(db: Session, target: User, new_role: str) -> None:
    if target.role != Role.admin.value:
        return
    if normalize_role(new_role).value == Role.admin.value:
        return
    if _count_users_with_role(db, Role.admin.value) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote the only admin; promote another admin first.",
        )


def _assert_can_remove_admin(db: Session, target: User) -> None:
    if target.role != Role.admin.value:
        return
    if _count_users_with_role(db, Role.admin.value) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the only admin.",
        )


@app.post("/admin/retention/apply", response_model=RetentionApplyOut)
def admin_apply_retention(
    admin: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> RetentionApplyOut:
    """Soft-delete active documents whose retention window has passed (skips legal hold)."""
    now = datetime.now(timezone.utc)
    res = db.execute(
        update(Document)
        .where(
            Document.deleted_at.is_(None),
            Document.legal_hold.is_(False),
            Document.retention_expires_at.is_not(None),
            Document.retention_expires_at < now,
        )
        .values(deleted_at=now)
    )
    count = int(res.rowcount or 0)
    log_activity(
        db,
        actor_user_id=admin.id,
        action=ActivityAction.RETENTION_APPLIED,
        payload={"soft_deleted_count": count},
    )
    db.commit()
    return RetentionApplyOut(soft_deleted_count=count)


@app.get("/admin/users", response_model=list[UserOut])
def admin_list_users(
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
    skip: int = 0,
    limit: int = 100,
) -> list[UserOut]:
    limit = min(max(limit, 1), 500)
    skip = max(skip, 0)
    rows = (
        db.execute(select(User).order_by(User.id).offset(skip).limit(limit)).scalars().all()
    )
    return [UserOut.model_validate(u) for u in rows]


@app.get("/admin/users/{user_id}", response_model=UserOut)
def admin_get_user(
    user_id: int,
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut.model_validate(target)


@app.post("/admin/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def admin_create_user(
    body: AdminUserCreate,
    admin: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.flush()
    log_activity(
        db,
        actor_user_id=admin.id,
        action=ActivityAction.USER_ADMIN_CREATE,
        target_user_id=user.id,
        payload={"email": user.email, "role": user.role},
    )
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@app.patch("/admin/users/{user_id}", response_model=UserOut)
def admin_update_user(
    user_id: int,
    body: AdminUserUpdate,
    admin: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    old_email = target.email
    old_role = target.role
    if body.role is not None:
        _assert_can_change_admin_role(db, target, body.role)
        target.role = body.role
    if body.email is not None:
        other = db.execute(
            select(User).where(User.email == body.email, User.id != user_id)
        ).scalar_one_or_none()
        if other:
            raise HTTPException(status_code=400, detail="Email already in use")
        target.email = body.email
    if body.password is not None:
        target.hashed_password = hash_password(body.password)
    payload: dict = {}
    if body.role is not None:
        payload["role"] = {"from": old_role, "to": body.role}
    if body.email is not None:
        payload["email"] = {"from": old_email, "to": body.email}
    if body.password is not None:
        payload["password_changed"] = True
    if payload:
        log_activity(
            db,
            actor_user_id=admin.id,
            action=ActivityAction.USER_ADMIN_UPDATE,
            target_user_id=target.id,
            payload=payload,
        )
    db.commit()
    db.refresh(target)
    return UserOut.model_validate(target)


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_user(
    user_id: int,
    admin: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if _count_documents_for_user(db, user_id) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User still owns documents; delete or reassign documents first.",
        )
    _assert_can_remove_admin(db, target)
    log_activity(
        db,
        actor_user_id=admin.id,
        action=ActivityAction.USER_ADMIN_DELETE,
        target_user_id=target.id,
        payload={"email": target.email},
    )
    db.delete(target)
    db.commit()


@app.patch("/admin/users/{user_id}/role", response_model=UserOut)
def admin_set_user_role(
    user_id: int,
    body: UserRoleUpdate,
    admin: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    old_role = target.role
    _assert_can_change_admin_role(db, target, body.role)
    target.role = body.role
    log_activity(
        db,
        actor_user_id=admin.id,
        action=ActivityAction.USER_ROLE_CHANGED,
        target_user_id=target.id,
        payload={"from": old_role, "to": body.role},
    )
    db.commit()
    db.refresh(target)
    return UserOut.model_validate(target)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
