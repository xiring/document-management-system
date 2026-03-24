from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse
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
    ensure_document_chain_columns,
    ensure_document_lifecycle_column,
    ensure_folder_tree_schema,
    ensure_document_retention_columns,
    ensure_organization_columns,
    ensure_pg_trgm,
    ensure_users_role_column,
    get_db,
    promote_bootstrap_admin_if_configured,
    run_alembic_upgrade_head,
)
from app.health import aggregate_readiness
from app.document_search import build_document_list_filters, document_count_query, document_list_query
from app.models import ActivityEvent, ChainConfig, Collection, Document, DocumentPermission, Folder, Tag, User
from app.blockchain_service import notarize_hash, notarize_hash_ctx
from app.chain_resolution import chain_context_from_db
from app.public_verify import create_public_verify_token, decode_public_verify_token
from app.document_access import can_read_document, can_verify_document, can_write_document
from app.document_output import document_to_out
from app.permissions import RequirePermission, has_permission
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
    PublicVerifyLinkCreate,
    PublicVerifyLinkOut,
    RetentionApplyOut,
    Token,
    UserCreate,
    UserOut,
    UserRoleUpdate,
)
from app.routers.chain import router as chain_router
from app.routers.collaboration import router as collaboration_router
from app.routers.organization import collection_router, folder_router, tag_router
from app.verify_logic import run_document_verify
from app.services.storage import save_upload


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


def _resolve_folder_for_owner(db: Session, folder_id: int | None, owner_id: int) -> int | None:
    if folder_id is None:
        return None
    f = db.get(Folder, folder_id)
    if f is None or f.owner_id != owner_id:
        raise HTTPException(status_code=404, detail="Folder not found")
    return folder_id


def _apply_notarization(
    db: Session,
    doc: Document,
    digest: bytes,
    *,
    chain_config_id: int | None,
    defer_notarization: bool,
    owner_id: int,
) -> None:
    cc: ChainConfig | None = None
    if chain_config_id is not None:
        cc = db.get(ChainConfig, chain_config_id)
        if cc is None or cc.owner_id != owner_id:
            raise HTTPException(status_code=404, detail="Chain config not found")
        doc.chain_config_id = cc.id
    if defer_notarization:
        if doc.chain_config_id is None:
            raise HTTPException(
                status_code=400,
                detail="defer_notarization requires chain_config_id with a batch contract",
            )
        cc2 = db.get(ChainConfig, doc.chain_config_id)
        if cc2 is None or not (cc2.batch_contract_address or "").strip():
            raise HTTPException(
                status_code=400,
                detail="Chain config must have batch_contract_address for deferred Merkle notarization",
            )
        doc.pending_merkle = True
        doc.blockchain_tx_hash = None
        return
    doc.pending_merkle = False
    if doc.chain_config_id is not None:
        cc = db.get(ChainConfig, doc.chain_config_id)
        if cc is None:
            doc.blockchain_tx_hash = None
            return
        doc.blockchain_tx_hash = notarize_hash_ctx(chain_context_from_db(cc), digest)
    else:
        doc.blockchain_tx_hash = notarize_hash(digest)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.run_migrations_on_startup:
        run_alembic_upgrade_head()
    elif settings.use_sqlalchemy_create_all:
        Base.metadata.create_all(bind=engine)
        ensure_users_role_column()
        ensure_organization_columns()
        ensure_document_retention_columns()
        ensure_document_lifecycle_column()
        ensure_document_chain_columns()
        ensure_folder_tree_schema()
        ensure_pg_trgm()
    promote_bootstrap_admin_if_configured()
    yield


app = FastAPI(
    title="DMS",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Authentication", "description": "Register, login, and current user."},
        {"name": "Documents", "description": "Upload, list, metadata, versions, and verification."},
        {"name": "Activity", "description": "Audit and activity feeds."},
        {"name": "Public", "description": "Unauthenticated endpoints (e.g. token-based verify)."},
        {"name": "Admin", "description": "User management and retention jobs (requires admin permissions)."},
        {
            "name": "Health",
            "description": "Liveness (`GET /health`) and readiness with DB + RPC (`GET /health/ready`).",
        },
        {"name": "Collaboration", "description": "ACL, share links, lifecycle workflow, and shared read/verify."},
        {"name": "Folders", "description": "Folder tree for organizing documents."},
        {"name": "Tags", "description": "Tags for documents."},
        {"name": "Collections", "description": "Document collections."},
        {"name": "Chain configs", "description": "Blockchain notarization chain configuration."},
    ],
)
app.include_router(folder_router)
app.include_router(tag_router)
app.include_router(collection_router)
app.include_router(chain_router)
app.include_router(collaboration_router)


def _initial_role_for_email(email: str) -> str:
    if (
        settings.bootstrap_admin_email
        and email.lower() == settings.bootstrap_admin_email.strip().lower()
    ):
        return Role.admin.value
    return Role.user.value


@app.post(
    "/auth/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
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


@app.get("/auth/me", response_model=UserOut, tags=["Authentication"])
def auth_me(current_user: Annotated[User, Depends(get_current_user)]) -> UserOut:
    return UserOut.model_validate(current_user)


@app.post("/auth/token", response_model=Token, tags=["Authentication"])
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    user = db.execute(select(User).where(User.email == form_data.username)).scalar_one_or_none()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    token = create_access_token(subject=user.email)
    return Token(access_token=token)


@app.post("/documents/upload", response_model=DocumentOut, tags=["Documents"])
async def upload_document(
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
    folder_id: int | None = Form(default=None),
    chain_config_id: int | None = Form(default=None),
    defer_notarization: bool = Form(default=False),
) -> DocumentOut:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    fid = _resolve_folder_for_owner(db, folder_id, current_user.id)
    storage_uri, digest = save_upload(content, file.filename or "unnamed")
    retention: datetime | None = None
    if settings.default_retention_days is not None and settings.default_retention_days > 0:
        retention = datetime.now(timezone.utc) + timedelta(days=settings.default_retention_days)
    doc = Document(
        filename=file.filename or "unnamed",
        owner_id=current_user.id,
        lifecycle_state="draft",
        folder_id=fid,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=None,
        version=1,
        previous_version_id=None,
        retention_expires_at=retention,
    )
    db.add(doc)
    db.flush()
    _apply_notarization(
        db,
        doc,
        digest,
        chain_config_id=chain_config_id,
        defer_notarization=defer_notarization,
        owner_id=current_user.id,
    )
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


@app.get("/documents", response_model=DocumentListResponse, tags=["Documents"])
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
    include_shared: bool = Query(
        default=True,
        description="Include documents shared with you via ACL (not only owned).",
    ),
    lifecycle_state: str | None = Query(
        default=None,
        description="Filter by workflow state: draft, review, published.",
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
            include_shared=include_shared,
            lifecycle_state=lifecycle_state,
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


@app.get("/activity", response_model=ActivityListResponse, tags=["Activity"])
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
        if doc is None or not can_read_document(db, current_user, doc):
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


@app.get("/documents/{document_id}", response_model=DocumentOut, tags=["Documents"])
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
    if doc is None or not can_read_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None and not include_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    return document_to_out(doc)


@app.get(
    "/documents/{document_id}/activity",
    response_model=ActivityListResponse,
    tags=["Activity"],
)
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
    if doc is None or not can_read_document(db, current_user, doc):
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


@app.patch("/documents/{document_id}", response_model=DocumentOut, tags=["Documents"])
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
    if doc is None or not can_write_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None:
        raise HTTPException(status_code=409, detail="Document is deleted; restore before editing metadata")
    org_owner = doc.owner_id
    patch = body.model_dump(exclude_unset=True)
    if "folder_id" in patch:
        if patch["folder_id"] is None:
            doc.folder_id = None
        else:
            doc.folder_id = _resolve_folder_for_owner(db, patch["folder_id"], org_owner)
    if "tag_ids" in patch:
        tids = patch["tag_ids"]
        if not tids:
            doc.tags = []
        else:
            tags = db.execute(
                select(Tag).where(Tag.id.in_(tids), Tag.owner_id == org_owner)
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
                    Collection.owner_id == org_owner,
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


@app.delete("/documents/{document_id}", response_model=DocumentOut, tags=["Documents"])
def soft_delete_document(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = db.get(Document, document_id)
    if doc is None or not can_write_document(db, current_user, doc):
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


@app.post("/documents/{document_id}/restore", response_model=DocumentOut, tags=["Documents"])
def restore_document(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    doc = db.get(Document, document_id)
    if doc is None or not can_write_document(db, current_user, doc):
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


@app.post("/documents/{document_id}/versions", response_model=DocumentOut, tags=["Documents"])
async def upload_new_version(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
    chain_config_id: int | None = Form(default=None),
    defer_notarization: bool = Form(default=False),
) -> DocumentOut:
    parent = db.execute(
        select(Document)
        .options(selectinload(Document.tags), selectinload(Document.collections))
        .where(Document.id == document_id)
    ).scalar_one_or_none()
    if parent is None or not can_write_document(db, current_user, parent):
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
    cid = chain_config_id if chain_config_id is not None else parent.chain_config_id
    new_doc = Document(
        filename=file.filename or parent.filename,
        owner_id=parent.owner_id,
        lifecycle_state=parent.lifecycle_state,
        folder_id=parent.folder_id,
        chain_config_id=cid,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=None,
        version=parent.version + 1,
        previous_version_id=parent.id,
        legal_hold=parent.legal_hold,
        retention_expires_at=parent.retention_expires_at,
    )
    db.add(new_doc)
    db.flush()
    _apply_notarization(
        db,
        new_doc,
        digest,
        chain_config_id=cid,
        defer_notarization=defer_notarization,
        owner_id=parent.owner_id,
    )
    new_doc.tags = list(parent.tags)
    new_doc.collections = list(parent.collections)
    for p in (
        db.execute(select(DocumentPermission).where(DocumentPermission.document_id == parent.id))
        .scalars()
        .all()
    ):
        db.add(
            DocumentPermission(
                document_id=new_doc.id,
                user_id=p.user_id,
                permission=p.permission,
            )
        )
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


@app.get(
    "/documents/{document_id}/verify",
    response_model=DocumentVerifyResult,
    tags=["Documents"],
)
def verify_document(
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    include_deleted: bool = Query(
        default=False,
        description="Allow verifying a soft-deleted document (e.g. audit).",
    ),
) -> DocumentVerifyResult:
    doc = db.get(Document, document_id)
    if doc is None or not can_read_document(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.deleted_at is not None and not include_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    if not can_verify_document(db, current_user, doc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to verify this document (needs documents:verify or ACL verify on the document).",
        )
    return run_document_verify(db, doc, actor_user_id=current_user.id, log_activity_events=True)


@app.post(
    "/documents/{document_id}/verify-link",
    response_model=PublicVerifyLinkOut,
    tags=["Documents"],
)
def create_public_verify_link(
    document_id: int,
    body: PublicVerifyLinkCreate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> PublicVerifyLinkOut:
    doc = db.get(Document, document_id)
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    token, hours = create_public_verify_token(document_id, body.expires_in_hours)
    return PublicVerifyLinkOut(
        token=token,
        expires_in_hours=hours,
        verify_path=f"/public/verify?t={token}",
    )


@app.get("/public/verify", response_model=DocumentVerifyResult, tags=["Public"])
def public_verify_document(
    db: Annotated[Session, Depends(get_db)],
    t: str = Query(..., description="JWT from POST /documents/{id}/verify-link"),
) -> DocumentVerifyResult:
    try:
        doc_id = decode_public_verify_token(t)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return run_document_verify(db, doc, actor_user_id=None, log_activity_events=True)


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


@app.post("/admin/retention/apply", response_model=RetentionApplyOut, tags=["Admin"])
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


@app.get("/admin/users", response_model=list[UserOut], tags=["Admin"])
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


@app.get("/admin/users/{user_id}", response_model=UserOut, tags=["Admin"])
def admin_get_user(
    user_id: int,
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut.model_validate(target)


@app.post(
    "/admin/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Admin"],
)
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


@app.patch("/admin/users/{user_id}", response_model=UserOut, tags=["Admin"])
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


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Admin"])
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


@app.patch("/admin/users/{user_id}/role", response_model=UserOut, tags=["Admin"])
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


@app.get("/health", tags=["Health"])
def health_liveness() -> dict[str, str]:
    """Process is up (Kubernetes liveness)."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["Health"])
def health_readiness(db: Annotated[Session, Depends(get_db)]) -> dict:
    """Database connectivity and optional ``ETH_RPC_URL`` JSON-RPC probe (readiness)."""
    overall, checks = aggregate_readiness(db)
    code = status.HTTP_200_OK
    if overall != "ok":
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=code,
        content={"status": overall, "checks": checks},
    )
