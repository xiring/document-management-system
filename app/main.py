from contextlib import asynccontextmanager
from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.orm import Session

load_dotenv()

from app.auth import create_access_token, get_current_user, hash_password, verify_password
from app.config import settings
from app.database import Base, engine, ensure_users_role_column, get_db, promote_bootstrap_admin_if_configured
from app.models import Document, User
from app.blockchain_service import get_on_chain_owner, is_notarization_configured, notarize_hash
from app.permissions import RequirePermission, can_access_document, has_permission
from app.roles import Role, normalize_role
from app.schemas import (
    AdminUserCreate,
    AdminUserUpdate,
    DocumentOut,
    DocumentVerifyResult,
    Token,
    UserCreate,
    UserOut,
    UserRoleUpdate,
)
from app.services.storage import read_stored_file, save_upload, sha256_bytes


def document_to_out(doc: Document) -> DocumentOut:
    return DocumentOut(
        id=doc.id,
        filename=doc.filename,
        owner_id=doc.owner_id,
        upload_date=doc.upload_date,
        storage_uri=doc.storage_uri,
        content_sha256_hex=doc.file_hash.hex()
        if isinstance(doc.file_hash, (bytes, bytearray))
        else str(doc.file_hash),
        blockchain_tx_hash=doc.blockchain_tx_hash,
        version=doc.version,
        previous_version_id=doc.previous_version_id,
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_users_role_column()
    promote_bootstrap_admin_if_configured()
    yield


app = FastAPI(title="DMS", lifespan=lifespan)


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
) -> DocumentOut:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    storage_uri, digest = save_upload(content, file.filename or "unnamed")
    tx_hash = notarize_hash(digest)
    doc = Document(
        filename=file.filename or "unnamed",
        owner_id=current_user.id,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=tx_hash,
        version=1,
        previous_version_id=None,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return document_to_out(doc)


@app.get("/documents", response_model=list[DocumentOut])
def list_documents(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[DocumentOut]:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if has_permission(current_user, "documents:read_all"):
        rows = db.execute(select(Document)).scalars().all()
    else:
        rows = (
            db.execute(select(Document).where(Document.owner_id == current_user.id)).scalars().all()
        )
    return [document_to_out(d) for d in rows]


@app.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentOut:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    doc = db.get(Document, document_id)
    if doc is None or not can_access_document(current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    return document_to_out(doc)


@app.post("/documents/{document_id}/versions", response_model=DocumentOut)
async def upload_new_version(
    document_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
) -> DocumentOut:
    parent = db.get(Document, document_id)
    if parent is None or parent.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    storage_uri, digest = save_upload(content, file.filename or parent.filename)
    tx_hash = notarize_hash(digest)
    new_doc = Document(
        filename=file.filename or parent.filename,
        owner_id=current_user.id,
        storage_uri=storage_uri,
        file_hash=digest,
        blockchain_tx_hash=tx_hash,
        version=parent.version + 1,
        previous_version_id=parent.id,
    )
    db.add(new_doc)
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
) -> DocumentVerifyResult:
    doc = db.get(Document, document_id)
    if doc is None or not can_access_document(current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    successor_id = _newer_version_document_id(db, doc)
    is_latest = successor_id is None
    configured = is_notarization_configured()

    try:
        raw = read_stored_file(doc.storage_uri)
    except FileNotFoundError:
        stored_hex = doc.file_hash.hex() if isinstance(doc.file_hash, (bytes, bytearray)) else None
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
        select(func.count()).select_from(Document).where(Document.owner_id == user_id)
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
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
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
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@app.patch("/admin/users/{user_id}", response_model=UserOut)
def admin_update_user(
    user_id: int,
    body: AdminUserUpdate,
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
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
    db.delete(target)
    db.commit()


@app.patch("/admin/users/{user_id}/role", response_model=UserOut)
def admin_set_user_role(
    user_id: int,
    body: UserRoleUpdate,
    _: Annotated[User, Depends(RequirePermission("users:manage"))],
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    _assert_can_change_admin_role(db, target, body.role)
    target.role = body.role
    db.commit()
    db.refresh(target)
    return UserOut.model_validate(target)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
