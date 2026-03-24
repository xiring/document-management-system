from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Collection, Document, Folder, Tag, User
from app.permissions import has_permission
from app.schemas import (
    CollectionCreate,
    CollectionOut,
    CollectionUpdate,
    DocumentTreeResponse,
    DocumentTreeSummary,
    FolderCreate,
    FolderOut,
    FolderTreeNode,
    TagCreate,
    TagOut,
)

folder_router = APIRouter(prefix="/folders", tags=["Folders"])
tag_router = APIRouter(prefix="/tags", tags=["Tags"])
collection_router = APIRouter(prefix="/collections", tags=["Collections"])


def _read_all(user: User) -> bool:
    return has_permission(user, "documents:read_all")


def _build_document_tree(owner_id: int, folders: list[Folder], documents: list[Document]) -> DocumentTreeResponse:
    by_parent: dict[int | None, list[Folder]] = defaultdict(list)
    fby = {f.id: f for f in folders}
    for f in folders:
        by_parent[f.parent_id].append(f)
    for k in by_parent:
        by_parent[k].sort(key=lambda x: (x.name.lower(), x.id))

    docs_by_folder: dict[int | None, list[Document]] = defaultdict(list)
    for d in documents:
        docs_by_folder[d.folder_id].append(d)
    for k in docs_by_folder:
        docs_by_folder[k].sort(key=lambda x: (x.filename.lower(), x.id))

    def make_node(fid: int) -> FolderTreeNode:
        f = fby[fid]
        child_folders = by_parent.get(f.id, [])
        children = [make_node(c.id) for c in child_folders]
        docs = [
            DocumentTreeSummary(
                id=d.id,
                filename=d.filename,
                version=d.version,
                upload_date=d.upload_date,
            )
            for d in docs_by_folder.get(f.id, [])
        ]
        return FolderTreeNode(
            id=f.id,
            owner_id=f.owner_id,
            parent_id=f.parent_id,
            name=f.name,
            children=children,
            documents=docs,
        )

    roots = [make_node(r.id) for r in by_parent.get(None, [])]
    orphans = [
        DocumentTreeSummary(
            id=d.id,
            filename=d.filename,
            version=d.version,
            upload_date=d.upload_date,
        )
        for d in docs_by_folder.get(None, [])
    ]
    return DocumentTreeResponse(owner_id=owner_id, roots=roots, orphan_documents=orphans)


@folder_router.get("", response_model=list[FolderOut])
def list_folders(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FolderOut]:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if _read_all(current_user):
        rows = db.execute(select(Folder).order_by(Folder.name)).scalars().all()
    else:
        rows = (
            db.execute(select(Folder).where(Folder.owner_id == current_user.id).order_by(Folder.name))
            .scalars()
            .all()
        )
    return [FolderOut.model_validate(f) for f in rows]


@folder_router.get("/tree", response_model=DocumentTreeResponse)
def get_document_tree(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    owner_id: int | None = Query(
        default=None,
        description="Tree for this user (defaults to you). Managers/admins may set another owner_id.",
    ),
) -> DocumentTreeResponse:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if owner_id is None:
        effective_owner = current_user.id
    elif not _read_all(current_user):
        if owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="owner_id requires documents:read_all or must match your user id.",
            )
        effective_owner = owner_id
    else:
        effective_owner = owner_id

    folders = db.execute(
        select(Folder).where(Folder.owner_id == effective_owner).order_by(Folder.name)
    ).scalars().all()
    documents = db.execute(
        select(Document)
        .where(Document.owner_id == effective_owner, Document.deleted_at.is_(None))
        .order_by(Document.filename)
    ).scalars().all()
    return _build_document_tree(effective_owner, list(folders), list(documents))


@folder_router.post("", response_model=FolderOut, status_code=status.HTTP_201_CREATED)
def create_folder(
    body: FolderCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> FolderOut:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    name = body.name.strip()
    parent_id = body.parent_id
    if parent_id is not None:
        p = db.get(Folder, parent_id)
        if p is None or p.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Parent folder not found")
    stmt = select(Folder).where(Folder.owner_id == current_user.id, Folder.name == name)
    if parent_id is None:
        stmt = stmt.where(Folder.parent_id.is_(None))
    else:
        stmt = stmt.where(Folder.parent_id == parent_id)
    existing = db.execute(stmt).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="A folder with this name already exists under this parent")
    f = Folder(owner_id=current_user.id, parent_id=parent_id, name=name)
    db.add(f)
    db.commit()
    db.refresh(f)
    return FolderOut.model_validate(f)


@folder_router.get("/{folder_id}", response_model=FolderOut)
def get_folder(
    folder_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> FolderOut:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    f = db.get(Folder, folder_id)
    if f is None or (not _read_all(current_user) and f.owner_id != current_user.id):
        raise HTTPException(status_code=404, detail="Folder not found")
    return FolderOut.model_validate(f)


@folder_router.delete("/{folder_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_folder(
    folder_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    f = db.get(Folder, folder_id)
    if f is None or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Folder not found")
    n = db.execute(
        select(func.count()).select_from(Document).where(Document.folder_id == folder_id)
    ).scalar_one()
    if int(n) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Folder still contains documents; move or remove them first.",
        )
    ns = db.execute(
        select(func.count()).select_from(Folder).where(Folder.parent_id == folder_id)
    ).scalar_one()
    if int(ns) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Folder still contains subfolders; delete or move them first.",
        )
    db.delete(f)
    db.commit()


# --- Tags ---


@tag_router.get("", response_model=list[TagOut])
def list_tags(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[TagOut]:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if _read_all(current_user):
        rows = db.execute(select(Tag).order_by(Tag.name)).scalars().all()
    else:
        rows = (
            db.execute(select(Tag).where(Tag.owner_id == current_user.id).order_by(Tag.name)).scalars().all()
        )
    return [TagOut.model_validate(t) for t in rows]


@tag_router.post("", response_model=TagOut, status_code=status.HTTP_201_CREATED)
def create_tag(
    body: TagCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> TagOut:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    name = body.name.strip()
    existing = db.execute(
        select(Tag).where(Tag.owner_id == current_user.id, Tag.name == name)
    ).scalar_one_or_none()
    if existing:
        return TagOut.model_validate(existing)
    t = Tag(owner_id=current_user.id, name=name)
    db.add(t)
    db.commit()
    db.refresh(t)
    return TagOut.model_validate(t)


@tag_router.delete("/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tag(
    tag_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    t = db.get(Tag, tag_id)
    if t is None or t.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Tag not found")
    db.delete(t)
    db.commit()


# --- Collections ---


@collection_router.get("", response_model=list[CollectionOut])
def list_collections(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[CollectionOut]:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    if _read_all(current_user):
        rows = db.execute(select(Collection).order_by(Collection.name)).scalars().all()
    else:
        rows = (
            db.execute(
                select(Collection)
                .where(Collection.owner_id == current_user.id)
                .order_by(Collection.name)
            )
            .scalars()
            .all()
        )
    return [CollectionOut.model_validate(c) for c in rows]


@collection_router.post("", response_model=CollectionOut, status_code=status.HTTP_201_CREATED)
def create_collection(
    body: CollectionCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> CollectionOut:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    name = body.name.strip()
    existing = db.execute(
        select(Collection).where(Collection.owner_id == current_user.id, Collection.name == name)
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="A collection with this name already exists")
    desc = body.description.strip() if body.description else None
    c = Collection(owner_id=current_user.id, name=name, description=desc)
    db.add(c)
    db.commit()
    db.refresh(c)
    return CollectionOut.model_validate(c)


@collection_router.get("/{collection_id}", response_model=CollectionOut)
def get_collection(
    collection_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> CollectionOut:
    if not has_permission(current_user, "documents:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:read")
    c = db.get(Collection, collection_id)
    if c is None or (not _read_all(current_user) and c.owner_id != current_user.id):
        raise HTTPException(status_code=404, detail="Collection not found")
    return CollectionOut.model_validate(c)


@collection_router.patch("/{collection_id}", response_model=CollectionOut)
def update_collection(
    collection_id: int,
    body: CollectionUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> CollectionOut:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    c = db.get(Collection, collection_id)
    if c is None or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    if body.name is not None:
        c.name = body.name.strip()
    if body.description is not None:
        c.description = body.description.strip() if body.description else None
    db.commit()
    db.refresh(c)
    return CollectionOut.model_validate(c)


@collection_router.delete("/{collection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_collection(
    collection_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    c = db.get(Collection, collection_id)
    if c is None or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    db.delete(c)
    db.commit()


@collection_router.post("/{collection_id}/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def add_document_to_collection(
    collection_id: int,
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    c = db.get(Collection, collection_id)
    doc = db.get(Document, document_id)
    if c is None or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc not in c.documents:
        c.documents.append(doc)
        db.commit()


@collection_router.delete("/{collection_id}/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_document_from_collection(
    collection_id: int,
    document_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    if not has_permission(current_user, "documents:write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing permission: documents:write")
    c = db.get(Collection, collection_id)
    doc = db.get(Document, document_id)
    if c is None or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc in c.documents:
        c.documents.remove(doc)
        db.commit()
