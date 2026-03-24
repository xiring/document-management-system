"""Per-tenant chain endpoints and periodic Merkle batch commit."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.activity_log import ActivityAction, log_activity
from app.blockchain_service import commit_merkle_root_ctx, is_merkle_batch_configured_for_context
from app.chain_resolution import chain_context_from_db
from app.database import get_db
from app.merkle import merkle_root as build_merkle_root
from app.models import ChainConfig, Document, MerkleBatch, User
from app.permissions import RequirePermission
from app.schemas import ChainConfigCreate, ChainConfigOut, ChainConfigUpdate, MerkleCommitOut

router = APIRouter(prefix="/chain-configs", tags=["Chain configs"])


def _get_owned_config(db: Session, config_id: int, user_id: int) -> ChainConfig:
    cc = db.get(ChainConfig, config_id)
    if cc is None or cc.owner_id != user_id:
        raise HTTPException(status_code=404, detail="Chain config not found")
    return cc


@router.get("", response_model=list[ChainConfigOut])
def list_chain_configs(
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> list[ChainConfigOut]:
    rows = db.execute(
        select(ChainConfig).where(ChainConfig.owner_id == current_user.id).order_by(ChainConfig.id)
    ).scalars().all()
    return list(rows)


@router.post("", response_model=ChainConfigOut, status_code=status.HTTP_201_CREATED)
def create_chain_config(
    body: ChainConfigCreate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> ChainConfig:
    cc = ChainConfig(
        owner_id=current_user.id,
        name=body.name.strip(),
        rpc_url=body.rpc_url.strip(),
        chain_id=body.chain_id,
        document_contract_address=body.document_contract_address.strip(),
        batch_contract_address=(body.batch_contract_address or "").strip() or None,
    )
    db.add(cc)
    db.commit()
    db.refresh(cc)
    return cc


@router.patch("/{config_id}", response_model=ChainConfigOut)
def update_chain_config(
    config_id: int,
    body: ChainConfigUpdate,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> ChainConfig:
    cc = _get_owned_config(db, config_id, current_user.id)
    if body.name is not None:
        cc.name = body.name.strip()
    if body.rpc_url is not None:
        cc.rpc_url = body.rpc_url.strip()
    if body.chain_id is not None:
        cc.chain_id = body.chain_id
    if body.document_contract_address is not None:
        cc.document_contract_address = body.document_contract_address.strip()
    if body.batch_contract_address is not None:
        cc.batch_contract_address = body.batch_contract_address.strip() or None
    db.commit()
    db.refresh(cc)
    return cc


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_chain_config(
    config_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    cc = _get_owned_config(db, config_id, current_user.id)
    n = db.execute(
        select(func.count()).select_from(Document).where(Document.chain_config_id == config_id)
    ).scalar_one()
    if int(n) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Documents still reference this chain config; reassign or remove them first.",
        )
    db.delete(cc)
    db.commit()


@router.post("/{config_id}/merkle/commit", response_model=MerkleCommitOut)
def commit_merkle_batch(
    config_id: int,
    current_user: Annotated[User, Depends(RequirePermission("documents:write"))],
    db: Annotated[Session, Depends(get_db)],
    max_documents: int = Query(default=500, ge=1, le=5000),
) -> MerkleCommitOut:
    cc = _get_owned_config(db, config_id, current_user.id)
    ctx = chain_context_from_db(cc)
    if not is_merkle_batch_configured_for_context(ctx):
        raise HTTPException(
            status_code=400,
            detail="Batch contract not configured for this chain (set batch_contract_address and PRIVATE_KEY).",
        )
    docs = (
        db.execute(
            select(Document)
            .where(
                Document.chain_config_id == config_id,
                Document.owner_id == current_user.id,
                Document.pending_merkle.is_(True),
                Document.merkle_batch_id.is_(None),
                Document.deleted_at.is_(None),
            )
            .limit(max_documents)
        )
        .scalars()
        .all()
    )
    if not docs:
        raise HTTPException(status_code=400, detail="No pending documents to batch for this chain config.")
    leaves = [d.file_hash for d in docs]
    root = build_merkle_root(leaves)
    tx = commit_merkle_root_ctx(ctx, root)
    if not tx:
        raise HTTPException(
            status_code=502,
            detail="Failed to submit Merkle root transaction (RPC or signing error).",
        )
    batch = MerkleBatch(
        chain_config_id=cc.id,
        merkle_root=root,
        tx_hash=tx,
        leaf_count=len(docs),
    )
    db.add(batch)
    db.flush()
    for d in docs:
        d.merkle_batch_id = batch.id
        d.pending_merkle = False
    log_activity(
        db,
        actor_user_id=current_user.id,
        action=ActivityAction.MERKLE_BATCH_COMMITTED,
        payload={
            "batch_id": batch.id,
            "leaf_count": len(docs),
            "merkle_root_hex": root.hex(),
            "tx_hash": tx,
            "chain_config_id": cc.id,
        },
    )
    db.commit()
    db.refresh(batch)
    return MerkleCommitOut(
        batch_id=batch.id,
        merkle_root_hex=root.hex(),
        tx_hash=tx,
        leaf_count=len(docs),
    )
