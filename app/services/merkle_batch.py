"""Commit Merkle batches for chain configs (HTTP handler and background worker)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.activity_log import ActivityAction, log_activity
from app.blockchain_service import commit_merkle_root_ctx, is_merkle_batch_configured_for_context
from app.chain_resolution import chain_context_from_db
from app.merkle import merkle_root as build_merkle_root
from app.models import ChainConfig, Document, MerkleBatch
from app.schemas import MerkleCommitOut


def commit_merkle_batch_for_config(
    db: Session,
    *,
    chain_config_id: int,
    max_documents: int,
    owner_id: int | None,
    actor_user_id: int | None,
) -> MerkleCommitOut | None:
    """
    Batch-commit pending Merkle documents for a chain config.

    When ``owner_id`` is set, only that user's documents are included (API use).
    When ``None``, all pending documents on the config are included (background job).
    """
    cc = db.get(ChainConfig, chain_config_id)
    if cc is None:
        raise ValueError("Chain config not found")
    ctx = chain_context_from_db(cc)
    if not is_merkle_batch_configured_for_context(ctx):
        raise ValueError(
            "Batch contract not configured for this chain (set batch_contract_address and PRIVATE_KEY)."
        )
    q = (
        select(Document)
        .where(
            Document.chain_config_id == chain_config_id,
            Document.pending_merkle.is_(True),
            Document.merkle_batch_id.is_(None),
            Document.deleted_at.is_(None),
        )
        .limit(max_documents)
    )
    if owner_id is not None:
        q = q.where(Document.owner_id == owner_id)
    docs = db.execute(q).scalars().all()
    if not docs:
        return None
    leaves = [d.file_hash for d in docs]
    root = build_merkle_root(leaves)
    tx = commit_merkle_root_ctx(ctx, root)
    if not tx:
        raise RuntimeError("Failed to submit Merkle root transaction (RPC or signing error).")
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
        actor_user_id=actor_user_id,
        action=ActivityAction.MERKLE_BATCH_COMMITTED,
        payload={
            "batch_id": batch.id,
            "leaf_count": len(docs),
            "merkle_root_hex": root.hex(),
            "tx_hash": tx,
            "chain_config_id": cc.id,
            "background": actor_user_id is None,
        },
    )
    return MerkleCommitOut(
        batch_id=batch.id,
        merkle_root_hex=root.hex(),
        tx_hash=tx,
        leaf_count=len(docs),
    )
