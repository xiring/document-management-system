"""Shared document verification (disk hash, per-doc notary, Merkle batch)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.activity_log import ActivityAction, log_activity
from app.blockchain_service import (
    get_on_chain_owner_ctx,
    is_merkle_batch_configured_for_context,
    is_merkle_root_committed_ctx,
    is_notarization_configured_for_context,
)
from app.chain_resolution import resolve_chain_context
from app.merkle import merkle_proof, merkle_root, verify_proof
from app.models import Document, MerkleBatch
from app.schemas import DocumentVerifyResult
from app.services.storage import read_stored_file, sha256_bytes


def _newer_version_document_id(db: Session, doc: Document) -> int | None:
    return db.execute(
        select(Document.id).where(
            Document.previous_version_id == doc.id,
            Document.owner_id == doc.owner_id,
        ).limit(1)
    ).scalar_one_or_none()


def run_document_verify(
    db: Session,
    doc: Document,
    *,
    actor_user_id: int | None,
    log_activity_events: bool = True,
) -> DocumentVerifyResult:
    successor_id = _newer_version_document_id(db, doc)
    is_latest = successor_id is None
    ctx = resolve_chain_context(db, doc)
    chain_id_out = ctx.chain_id if ctx else None

    try:
        raw = read_stored_file(doc.storage_uri)
    except FileNotFoundError:
        stored_hex = doc.file_hash.hex() if isinstance(doc.file_hash, (bytes, bytearray)) else None
        if log_activity_events:
            log_activity(
                db,
                actor_user_id=actor_user_id,
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
            notarization_configured=is_notarization_configured_for_context(ctx)
            or is_merkle_batch_configured_for_context(ctx),
            is_latest_version=is_latest,
            newer_version_document_id=successor_id,
            message="Stored file missing; cannot recompute content hash from disk.",
            chain_id=chain_id_out,
            merkle_batch_id=doc.merkle_batch_id,
            merkle_root_hex=None,
            merkle_root_on_chain=None,
            merkle_proof_valid=None,
        )

    current_hash = sha256_bytes(raw)
    stored_hex = doc.file_hash.hex() if isinstance(doc.file_hash, (bytes, bytearray)) else ""
    computed_hex = current_hash.hex()
    matches_record = current_hash == doc.file_hash

    parts: list[str] = []
    if matches_record:
        parts.append("SHA-256 of file bytes on disk matches the content hash stored at upload.")
    else:
        parts.append("SHA-256 of file bytes on disk does not match stored content hash (file was altered).")

    if successor_id is not None:
        parts.append(
            f"This row is not the latest version — verify document_id={successor_id} for the newest upload."
        )

    matches_chain: bool | None = None
    merkle_root_hex: str | None = None
    merkle_root_on_chain: bool | None = None
    merkle_proof_valid: bool | None = None

    if doc.merkle_batch_id is not None:
        batch = db.get(MerkleBatch, doc.merkle_batch_id)
        batch_cfg = is_merkle_batch_configured_for_context(ctx)
        if batch is None:
            parts.append("Merkle batch record missing for this document.")
            matches_chain = None
        else:
            merkle_root_hex = batch.merkle_root.hex()
            rows = db.execute(
                select(Document.file_hash).where(Document.merkle_batch_id == batch.id)
            ).all()
            leaves = [r[0] for r in rows]
            try:
                computed = merkle_root(leaves)
            except ValueError:
                computed = b""
            root_matches_db = computed == batch.merkle_root
            try:
                proof_root, proof = merkle_proof(leaves, doc.file_hash)
            except ValueError:
                proof_root, proof = b"", []
            merkle_proof_valid = root_matches_db and verify_proof(proof_root, doc.file_hash, proof) and proof_root == batch.merkle_root
            merkle_root_on_chain = is_merkle_root_committed_ctx(ctx, batch.merkle_root) if ctx else False
            if not batch_cfg:
                matches_chain = None
                parts.append(
                    "Merkle batch verification needs BatchNotary RPC, batch contract, and PRIVATE_KEY."
                )
            elif not merkle_root_on_chain:
                matches_chain = False
                parts.append("Merkle root is not committed on-chain yet (or wrong network / contract).")
            elif merkle_proof_valid:
                matches_chain = matches_record
                if matches_record:
                    parts.append("Merkle proof matches batch root; root is committed on-chain.")
                else:
                    parts.append("Merkle proof is valid but file bytes no longer match the batched hash.")
            else:
                matches_chain = False
                parts.append("Merkle proof does not match the stored batch root.")

    elif doc.pending_merkle and doc.merkle_batch_id is None:
        matches_chain = None
        parts.append("Document is queued for periodic Merkle batch notarization (not anchored yet).")

    elif not is_notarization_configured_for_context(ctx):
        matches_chain = None
        parts.append(
            "On-chain proof is unavailable: configure chain (or ChainConfig) with RPC, contract, and PRIVATE_KEY."
        )
    elif doc.blockchain_tx_hash is None:
        matches_chain = None
        parts.append(
            "No per-document notarization transaction was stored (batch mode or skipped at upload)."
        )
    else:
        chain_owner = get_on_chain_owner_ctx(ctx, doc.file_hash) if ctx else None
        if chain_owner is None:
            matches_chain = False
            parts.append(
                "Could not read document owner on-chain (wrong network, contract address, or RPC)."
            )
        else:
            matches_chain = matches_record
            if matches_record:
                parts.append("The stored hash is registered on-chain (per-document notary).")
            else:
                parts.append("The file no longer matches the hash that was notarized on-chain.")

    if log_activity_events:
        log_activity(
            db,
            actor_user_id=actor_user_id,
            action=ActivityAction.DOCUMENT_VERIFY,
            document_id=doc.id,
            payload={
                "outcome": "ok",
                "content_matches_stored_hash": matches_record,
                "content_hash_matches_blockchain": matches_chain,
                "is_latest_version": is_latest,
                "newer_version_document_id": successor_id,
                "merkle_batch_id": doc.merkle_batch_id,
            },
        )
        db.commit()

    return DocumentVerifyResult(
        document_id=doc.id,
        content_matches_stored_hash=matches_record,
        content_hash_matches_blockchain=matches_chain,
        stored_content_sha256_hex=stored_hex,
        computed_content_sha256_hex=computed_hex,
        notarization_configured=is_notarization_configured_for_context(ctx)
        or is_merkle_batch_configured_for_context(ctx),
        is_latest_version=is_latest,
        newer_version_document_id=successor_id,
        message=" ".join(parts),
        chain_id=chain_id_out,
        merkle_batch_id=doc.merkle_batch_id,
        merkle_root_hex=merkle_root_hex,
        merkle_root_on_chain=merkle_root_on_chain,
        merkle_proof_valid=merkle_proof_valid,
    )
