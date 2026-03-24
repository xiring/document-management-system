"""Background jobs: Merkle batch commits, virus scan hooks, outbound email."""

from __future__ import annotations

import logging

from sqlalchemy import select

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import ChainConfig, Document
from app.services.merkle_batch import commit_merkle_batch_for_config

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="dms.merkle.commit_config")
def commit_merkle_batch_task(self, chain_config_id: int, max_documents: int = 500) -> dict | None:
    """
    Commit pending Merkle batches for *all* documents on a chain config (not owner-scoped).
    Intended for periodic workers or retries after RPC outages.
    """
    db = SessionLocal()
    try:
        try:
            out = commit_merkle_batch_for_config(
                db,
                chain_config_id=chain_config_id,
                max_documents=max_documents,
                owner_id=None,
                actor_user_id=None,
            )
        except ValueError as e:
            logger.warning("Merkle commit skipped: %s", e)
            return {"error": str(e)}
        except RuntimeError as e:
            logger.exception("Merkle commit failed")
            raise self.retry(exc=e) from e
        if out is None:
            return None
        db.commit()
        return {
            "batch_id": out.batch_id,
            "leaf_count": out.leaf_count,
            "tx_hash": out.tx_hash,
        }
    finally:
        db.close()


@celery_app.task(name="dms.merkle.commit_all_pending")
def commit_all_pending_merkle_batches(max_documents: int = 500) -> list[dict]:
    """Find chain configs that have pending Merkle documents and commit each (one batch per config)."""
    db = SessionLocal()
    results: list[dict] = []
    try:
        cfg_ids = (
            db.execute(
                select(Document.chain_config_id)
                .where(
                    Document.pending_merkle.is_(True),
                    Document.merkle_batch_id.is_(None),
                    Document.deleted_at.is_(None),
                )
                .distinct()
            )
            .scalars()
            .all()
        )
        for cid in cfg_ids:
            if cid is None:
                continue
            cc = db.get(ChainConfig, cid)
            if cc is None:
                continue
            try:
                out = commit_merkle_batch_for_config(
                    db,
                    chain_config_id=cid,
                    max_documents=max_documents,
                    owner_id=None,
                    actor_user_id=None,
                )
            except (ValueError, RuntimeError) as e:
                db.rollback()
                results.append({"chain_config_id": cid, "error": str(e)})
                continue
            if out is not None:
                db.commit()
                results.append(
                    {
                        "chain_config_id": cid,
                        "batch_id": out.batch_id,
                        "leaf_count": out.leaf_count,
                        "tx_hash": out.tx_hash,
                    }
                )
            else:
                db.rollback()
        return results
    finally:
        db.close()


@celery_app.task(name="dms.document.virus_scan")
def virus_scan_document_stub(document_id: int) -> dict:
    """
    Placeholder for antivirus scanning (ClamAV, cloud scanners, etc.).

    Wire your scanner here and enqueue from upload/version handlers when ready.
    """
    logger.info("virus_scan_document_stub document_id=%s (no-op)", document_id)
    return {"document_id": document_id, "status": "skipped", "detail": "not configured"}


@celery_app.task(name="dms.email.send")
def send_email_stub(to: str, subject: str, body: str) -> dict:
    """Placeholder for transactional email (SMTP, SES, SendGrid, etc.)."""
    logger.info("send_email_stub to=%s subject=%r (no-op)", to, subject)
    return {"to": to, "status": "skipped", "detail": "not configured"}
