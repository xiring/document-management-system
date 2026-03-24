"""Serialize Document ORM → DocumentOut (shared by API routers)."""

from app.models import Document
from app.schemas import DocumentOut


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
        chain_config_id=doc.chain_config_id,
        merkle_batch_id=doc.merkle_batch_id,
        pending_merkle=bool(doc.pending_merkle),
        lifecycle_state=doc.lifecycle_state,
    )
