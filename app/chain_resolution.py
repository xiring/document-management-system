"""Resolve which RPC / contracts apply to a document (global defaults vs per-tenant ChainConfig)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.config import settings
from app.models import ChainConfig, Document


@dataclass(frozen=True)
class ChainContext:
    rpc_url: str
    chain_id: int
    document_contract: str
    batch_contract: str | None


def default_chain_context() -> ChainContext | None:
    if not settings.eth_rpc_url or not settings.contract_address:
        return None
    batch = (settings.batch_contract_address or "").strip() or None
    return ChainContext(
        rpc_url=settings.eth_rpc_url,
        chain_id=settings.chain_id,
        document_contract=settings.contract_address,
        batch_contract=batch,
    )


def chain_context_from_db(cc: ChainConfig) -> ChainContext:
    batch = (cc.batch_contract_address or "").strip() or None
    return ChainContext(
        rpc_url=cc.rpc_url,
        chain_id=cc.chain_id,
        document_contract=cc.document_contract_address,
        batch_contract=batch,
    )


def resolve_chain_context(db: Session, doc: Document) -> ChainContext | None:
    if doc.chain_config_id is not None:
        cc = db.get(ChainConfig, doc.chain_config_id)
        if cc is not None:
            return chain_context_from_db(cc)
    return default_chain_context()
