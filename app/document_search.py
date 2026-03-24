"""Build SQLAlchemy filters for document listing (substring / pg_trgm similarity)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.sql.selectable import Select

from app.models import Document


def escape_ilike_pattern(q: str) -> str:
    """Escape `%`, `_`, and `\\` for use with ILIKE ... ESCAPE '\\'."""
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_content_sha256_hex(hex_str: str) -> bytes:
    h = hex_str.strip().lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError("content_sha256_hex must be 64 hexadecimal characters")
    return bytes.fromhex(h)


def build_document_list_filters(
    *,
    read_all: bool,
    current_user_id: int,
    owner_id: int | None,
    q: str | None,
    search_mode: str,
    uploaded_after: datetime | None,
    uploaded_before: datetime | None,
    content_sha256_hex: str | None,
    version: int | None,
    version_min: int | None,
    version_max: int | None,
) -> list[Any]:
    conditions: list[Any] = []

    if not read_all:
        conditions.append(Document.owner_id == current_user_id)
    elif owner_id is not None:
        conditions.append(Document.owner_id == owner_id)

    if q is not None and (q_stripped := q.strip()):
        if search_mode == "trigram":
            # similarity() is provided by pg_trgm (see ensure_pg_trgm on startup)
            conditions.append(func.similarity(Document.filename, q_stripped) > 0.12)
        else:
            safe = escape_ilike_pattern(q_stripped)
            conditions.append(Document.filename.ilike(f"%{safe}%", escape="\\"))

    if uploaded_after is not None:
        conditions.append(Document.upload_date >= uploaded_after)
    if uploaded_before is not None:
        conditions.append(Document.upload_date <= uploaded_before)

    if content_sha256_hex is not None:
        digest = parse_content_sha256_hex(content_sha256_hex)
        conditions.append(Document.file_hash == digest)

    if version is not None:
        conditions.append(Document.version == version)
    if version_min is not None:
        conditions.append(Document.version >= version_min)
    if version_max is not None:
        conditions.append(Document.version <= version_max)

    return conditions


def apply_filters_to_select(stmt: Select[Any], conditions: list[Any]) -> Select[Any]:
    if not conditions:
        return stmt
    return stmt.where(and_(*conditions))


def document_count_query(conditions: list[Any]) -> Select[Any]:
    q = select(func.count()).select_from(Document)
    if conditions:
        q = q.where(and_(*conditions))
    return q


def document_list_query(
    conditions: list[Any],
    *,
    skip: int,
    limit: int | None,
) -> Select[Any]:
    stmt = select(Document).order_by(Document.upload_date.desc(), Document.id.desc())
    stmt = apply_filters_to_select(stmt, conditions)
    stmt = stmt.offset(skip)
    if limit is not None:
        stmt = stmt.limit(limit)
    return stmt
