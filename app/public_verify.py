"""Stateless JWT for public document verification links (no login)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from app.config import settings


def _secret() -> str:
    s = (settings.public_verify_secret or "").strip()
    return s or settings.jwt_secret_key


def create_public_verify_token(document_id: int, expires_hours: int | None = None) -> tuple[str, int]:
    hours = expires_hours if expires_hours is not None else settings.public_verify_token_hours
    exp = datetime.now(timezone.utc) + timedelta(hours=hours)
    payload = {"typ": "pv", "doc": document_id, "exp": exp}
    token = jwt.encode(payload, _secret(), algorithm=settings.jwt_algorithm)
    return token, hours


def decode_public_verify_token(token: str) -> int:
    try:
        payload = jwt.decode(token, _secret(), algorithms=[settings.jwt_algorithm])
    except JWTError as e:
        raise ValueError("invalid or expired token") from e
    if payload.get("typ") != "pv":
        raise ValueError("wrong token type")
    return int(payload["doc"])
