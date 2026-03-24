"""Liveness / readiness checks (database, optional JSON-RPC)."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.blockchain_service import w3_for_rpc
from app.config import settings


def check_database(db: Session) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        return {"status": "error", "detail": str(e)}
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {"status": "ok", "latency_ms": round(elapsed_ms, 2)}


def check_eth_rpc() -> dict[str, Any]:
    url = (settings.eth_rpc_url or "").strip()
    if not url:
        return {"status": "skipped", "detail": "ETH_RPC_URL not set"}
    start = time.perf_counter()
    try:
        w3 = w3_for_rpc(url)
        if w3 is None or not w3.is_connected():
            return {"status": "error", "detail": "RPC not reachable"}
        block = w3.eth.block_number
    except Exception as e:
        return {"status": "error", "detail": str(e)}
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {
        "status": "ok",
        "latency_ms": round(elapsed_ms, 2),
        "block_number": int(block),
    }


def aggregate_readiness(db: Session) -> tuple[str, dict[str, Any]]:
    """
    Returns (overall_status, checks) where overall is ``ok`` or ``degraded``.

    Database failure or RPC failure (when ``ETH_RPC_URL`` is set) yields ``degraded``.
    """
    checks: dict[str, Any] = {
        "database": check_database(db),
        "eth_rpc": check_eth_rpc(),
    }
    if checks["database"].get("status") != "ok":
        return "degraded", checks
    rpc = checks["eth_rpc"]
    if rpc["status"] == "error":
        return "degraded", checks
    return "ok", checks
