"""Re-exports `blockchain_service` for the suggested `services/blockchain.py` layout."""

from app.blockchain_service import NOTARY_ABI, get_on_chain_owner, is_notarization_configured, notarize_hash

__all__ = ["NOTARY_ABI", "get_on_chain_owner", "is_notarization_configured", "notarize_hash"]
