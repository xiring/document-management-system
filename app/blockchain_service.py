import logging
import os
from typing import Any

from web3 import Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from app.chain_resolution import ChainContext, default_chain_context
from app.config import settings

logger = logging.getLogger(__name__)

# Minimal ABI for DocumentNotary.sol (notarize + documentOwner mapping reader)
NOTARY_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "hash", "type": "bytes32"},
            {"internalType": "address", "name": "owner", "type": "address"},
        ],
        "name": "notarize",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "documentOwner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]

BATCH_NOTARY_ABI: list[dict[str, Any]] = [
    {
        "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
        "name": "commitRoot",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "committedRoots",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def _private_key() -> str:
    """Prefer PRIVATE_KEY from the environment — never hardcode secrets in source."""
    key = os.getenv("PRIVATE_KEY") or settings.private_key
    if not key:
        return ""
    return key.strip()


def is_notarization_configured() -> bool:
    """True when global RPC, contract, and private key are set so notarization can run."""
    return bool(settings.eth_rpc_url and settings.contract_address and _private_key())


def is_notarization_configured_for_context(ctx: ChainContext | None) -> bool:
    """Whether per-document notarization (documentOwner / notarize) can run for this chain context."""
    if ctx is None:
        return False
    return bool(_private_key() and ctx.rpc_url and ctx.document_contract)


def is_merkle_batch_configured_for_context(ctx: ChainContext | None) -> bool:
    if ctx is None:
        return False
    return bool(_private_key() and ctx.rpc_url and ctx.batch_contract)


def w3_for_rpc(rpc_url: str) -> Web3 | None:
    if not rpc_url:
        return None
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    return w3 if w3.is_connected() else None


def _document_contract(w3: Web3, address: str) -> Contract:
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=NOTARY_ABI)


def _batch_contract(w3: Web3, address: str) -> Contract:
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=BATCH_NOTARY_ABI)


def _send_contract_tx(w3: Web3, build, chain_id: int) -> str:
    pk = _private_key()
    if not pk:
        raise RuntimeError("PRIVATE_KEY required for chain transactions")
    account = w3.eth.account.from_key(pk)
    nonce = w3.eth.get_transaction_count(account.address)
    tx = build(account.address, nonce, chain_id)
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)
    latest = w3.eth.get_block("latest")
    base = latest.get("baseFeePerGas")
    if base is not None:
        priority = w3.eth.max_priority_fee
        if priority is None:
            priority = Web3.to_wei(1, "gwei")
        tx["maxPriorityFeePerGas"] = priority
        tx["maxFeePerGas"] = int(base * 2 + priority)
    else:
        tx["gasPrice"] = w3.eth.gas_price

    signed = w3.eth.account.sign_transaction(tx, private_key=pk)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None)
    if raw is None:
        raise RuntimeError("Signed transaction missing raw bytes")
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
    return Web3.to_hex(receipt["transactionHash"])


def notarize_hash_ctx(ctx: ChainContext, file_hash: bytes, owner_address: str | None = None) -> str | None:
    """Submit file_hash to the document notary contract for this chain context."""
    pk = _private_key()
    w3 = w3_for_rpc(ctx.rpc_url)
    if not pk or not w3:
        return None
    contract = _document_contract(w3, ctx.document_contract)
    account = w3.eth.account.from_key(pk)
    owner = owner_address or account.address
    checksum_owner = Web3.to_checksum_address(owner)
    h32 = file_hash if len(file_hash) == 32 else bytes.fromhex(file_hash.hex())[:32]
    if len(h32) != 32:
        raise ValueError("file_hash must be 32 bytes (SHA-256)")

    def build(from_addr: str, nonce: int, chain_id: int):
        return contract.functions.notarize(h32, checksum_owner).build_transaction(
            {"from": from_addr, "nonce": nonce, "chainId": chain_id}
        )

    return _send_contract_tx(w3, build, ctx.chain_id)


def notarize_hash(file_hash: bytes, owner_address: str | None = None) -> str | None:
    """Global default chain (settings)."""
    ctx = default_chain_context()
    if ctx is None:
        return None
    return notarize_hash_ctx(ctx, file_hash, owner_address)


def get_on_chain_owner_ctx(ctx: ChainContext, file_hash: bytes) -> str | None:
    w3 = w3_for_rpc(ctx.rpc_url)
    if not w3:
        return None
    contract = _document_contract(w3, ctx.document_contract)
    h32 = file_hash if len(file_hash) == 32 else bytes.fromhex(file_hash.hex())[:32]
    try:
        addr = contract.functions.documentOwner(h32).call()
    except (BadFunctionCallOutput, ContractLogicError, ValueError, OSError) as e:
        logger.warning("documentOwner call failed (check contract / CHAIN_ID / RPC): %s", e)
        return None
    if addr == "0x0000000000000000000000000000000000000000":
        return None
    return Web3.to_checksum_address(addr)


def get_on_chain_owner(file_hash: bytes) -> str | None:
    ctx = default_chain_context()
    if ctx is None:
        return None
    return get_on_chain_owner_ctx(ctx, file_hash)


def commit_merkle_root_ctx(ctx: ChainContext, root: bytes) -> str | None:
    """Submit Merkle root to BatchNotary."""
    if not ctx.batch_contract:
        return None
    if len(root) != 32:
        raise ValueError("root must be 32 bytes")
    w3 = w3_for_rpc(ctx.rpc_url)
    if not w3 or not _private_key():
        return None
    contract = _batch_contract(w3, ctx.batch_contract)

    def build(from_addr: str, nonce: int, chain_id: int):
        return contract.functions.commitRoot(root).build_transaction(
            {"from": from_addr, "nonce": nonce, "chainId": chain_id}
        )

    return _send_contract_tx(w3, build, ctx.chain_id)


def is_merkle_root_committed_ctx(ctx: ChainContext, root: bytes) -> bool:
    if not ctx.batch_contract or len(root) != 32:
        return False
    w3 = w3_for_rpc(ctx.rpc_url)
    if not w3:
        return False
    contract = _batch_contract(w3, ctx.batch_contract)
    try:
        return bool(contract.functions.committedRoots(root).call())
    except (BadFunctionCallOutput, ContractLogicError, ValueError, OSError):
        return False
