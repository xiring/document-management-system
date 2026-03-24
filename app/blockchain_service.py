import os
from typing import Any

from web3 import Web3
from web3.contract import Contract

from app.config import settings

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


def _private_key() -> str:
    """Prefer PRIVATE_KEY from the environment — never hardcode secrets in source."""
    key = os.getenv("PRIVATE_KEY") or settings.private_key
    if not key:
        return ""
    return key.strip()


def is_notarization_configured() -> bool:
    """True when RPC, contract, and private key are set so notarization can run."""
    return bool(settings.eth_rpc_url and settings.contract_address and _private_key())


def _w3() -> Web3 | None:
    if not settings.eth_rpc_url:
        return None
    return Web3(Web3.HTTPProvider(settings.eth_rpc_url))


def _contract(w3: Web3) -> Contract | None:
    if not settings.contract_address:
        return None
    return w3.eth.contract(
        address=Web3.to_checksum_address(settings.contract_address),
        abi=NOTARY_ABI,
    )


def notarize_hash(file_hash: bytes, owner_address: str | None = None) -> str | None:
    """
    Submit file_hash (32 bytes) to the smart contract. Returns tx hash hex or None if disabled.
    """
    pk = _private_key()
    w3 = _w3()
    if not pk or not w3 or not w3.is_connected():
        return None
    contract = _contract(w3)
    if contract is None:
        return None

    account = w3.eth.account.from_key(pk)
    owner = owner_address or account.address
    checksum_owner = Web3.to_checksum_address(owner)
    h32 = file_hash if len(file_hash) == 32 else bytes.fromhex(file_hash.hex())[:32]
    if len(h32) != 32:
        raise ValueError("file_hash must be 32 bytes (SHA-256)")

    nonce = w3.eth.get_transaction_count(account.address)
    tx = contract.functions.notarize(h32, checksum_owner).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": settings.chain_id,
        }
    )
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


def get_on_chain_owner(file_hash: bytes) -> str | None:
    """Return checksummed owner address for hash, or None if unset / RPC unavailable."""
    w3 = _w3()
    if not w3 or not w3.is_connected():
        return None
    contract = _contract(w3)
    if contract is None:
        return None
    h32 = file_hash if len(file_hash) == 32 else bytes.fromhex(file_hash.hex())[:32]
    addr = contract.functions.documentOwner(h32).call()
    if addr == "0x0000000000000000000000000000000000000000":
        return None
    return Web3.to_checksum_address(addr)
