"""Sorted-leaves binary Merkle tree (OpenZeppelin-style pair hashing)."""

from __future__ import annotations

from web3 import Web3


def _pair_hash(a: bytes, b: bytes) -> bytes:
    if len(a) != 32 or len(b) != 32:
        raise ValueError("pair_hash expects two bytes32 values")
    if a < b:
        return Web3.solidity_keccak(["bytes32", "bytes32"], [a, b])
    return Web3.solidity_keccak(["bytes32", "bytes32"], [b, a])


def merkle_root(leaves: list[bytes]) -> bytes:
    """Deterministic root from sorted SHA-256 hashes (each 32 bytes)."""
    if not leaves:
        raise ValueError("no leaves")
    for h in leaves:
        if len(h) != 32:
            raise ValueError("each leaf must be 32 bytes")
    layer = sorted(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer = layer + [layer[-1]]
        layer = [_pair_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(leaves: list[bytes], leaf: bytes) -> tuple[bytes, list[bytes]]:
    """Return (root, proof) for `leaf` using the same tree rules as `merkle_root`."""
    for h in leaves:
        if len(h) != 32:
            raise ValueError("each leaf must be 32 bytes")
    if len(leaf) != 32:
        raise ValueError("leaf must be 32 bytes")
    layer = sorted(leaves)
    if leaf not in layer:
        raise ValueError("leaf not in leaves set")
    if len(layer) == 1:
        return layer[0], []

    idx = layer.index(leaf)
    proof: list[bytes] = []
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer = layer + [layer[-1]]
        sibling_idx = idx ^ 1
        proof.append(layer[sibling_idx])
        new_layer = []
        for i in range(0, len(layer), 2):
            new_layer.append(_pair_hash(layer[i], layer[i + 1]))
        idx = idx // 2
        layer = new_layer
    return layer[0], proof


def verify_proof(root: bytes, leaf: bytes, proof: list[bytes]) -> bool:
    """Check that `leaf` with `proof` resolves to `root`."""
    if len(leaf) != 32 or len(root) != 32:
        return False
    cur = leaf
    for sib in proof:
        if len(sib) != 32:
            return False
        cur = _pair_hash(cur, sib)
    return cur == root
