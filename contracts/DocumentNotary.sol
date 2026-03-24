// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DocumentNotary — proof-of-existence: SHA-256 hash -> notary owner address
contract DocumentNotary {
    mapping(bytes32 => address) public documentOwner;

    event DocumentNotarized(bytes32 indexed hash, address indexed owner);

    /// @notice Register a document hash once; owner is typically the backend hot wallet or end-user wallet.
    function notarize(bytes32 hash, address owner) external {
        require(documentOwner[hash] == address(0), "Already notarized");
        require(owner != address(0), "Invalid owner");
        documentOwner[hash] = owner;
        emit DocumentNotarized(hash, owner);
    }
}
