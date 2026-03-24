// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BatchNotary — periodic Merkle root commitment for many document hashes (gas savings vs per-hash notarize).
contract BatchNotary {
    mapping(bytes32 => bool) public committedRoots;

    event RootCommitted(bytes32 indexed root, address indexed committer);

    function commitRoot(bytes32 root) external {
        require(!committedRoots[root], "root exists");
        require(root != bytes32(0), "empty root");
        committedRoots[root] = true;
        emit RootCommitted(root, msg.sender);
    }
}
