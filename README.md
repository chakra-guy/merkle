# Merkle Tree Implementation

## Overview

This package provides an implementation of a Merkle Tree data structure in Go.

A Merkle Tree is a binary tree where each leaf node contains the hash of a data block, and each non-leaf node contains the hash of its children's hashes. This structure allows for efficient and secure verification of large data structures.

Key characteristics of Merkle Trees:

1. Hierarchical Structure: Organized as a binary tree of hashes.
2. Data Integrity: Allows verification of data integrity with minimal information exchange.
3. Efficient Proofs: Enables generation and verification of membership proofs with logarithmic complexity.
4. Tamper Evidence: Any change in the data is reflected in the root hash, making tampering evident.

Use-cases:

- Blockchain technologies, distributed file systems, peer-to-peer networks, version control systems, database systems for data verification

## Notes on the Implementation

The hash function can be configured when the data structure is instantiated, as long as it implements the `hash.Hash` interface. 

For testing purposes I created a mockHash function, that I found to be quite handy, as it returns with a human readable  "hash": `hash(hash(c)hash(d))`. That can be found in the `merkle_test.go` file.