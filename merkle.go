package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
)

var (
	ErrEmptyData    = errors.New("data cannot be empty")
	ErrNotFoundData = errors.New("data not found in the tree")
)

type MerkleTree struct {
	root   *Node
	leafs  []*Node
	hashFn func() hash.Hash
}

type Node struct {
	parent *Node
	left   *Node
	right  *Node
	hash   []byte
	data   []byte
}

type Option func(*MerkleTree)

type Side int8

const (
	Left Side = iota
	Right
)

type ProofElement struct {
	Hash []byte
	Side Side
}

type Proof []ProofElement

// New creates a new Merkle tree from a list of data
func New(data [][]byte, opts ...Option) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	m := &MerkleTree{hashFn: sha256.New}

	for _, opt := range opts {
		opt(m)
	}

	for _, item := range data {
		node := &Node{
			hash: m.hash(item),
			data: item,
		}
		m.leafs = append(m.leafs, node)
	}

	m.root = m.buildTree(m.leafs)

	return m, nil
}

// WithHashFunction sets a custom hash function for the MerkleTree
func WithHashFunction(h func() hash.Hash) Option {
	return func(m *MerkleTree) {
		m.hashFn = h
	}
}

// GenerateProof generates a Merkle proof for a given leaf node
func (m *MerkleTree) GenerateProof(data []byte) (Proof, error) {
	var node *Node
	for _, leaf := range m.leafs {
		if bytes.Equal(leaf.data, data) {
			node = leaf
			break
		}
	}

	if node == nil {
		return nil, ErrNotFoundData
	}

	var proof Proof
	for node.parent != nil {
		var pe ProofElement
		if node == node.parent.left {
			pe = ProofElement{Hash: node.parent.right.hash, Side: Right}
		} else {
			pe = ProofElement{Hash: node.parent.left.hash, Side: Left}
		}
		proof = append(proof, pe)
		node = node.parent
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func (m *MerkleTree) VerifyProof(hash []byte, proof Proof) bool {
	for _, node := range proof {
		switch node.Side {
		case Left:
			hash = m.hash(append(node.Hash, hash...))
		case Right:
			hash = m.hash(append(hash, node.Hash...))
		}
	}
	return bytes.Equal(hash, m.root.hash)
}

// VerifyData verifies a Merkle proof for given data
func (m *MerkleTree) VerifyData(data []byte, proof Proof) bool {
	return m.VerifyProof(m.hash(data), proof)
}

// AddLeaf adds a new leaf node to the tree
func (m *MerkleTree) AddLeaf(data []byte) {
	node := &Node{
		hash: m.hash(data),
		data: data,
	}
	m.leafs = append(m.leafs, node)
	m.root = m.buildTree(m.leafs)
}

// UpdateLeaf updates a leaf node and recalculates the tree
func (m *MerkleTree) UpdateLeaf(oldData, newData []byte) error {
	for i, leaf := range m.leafs {
		if bytes.Equal(leaf.data, oldData) {
			m.leafs[i].data = newData
			m.leafs[i].hash = m.hash(newData)
			m.root = m.buildTree(m.leafs)
			return nil
		}
	}
	return ErrNotFoundData
}

// hash computes the hash of a given value
func (m *MerkleTree) hash(v []byte) []byte {
	h := m.hashFn()
	h.Write(v)
	return h.Sum(nil)
}

// buildTree recursively builds the Merkle tree
func (m *MerkleTree) buildTree(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		left, right := nodes[i], nodes[i] // default right to left for odd number of nodes
		if i+1 < len(nodes) {
			right = nodes[i+1]
		}

		parent := &Node{
			left:  left,
			right: right,
			hash:  m.hash(append(left.hash, right.hash...)),
		}

		left.parent = parent
		right.parent = parent

		parents = append(parents, parent)
	}

	return m.buildTree(parents)
}
