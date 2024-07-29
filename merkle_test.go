package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	t.Run("should create a new Merkle tree", func(t *testing.T) {
		data := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		tree, err := New(data, WithHashFunction(mockHash))
		require.NoError(t, err)
		require.NotNil(t, tree)
		require.Len(t, tree.leafs, 3)
		require.Equal(t, "hash(hash(hash(a)hash(b))hash(hash(c)hash(c)))", string(tree.root.hash))
	})

	t.Run("should return error for empty data", func(t *testing.T) {
		_, err := New([][]byte{})
		require.ErrorIs(t, err, ErrEmptyData)
	})

	t.Run("should set custom hash function", func(t *testing.T) {
		data := [][]byte{[]byte("a"), []byte("b")}
		tree, err := New(data, WithHashFunction(sha256.New))
		require.NoError(t, err)
		require.Equal(t, sha256.Size, len(tree.root.hash))
	})
}

func Test_GenerateProof(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tree, err := New(data, WithHashFunction(mockHash))
	require.NoError(t, err)

	t.Run("should generate valid proof", func(t *testing.T) {
		proof, err := tree.GenerateProof([]byte("b"))
		require.NoError(t, err)
		require.Len(t, proof, 2) // log2(4) = 2
		require.Equal(t, []byte("hash(a)"), proof[0].Hash)
		require.Equal(t, []byte("hash(hash(c)hash(d))"), proof[1].Hash)
	})

	t.Run("should return error for non-existent data", func(t *testing.T) {
		_, err := tree.GenerateProof([]byte("e"))
		require.ErrorIs(t, err, ErrNotFoundData)
	})
}

func Test_VerifyProof(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tree, err := New(data, WithHashFunction(mockHash))
	require.NoError(t, err)

	proof, err := tree.GenerateProof([]byte("b"))
	require.NoError(t, err)

	t.Run("should verify valid proof", func(t *testing.T) {
		valid := tree.VerifyProof([]byte("hash(b)"), proof)
		require.True(t, valid)
	})

	t.Run("should not verify invalid proof", func(t *testing.T) {
		invalidProof := append(proof, ProofElement{Hash: []byte("invalid"), Side: Left})
		valid := tree.VerifyProof([]byte("hash(b)"), invalidProof)
		require.False(t, valid)
	})
}

func Test_VerifyData(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tree, err := New(data, WithHashFunction(mockHash))
	require.NoError(t, err)

	proof, err := tree.GenerateProof([]byte("b"))
	require.NoError(t, err)

	t.Run("should verify valid data", func(t *testing.T) {
		valid := tree.VerifyData([]byte("b"), proof)
		require.True(t, valid)
	})

	t.Run("should not verify invalid data", func(t *testing.T) {
		valid := tree.VerifyData([]byte("e"), proof)
		require.False(t, valid)
	})
}

func Test_AddLeaf(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b")}
	tree, err := New(data, WithHashFunction(mockHash))
	require.NoError(t, err)

	t.Run("should add new leaf and update root hash", func(t *testing.T) {
		oldRoot := tree.root.hash
		tree.AddLeaf([]byte("c"))

		require.Len(t, tree.leafs, 3)
		require.NotEqual(t, oldRoot, tree.root.hash)
		require.Equal(t, "hash(hash(hash(a)hash(b))hash(hash(c)hash(c)))", string(tree.root.hash))
	})
}

func Test_UpdateLeaf(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tree, err := New(data, WithHashFunction(mockHash))
	require.NoError(t, err)

	t.Run("should update existing leaf and recalculate root", func(t *testing.T) {
		oldRoot := tree.root.hash
		err := tree.UpdateLeaf([]byte("b"), []byte("b2"))
		require.NoError(t, err)
		require.NotEqual(t, oldRoot, tree.root.hash)
		require.Equal(t, "hash(hash(hash(a)hash(b2))hash(hash(c)hash(c)))", string(tree.root.hash))
	})

	t.Run("should return error for non-existent leaf", func(t *testing.T) {
		err := tree.UpdateLeaf([]byte("e"), []byte("e2"))
		require.ErrorIs(t, err, ErrNotFoundData)
	})
}

func mockHash() hash.Hash {
	return &mockHasher{}
}

type mockHasher struct {
	data []byte
}

func (m *mockHasher) Reset()         { m.data = nil }
func (m *mockHasher) Size() int      { return 8 }
func (m *mockHasher) BlockSize() int { return 8 }

func (m *mockHasher) Write(p []byte) (n int, err error) {
	m.data = append(m.data, p...)
	return len(p), nil
}

func (m *mockHasher) Sum(b []byte) []byte {
	return []byte(fmt.Sprintf("hash(%s)", string(m.data)))
}
