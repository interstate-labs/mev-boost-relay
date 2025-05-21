package api

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
)

// MerkleTree represents a merkle tree for constraints
type MerkleTree struct {
	leaves []phase0.Hash32
	root   phase0.Hash32
}

// NewMerkleTree creates a new merkle tree from a list of constraints
func NewMerkleTree(constraints []*Constraint) (*MerkleTree, error) {
	if len(constraints) == 0 {
		return &MerkleTree{
			leaves: make([]phase0.Hash32, 0),
			root:   phase0.Hash32{},
		}, nil
	}

	// Calculate leaf hashes
	leaves := make([]phase0.Hash32, len(constraints))
	for i, constraint := range constraints {
		leaf, err := calculateLeafHash(constraint)
		if err != nil {
			return nil, err
		}
		leaves[i] = leaf
	}

	// Build the tree
	root := buildTree(leaves)

	return &MerkleTree{
		leaves: leaves,
		root:   root,
	}, nil
}

// GetRoot returns the root of the merkle tree
func (t *MerkleTree) GetRoot() phase0.Hash32 {
	return t.root
}

// GetProof returns a merkle proof for the given index
func (t *MerkleTree) GetProof(index uint64) *Proof {
	if index >= uint64(len(t.leaves)) {
		return nil
	}

	// Calculate the path
	path := make([]phase0.Hash32, 0)
	currentIndex := index
	currentLevel := t.leaves

	for len(currentLevel) > 1 {
		// If we're at an odd index, the sibling is to the left
		// If we're at an even index, the sibling is to the right
		siblingIndex := currentIndex ^ 1
		if siblingIndex < uint64(len(currentLevel)) {
			path = append(path, currentLevel[siblingIndex])
		}

		// Move up to the next level
		currentLevel = buildNextLevel(currentLevel)
		currentIndex = currentIndex / 2
	}

	return &Proof{
		Leaf:  t.leaves[index],
		Path:  path,
		Index: index,
	}
}

// buildTree builds a merkle tree from a list of leaves
func buildTree(leaves []phase0.Hash32) phase0.Hash32 {
	if len(leaves) == 0 {
		return phase0.Hash32{}
	}

	currentLevel := leaves
	for len(currentLevel) > 1 {
		currentLevel = buildNextLevel(currentLevel)
	}

	return currentLevel[0]
}

// buildNextLevel builds the next level of the merkle tree
func buildNextLevel(level []phase0.Hash32) []phase0.Hash32 {
	nextLevel := make([]phase0.Hash32, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 < len(level) {
			// We have a pair
			nextLevel = append(nextLevel, hashPair(level[i], level[i+1]))
		} else {
			// We have an odd number of nodes, duplicate the last one
			nextLevel = append(nextLevel, hashPair(level[i], level[i]))
		}
	}
	return nextLevel
} 