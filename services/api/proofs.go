package api

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
)

var (
	ErrNilConstraint             = errors.New("nil constraint")
	ErrNilProof                  = errors.New("nil proof")
	ErrInvalidProofs             = errors.New("proof verification failed")
	ErrInvalidRoot               = errors.New("failed getting tx root from bid")
	ErrHashesIndexesMismatch     = errors.New("proof transaction hashes and indexes length mismatch")
	ErrHashesConstraintsMismatch = errors.New("proof transaction hashes and constraints length mismatch")
)

// verifyInclusionProof verifies the proofs against the constraints, and returns an error if the proofs are invalid.
//
// NOTE: assumes constraints transactions are already without blobs
func verifyInclusionProof(proofs []*Proof, constraints []*Constraint, root phase0.Hash32) error {
	if len(proofs) == 0 {
		return nil
	}

	if len(proofs) != len(constraints) {
		return fmt.Errorf("%w: got %d proofs and %d constraints", ErrHashesConstraintsMismatch, len(proofs), len(constraints))
	}

	// Verify each proof
	for i, proof := range proofs {
		if proof == nil {
			return fmt.Errorf("%w: proof at index %d is nil", ErrNilProof, i)
		}

		// Calculate the leaf hash from the constraint
		leaf, err := calculateLeafHash(constraints[i])
		if err != nil {
			return fmt.Errorf("failed to calculate leaf hash: %w", err)
		}

		// Verify the proof
		if !verifyMerkleProof(leaf, proof.Path, proof.Index, root) {
			return fmt.Errorf("%w: invalid proof at index %d", ErrInvalidProofs, i)
		}
	}

	return nil
}

// calculateLeafHash calculates the hash of a constraint for the merkle tree
func calculateLeafHash(constraint *Constraint) (phase0.Hash32, error) {
	if constraint == nil {
		return phase0.Hash32{}, ErrNilConstraint
	}

	// Calculate the hash of the transaction
	txHash := gethCommon.BytesToHash(constraint.Tx)

	// If there's an index, include it in the hash
	if constraint.Index != nil {
		// Combine tx hash and index into a single hash
		combined := make([]byte, 40) // 32 bytes for tx hash + 8 bytes for index
		copy(combined[:32], txHash[:])
		binary.LittleEndian.PutUint64(combined[32:], uint64(*constraint.Index))
		return phase0.Hash32(gethCommon.BytesToHash(combined)), nil
	}

	return phase0.Hash32(txHash), nil
}

// verifyMerkleProof verifies a merkle proof against a root
func verifyMerkleProof(leaf phase0.Hash32, path []phase0.Hash32, index uint64, root phase0.Hash32) bool {
	current := leaf
	for i, sibling := range path {
		if (index>>i)&1 == 0 {
			// Current is left
			current = hashPair(current, sibling)
		} else {
			// Current is right
			current = hashPair(sibling, current)
		}
	}
	return current == root
}

// hashPair combines two hashes into a single hash
func hashPair(a, b phase0.Hash32) phase0.Hash32 {
	combined := make([]byte, 64) // 32 bytes for each hash
	copy(combined[:32], a[:])
	copy(combined[32:], b[:])
	return phase0.Hash32(gethCommon.BytesToHash(combined))
}
