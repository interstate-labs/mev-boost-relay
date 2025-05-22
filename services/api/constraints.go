package api

import (
	"encoding/binary"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
)

// These types are taken from https://chainbound.github.io/bolt-docs/

const (
	// Note: we decided to set max constraints per slot to the same value
	// as the max transactions per block in Ethereum. This allows bolt operators
	// to decide how many commitments to include in a slot without the protocol
	// imposing hard limits that would be really hard to change in the future.
	//
	// Specs: https://github.com/ethereum/consensus-specs/blob/9515f3e7e1ce893f97ac638d0280ea9026518bad/specs/bellatrix/beacon-chain.md#execution
	MAX_CONSTRAINTS_PER_SLOT  = 1048576    // 2**20
	MAX_BYTES_PER_TRANSACTION = 1073741824 // 2**30
	MAX_RECEIVERS             = 1024
)

type SignedConstraints struct {
	Message *ConstraintsMessage `json:"message"`
	// NOTE: This might change to an ECDSA signature in the future. In such case,
	// when encoding/decoding SSZ we should take into account that it is 64 bytes long instead of 96
	Signature phase0.BLSSignature `ssz-size:"96" json:"signature"`
}

type ConstraintsMessage struct {
	Proposer    phase0.BLSPubkey      `ssz-size:"48" json:"proposer"`  // 48-byte BLS pubkey
	Delegate    phase0.BLSPubkey      `ssz-size:"48" json:"delegate"`
	Slot           uint64        `json:"slot"`
	Constraints    []*Constraint `ssz-max:"1048576" json:"constraints"`
	Receivers   []phase0.BLSPubkey    `ssz-max:"1024" json:"receivers"`
}

type Constraint struct {
	ConstraintType uint64 `json:"constraintType"`
	Payload        []byte `ssz-max:"1073741824" json:"payload"` // 1 GB max payload
}

// Index is the Union[uint64, None] (For SSZ purposes)
type Index uint64

func NewIndex(i uint64) *Index {
	idx := Index(i)
	return &idx
}

func (c SignedConstraints) String() string {
	return JSONStringify(c)
}

func (c ConstraintsMessage) String() string {
	return JSONStringify(c)
}

func (c Constraint) String() string {
	return JSONStringify(c)
}

// ConstraintsMap is a map of constraints for a block.
type ConstraintsMap = map[phase0.Hash32]*Constraint

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to constraints
	constraints map[uint64]ConstraintsMap
}

// Proof represents a merkle proof for a constraint
type Proof struct {
	Leaf  phase0.Hash32   `json:"leaf"`
	Path  []phase0.Hash32 `json:"path"`
	Index uint64          `json:"index"`
}

// SignedProof represents a signed merkle proof
type SignedProof struct {
	Message   *Proof              `json:"message"`
	Signature phase0.BLSSignature `ssz-size:"96" json:"signature"`
}

func (p *Proof) String() string {
	return JSONStringify(p)
}

func (p *SignedProof) String() string {
	return JSONStringify(p)
}

func (c *SignedConstraints) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

func (c *SignedConstraints) MarshalSSZTo(dst []byte) ([]byte, error) {
	// We have 4 bytes of an offset to a dinamically sized object
	// plus 96 bytes of the BLS signature. This indicates
	// where the dynamic data begins
	offset := 100

	// Field (0) `Message`
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) `Signature`
	dst = append(dst, c.Signature[:]...)

	// Field (0) `Message`
	dst, err := c.Message.MarshalSSZTo(dst)

	return dst, err
}

func (c *SignedConstraints) SizeSSZ() int {
	// At minimum, the size is 4 bytes of an offset to a dinamically sized object
	// plus 96 bytes of the BLS signature
	size := 100

	// Field (0) 'Message'. We need to add the size of the message with its default values
	if c.Message == nil {
		c.Message = new(ConstraintsMessage)
	}
	size += c.Message.SizeSSZ()

	return 0
}

func (c *SignedConstraints) UnmarshalSSZ(buf []byte) (err error) {
	size := uint64(len(buf))
	if size < 100 {
		// The buf must be at least 100 bytes long according to offset + signature
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64 // Offset (0) 'Message'

	// Offset (0) 'Message'. Handle offset too big and too small respectively
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}
	if o0 < 100 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (0) 'Message'
	buf = tail[o0:]
	if c.Message == nil {
		c.Message = new(ConstraintsMessage)
	}
	if err = c.Message.UnmarshalSSZ(buf); err != nil {
		return
	}

	// Field (1) `Signature`
	copy(c.Signature[:], tail[4:100])

	return
}

func (m *ConstraintsMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(m)
}

func (m *ConstraintsMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	// We have 4 bytes of an offset to a dinamically sized object
	// plus 16 bytes of the two uint64 fields
	offset := 20
	dst = buf

	// Field (0) `ValidatorIndex`
	dst = ssz.MarshalUint64(dst, m.ValidatorIndex)

	// Field (1) `Slot`
	dst = ssz.MarshalUint64(dst, m.Slot)

	// Field (2) `Constraints`
	dst = ssz.WriteOffset(dst, offset)

	// ------- Dynamic fields -------

	// Field (2) `Constraints`
	if size := len(m.Constraints); size > MAX_CONSTRAINTS_PER_SLOT {
		err = ssz.ErrListTooBigFn("ConstraintsMessage.Constraints", size, MAX_CONSTRAINTS_PER_SLOT)
		return
	}
	// Each constraint is a dynamically sized object so we first add the offsets
	offset = 4 * len(m.Constraints)
	for i := 0; i < len(m.Constraints); i++ {
		dst = ssz.WriteOffset(dst, offset)
		offset += m.Constraints[i].SizeSSZ()
	}
	// Now we add the actual data
	for i := 0; i < len(m.Constraints); i++ {
		if dst, err = m.Constraints[i].MarshalSSZTo(dst); err != nil {
			return
		}
		if size := len(m.Constraints[i].Tx); size > MAX_BYTES_PER_TRANSACTION {
			err = ssz.ErrBytesLengthFn("Constraints[i].Tx", size, MAX_BYTES_PER_TRANSACTION)
			return
		}
	}

	return
}

func (m *ConstraintsMessage) SizeSSZ() int {
	size := 48 + 48 + 8 + 4 + 4
	for _, c := range m.Constraints {
		size += 4 + c.SizeSSZ()
	}
	size += len(m.Receivers) * 48
	return size
}

func (m *ConstraintsMessage) UnmarshalSSZ(buf []byte) error {
	if len(buf) < 104 {
		return ssz.ErrSize
	}
	o0 := ssz.ReadOffset(buf[104:108])
	o1 := ssz.ReadOffset(buf[108:112])

	copy(m.Proposer[:], buf[0:48])
	copy(m.Delegate[:], buf[48:96])
	m.Slot = binary.LittleEndian.Uint64(buf[96:104])

	// Constraints
	constraintsBuf := buf[o0:]
	length, err := ssz.DecodeDynamicLength(constraintsBuf, MAX_CONSTRAINTS_PER_SLOT)
	if err != nil {
		return err
	}
	m.Constraints = make([]*Constraint, length)
	err = ssz.UnmarshalDynamic(constraintsBuf, length, func(i int, b []byte) error {
		c := new(Constraint)
		if err := c.UnmarshalSSZ(b); err != nil {
			return err
		}
		m.Constraints[i] = c
		return nil
	})
	if err != nil {
		return err
	}

	// Receivers
	receiversBuf := buf[o1:]
	length, err = ssz.DecodeFixedLength(receiversBuf, 48, MAX_RECEIVERS)
	if err != nil {
		return err
	}
	m.Receivers = make([]phase0.BLSPubkey, length)
	for i := range m.Receivers {
		copy(m.Receivers[i][:], receiversBuf[i*48:(i+1)*48])
	}
	return nil
}

func (c *Constraint) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

func (c *Constraint) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	// Both fields are dynamically sized, so we start with two offsets of 4 bytes each
	offset := 8
	dst = buf

	// Field (0) `Tx`
	dst = ssz.WriteOffset(dst, offset)
	offset += len(c.Tx)

	// Field (1) `Index`
	dst = ssz.WriteOffset(dst, offset)

	// Field (0) `Tx`
	dst = append(dst, c.Tx...)

	// Field (1) `Index`
	if c.Index == nil {
		dst = append(dst, 0)
	} else {
		// Index is `Union[None, uint64]
		dst = append(dst, 1)
		dst = ssz.MarshalUint64(dst, uint64(*c.Index))
	}

	return
}

func (c *Constraint) SizeSSZ() int {
	// Both fields are dynamically sized, so we start with two offsets of 4 bytes each
	return 8 + 4 + len(c.Payload)
}

func (c *Constraint) UnmarshalSSZ(buf []byte) (err error) {
	if len(buf) < 12 {
		return ssz.ErrSize
	}
	c.ConstraintType = binary.LittleEndian.Uint64(buf[:8])
	o0 := ssz.ReadOffset(buf[8:12])
	if o0 > uint64(len(buf)) || o0 < 12 {
		return ssz.ErrInvalidVariableOffset
	}
	c.Payload = make([]byte, len(buf[o0:]))
	copy(c.Payload, buf[o0:])
	return nil
}

func (i *Index) SizeSSZ() int {
	if i == nil {
		return 1
	}
	// selector + uint64
	return 9
}

type ConstraintsCache struct {
	mu          sync.RWMutex
	constraints map[phase0.Slot]*SignedConstraints
	subscribers []chan *SignedConstraints
}

func NewConstraintsCache() *ConstraintsCache {
	return &ConstraintsCache{
		constraints: make(map[phase0.Slot]*SignedConstraints),
		subscribers: make([]chan *SignedConstraints, 0),
	}
}

func (c *ConstraintsCache) Get(slot phase0.Slot) (*SignedConstraints, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	constraints, ok := c.constraints[slot]
	return constraints, ok
}

func (c *ConstraintsCache) Set(slot phase0.Slot, constraints *SignedConstraints) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.constraints[slot] = constraints
}

func (c *ConstraintsCache) GetAll() []*SignedConstraints {
	c.mu.RLock()
	defer c.mu.RUnlock()
	constraints := make([]*SignedConstraints, 0, len(c.constraints))
	for _, c := range c.constraints {
		constraints = append(constraints, c)
	}
	return constraints
}

func (c *ConstraintsCache) Subscribe(ch chan *SignedConstraints) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subscribers = append(c.subscribers, ch)
}

func (c *ConstraintsCache) Unsubscribe(ch chan *SignedConstraints) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, subscriber := range c.subscribers {
		if subscriber == ch {
			c.subscribers = append(c.subscribers[:i], c.subscribers[i+1:]...)
			return
		}
	}
}

func (c *ConstraintsCache) Notify(constraints *SignedConstraints) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, ch := range c.subscribers {
		select {
		case ch <- constraints:
		default:
			// Skip if channel is full
		}
	}
}

// Delegation and SignedDelegation types for v1 constraints spec

type Delegation struct {
	ValidatorIndex uint64   `json:"validator_index"`
	Slot           uint64   `json:"slot"`
	Gateway        [48]byte `json:"gateway"` // BLS pubkey
	Expiry         uint64   `json:"expiry"`
}

type SignedDelegation struct {
	Message   *Delegation         `json:"message"`
	Signature phase0.BLSSignature `ssz-size:"96" json:"signature"`
}

func (d Delegation) String() string {
	return JSONStringify(d)
}

func (d SignedDelegation) String() string {
	return JSONStringify(d)
}
