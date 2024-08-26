// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package commitment defines the FROST Signer commitment.
package frost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
)

var (
	errDecodeCommitmentLength = errors.New("failed to decode commitment: invalid length")
	errInvalidCiphersuite     = errors.New("ciphersuite not available")
	errInvalidLength          = errors.New("invalid encoding length")
	errHidingNonce            = errors.New("invalid hiding nonce (nil, identity, or generator)")
	errBindingNonce           = errors.New("invalid binding nonce (nil, identity, or generator)")
)

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	HidingNonce  *group.Element
	BindingNonce *group.Element
	CommitmentID uint64
	SignerID     uint64
	Group        group.Group
}

// Verify returns an error if the commitment is
func (c *Commitment) Verify(g group.Group) error {
	if c.Group != g {
		return fmt.Errorf(
			"commitment for participant %d has an unexpected ciphersuite: expected %s, got %s",
			c.SignerID,
			g,
			c.Group,
		)
	}

	generator := g.Base()

	if c.HidingNonce == nil || c.HidingNonce.IsIdentity() || c.HidingNonce.Equal(generator) == 1 {
		return errHidingNonce
	}

	if c.BindingNonce == nil || c.BindingNonce.IsIdentity() || c.BindingNonce.Equal(generator) == 1 {
		return errBindingNonce
	}

	return nil
}

// Copy returns a new Commitment struct populated with the same values as the receiver.
func (c *Commitment) Copy() *Commitment {
	return &Commitment{
		HidingNonce:  c.HidingNonce.Copy(),
		BindingNonce: c.BindingNonce.Copy(),
		CommitmentID: c.CommitmentID,
		SignerID:     c.SignerID,
		Group:        c.Group,
	}
}

// EncodedSize returns the byte size of the output of Encode().
func EncodedSize(g group.Group) uint64 {
	return 1 + 8 + 8 + 2*uint64(g.ElementLength())
}

// Encode returns the serialized byte encoding of a participant's commitment.
func (c *Commitment) Encode() []byte {
	hNonce := c.HidingNonce.Encode()
	bNonce := c.BindingNonce.Encode()

	out := make([]byte, 17, EncodedSize(c.Group))
	out[0] = byte(c.Group)
	binary.LittleEndian.PutUint64(out[1:9], c.CommitmentID)
	binary.LittleEndian.PutUint64(out[9:17], c.SignerID)
	out = append(out, hNonce...)
	out = append(out, bNonce...)

	return out
}

// Decode attempts to deserialize the encoded commitment given as input, and to return it.
func (c *Commitment) Decode(data []byte) error {
	if len(data) < 17 {
		return errDecodeCommitmentLength
	}

	g := group.Group(data[0])
	if !g.Available() {
		return errInvalidCiphersuite
	}

	if uint64(len(data)) != EncodedSize(g) {
		return errDecodeCommitmentLength
	}

	cID := binary.LittleEndian.Uint64(data[1:9])
	pID := binary.LittleEndian.Uint64(data[9:17])
	offset := 17

	hn := g.NewElement()
	if err := hn.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("invalid encoding of hiding nonce: %w", err)
	}

	offset += g.ElementLength()

	bn := g.NewElement()
	if err := bn.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("invalid encoding of binding nonce: %w", err)
	}

	c.Group = g
	c.CommitmentID = cID
	c.SignerID = pID
	c.HidingNonce = hn
	c.BindingNonce = bn

	return nil
}

// CommitmentList is a sortable list of commitments with search functions.
type CommitmentList []*Commitment

func cmpID(a, b *Commitment) int {
	switch {
	case a.SignerID < b.SignerID: // a < b
		return -1
	case a.SignerID > b.SignerID:
		return 1
	default:
		return 0
	}
}

// Sort sorts the list the ascending order of identifiers.
func (c CommitmentList) Sort() {
	slices.SortFunc(c, cmpID)
}

// IsSorted returns whether the list is sorted in ascending order by identifier.
func (c CommitmentList) IsSorted() bool {
	return slices.IsSortedFunc(c, cmpID)
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c CommitmentList) Get(identifier uint64) *Commitment {
	for _, com := range c {
		if com.SignerID == identifier {
			return com
		}
	}

	return nil
}

// ParticipantsUInt64 returns the uint64 list of participant identifiers in the list.
func (c CommitmentList) ParticipantsUInt64() []uint64 {
	out := make([]uint64, len(c))

	for i, com := range c {
		out[i] = com.SignerID
	}

	return out
}

// ParticipantsScalar returns the group.Scalar list of participant identifier in the list
func (c CommitmentList) ParticipantsScalar() []*group.Scalar {
	if len(c) == 0 {
		return nil
	}

	if c[0] == nil {
		return nil
	}

	g := c[0].Group

	return secretsharing.NewPolynomialFromListFunc(g, c, func(c *Commitment) *group.Scalar {
		return g.NewScalar().SetUInt64(c.SignerID)
	})
}

// Verify checks for the Commitment list's integrity.
func (c CommitmentList) Verify(g group.Group, threshold uint64) error {
	// Verify number of commitments.
	if uint64(len(c)) < threshold {
		return fmt.Errorf("too few commitments: expected at least %d but got %d", threshold, len(c))
	}

	// Ensure the list is sorted
	if !c.IsSorted() {
		c.Sort()
	}

	// set to detect duplication
	set := make(map[uint64]struct{}, len(c))

	for _, com := range c {
		// Check for duplicate participant entries.
		if _, exists := set[com.SignerID]; exists {
			return fmt.Errorf("commitment list contains multiple commitments of participant %d", com.SignerID)
		}

		set[com.SignerID] = struct{}{}

		// Check general consistency.
		if err := com.Verify(g); err != nil {
			return err
		}
	}

	return nil
}

func (c CommitmentList) Encode() []byte {
	n := len(c)
	if n == 0 {
		return nil
	}

	g := c[0].Group
	size := 1 + 8 + uint64(n)*EncodedSize(g)
	out := make([]byte, 9, size)
	out[0] = byte(g)
	binary.LittleEndian.PutUint64(out[1:9], uint64(n))

	for _, com := range c {
		out = append(out, com.Encode()...)
	}

	return out
}

func DecodeList(data []byte) (CommitmentList, error) {
	if len(data) < 9 {
		return nil, errInvalidLength
	}

	g := group.Group(data[0])
	if !g.Available() {
		return nil, errInvalidCiphersuite
	}

	n := binary.LittleEndian.Uint64(data[1:9])
	es := EncodedSize(g)
	size := 1 + 8 + n*es

	if uint64(len(data)) != size {
		return nil, errInvalidLength
	}

	c := make(CommitmentList, 0, n)

	for offset := uint64(9); offset < uint64(len(data)); offset += es {
		com := new(Commitment)
		if err := com.Decode(data[offset : offset+es]); err != nil {
			return nil, fmt.Errorf("invalid encoding of commitment: %w", err)
		}

		c = append(c, com)
	}

	return c, nil
}

func (c CommitmentList) GroupCommitmentAndBindingFactors(
	publicKey *group.Element,
	message []byte,
) (*group.Element, BindingFactors) {
	bindingFactors := c.bindingFactors(publicKey, message)
	groupCommitment := c.groupCommitment(bindingFactors)

	return groupCommitment, bindingFactors
}

type commitmentWithEncodedID struct {
	*Commitment
	ParticipantID []byte
}

func commitmentsWithEncodedID(g group.Group, commitments CommitmentList) []*commitmentWithEncodedID {
	r := make([]*commitmentWithEncodedID, len(commitments))
	for i, com := range commitments {
		r[i] = &commitmentWithEncodedID{
			ParticipantID: g.NewScalar().SetUInt64(com.SignerID).Encode(),
			Commitment:    com,
		}
	}

	return r
}

func encodeCommitmentList(g group.Group, commitments []*commitmentWithEncodedID) []byte {
	size := len(commitments) * (g.ScalarLength() + 2*g.ElementLength())
	encoded := make([]byte, 0, size)

	for _, com := range commitments {
		encoded = append(encoded, com.ParticipantID...)
		encoded = append(encoded, com.HidingNonce.Encode()...)
		encoded = append(encoded, com.BindingNonce.Encode()...)
	}

	return encoded
}

// BindingFactors is a map of participant identifier to BindingFactors.
type BindingFactors map[uint64]*group.Scalar

func (c CommitmentList) bindingFactors(publicKey *group.Element, message []byte) BindingFactors {
	g := c[0].Group
	coms := commitmentsWithEncodedID(g, c)
	encodedCommitHash := internal.H5(g, encodeCommitmentList(g, coms))
	h := internal.H4(g, message)
	rhoInputPrefix := internal.Concatenate(publicKey.Encode(), h, encodedCommitHash)
	bindingFactors := make(BindingFactors, len(c))

	for _, com := range coms {
		rhoInput := internal.Concatenate(rhoInputPrefix, com.ParticipantID)
		bindingFactors[com.Commitment.SignerID] = internal.H1(g, rhoInput)
	}

	return bindingFactors
}

func (c CommitmentList) groupCommitment(bf BindingFactors) *group.Element {
	g := c[0].Group
	gc := g.NewElement()

	for _, com := range c {
		factor := bf[com.SignerID]
		bindingNonce := com.BindingNonce.Copy().Multiply(factor)
		gc.Add(com.HidingNonce).Add(bindingNonce)
	}

	return gc
}
