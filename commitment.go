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
	errHidingNonceCommitment  = errors.New("invalid hiding nonce commitment (nil, identity, or generator)")
	errBindingNonceCommitment = errors.New("invalid binding nonce commitment (nil, identity, or generator)")
)

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	HidingNonceCommitment  *group.Element
	BindingNonceCommitment *group.Element
	CommitmentID           uint64
	SignerID               uint64
	Group                  group.Group
}

// Validate returns an error if the commitment is
func (c *Commitment) Validate(g group.Group) error {
	if c.Group != g {
		return fmt.Errorf(
			"commitment %d for participant %d has an unexpected ciphersuite: expected %s, got %s",
			c.CommitmentID,
			c.SignerID,
			g,
			c.Group,
		)
	}

	generator := g.Base()

	if c.HidingNonceCommitment == nil || c.HidingNonceCommitment.IsIdentity() ||
		c.HidingNonceCommitment.Equal(generator) == 1 {
		return fmt.Errorf("commitment %d for signer %d has an %w", c.CommitmentID,
			c.SignerID, errHidingNonceCommitment)
	}

	if c.BindingNonceCommitment == nil || c.BindingNonceCommitment.IsIdentity() ||
		c.BindingNonceCommitment.Equal(generator) == 1 {
		return fmt.Errorf("commitment %d for signer %d has an %w", c.CommitmentID,
			c.SignerID, errBindingNonceCommitment)
	}

	return nil
}

// Copy returns a new Commitment struct populated with the same values as the receiver.
func (c *Commitment) Copy() *Commitment {
	return &Commitment{
		HidingNonceCommitment:  c.HidingNonceCommitment.Copy(),
		BindingNonceCommitment: c.BindingNonceCommitment.Copy(),
		CommitmentID:           c.CommitmentID,
		SignerID:               c.SignerID,
		Group:                  c.Group,
	}
}

// EncodedSize returns the byte size of the output of Encode().
func EncodedSize(g group.Group) uint64 {
	return 1 + 8 + 8 + 2*uint64(g.ElementLength())
}

// CommitmentList is a sortable list of commitments with search functions.
type CommitmentList []*Commitment

// cmpID returns a negative number when the signer identity of a < b, a positive number when
// a > b and zero when a == b.
func cmpID(a, b *Commitment) int {
	switch {
	case a == nil || b == nil:
		return 0
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
	if !c.IsSorted() {
		slices.SortFunc(c, cmpID)
	}
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

// Participants returns the uint64 list of participant identifiers in the list.
func (c CommitmentList) Participants() []uint64 {
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

func (c *Configuration) isSignerRegistered(sid uint64) bool {
	for _, peer := range c.SignerPublicKeys {
		if peer.ID == sid {
			return true
		}
	}

	return false
}

// ValidateCommitmentList returns an error if at least one of the following conditions is not met:
// - list length is within [threshold;max]
// - no signer identifier in commitments is 0
// - no singer identifier in commitments is > max signers
// - no duplicated in signer identifiers
// - all commitment signer identifiers are registered in the configuration
func (c *Configuration) ValidateCommitmentList(commitments CommitmentList) error {
	// Validate number of commitments.
	length := uint64(len(commitments))

	if length == 0 {
		return fmt.Errorf("commitment list is empty")
	}

	if length < c.Threshold {
		return fmt.Errorf("too few commitments: expected at least %d but got %d", c.Threshold, length)
	}

	if length > c.MaxSigners {
		return fmt.Errorf("too many commitments: expected %d or less but got %d", c.MaxSigners, length)
	}

	// set to detect duplication
	set := make(map[uint64]struct{}, length)

	for i, commitment := range commitments {
		if commitment == nil {
			return fmt.Errorf("the commitment list has a nil commitment")
		}

		if commitment.SignerID == 0 {
			return fmt.Errorf("signer identifier for commitment %d is 0", commitment.CommitmentID)
		}

		if commitment.SignerID > c.MaxSigners {
			return fmt.Errorf(
				"signer identifier %d for commitment %d is above allowed values (%d)",
				commitment.SignerID,
				commitment.CommitmentID,
				c.MaxSigners,
			)
		}

		// Check for duplicate participant entries.
		if _, exists := set[commitment.SignerID]; exists {
			return fmt.Errorf("commitment list contains multiple commitments of participant %d", commitment.SignerID)
		}

		set[commitment.SignerID] = struct{}{}

		// Check general validity of the commitment.
		if err := commitment.Validate(c.group); err != nil {
			return err
		}

		// List must be sorted, compare with the next commitment.
		if uint64(i) < length-2 {
			if cmpID(commitment, commitments[i+1]) > 0 {
				return fmt.Errorf("commitment list is not sorted by signer identifiers")
			}
		}

		// Validate that all commitments come from registered signers.
		if !c.isSignerRegistered(commitment.SignerID) {
			return fmt.Errorf(
				"signer identifier %d for commitment %d is not registered in the configuration",
				commitment.SignerID,
				commitment.CommitmentID,
			)
		}
	}

	return nil
}

// Validate checks for the Commitment list's integrity.
// - list is returned sorted
// - no signer identifier in commitments is 0
// - no
func (c CommitmentList) Validate(g group.Group) error {
	// set to detect duplication
	set := make(map[uint64]struct{}, len(c))

	for _, com := range c {

		// Check for duplicate participant entries.
		if _, exists := set[com.SignerID]; exists {
			return fmt.Errorf("commitment list contains multiple commitments of participant %d", com.SignerID)
		}

		set[com.SignerID] = struct{}{}

		// Check general validity of the commitment.
		if err := com.Validate(g); err != nil {
			return err
		}
	}

	// Ensure the list is sorted
	if !c.IsSorted() {
		c.Sort()
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
		encoded = append(encoded, com.HidingNonceCommitment.Encode()...)
		encoded = append(encoded, com.BindingNonceCommitment.Encode()...)
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
		bindingNonce := com.BindingNonceCommitment.Copy().Multiply(factor)
		gc.Add(com.HidingNonceCommitment).Add(bindingNonce)
	}

	return gc
}
