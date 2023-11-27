// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"errors"
	"fmt"
	"slices"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

var errDecodeCommitmentLength = errors.New("failed to decode commitment: invalid length")

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	Identifier   *group.Scalar
	HidingNonce  *group.Element
	BindingNonce *group.Element
}

// Encode returns the serialized byte encoding of a participant's commitment.
func (c Commitment) Encode() []byte {
	id := c.Identifier.Encode()
	hNonce := c.HidingNonce.Encode()
	bNonce := c.BindingNonce.Encode()

	out := make([]byte, len(id)+len(hNonce)+len(bNonce))
	copy(out, id)
	copy(out[len(id):], hNonce)
	copy(out[len(id)+len(hNonce):], bNonce)

	return out
}

// DecodeCommitment attempts to deserialize the encoded commitment given as input, and to return it.
func DecodeCommitment(cs Ciphersuite, data []byte) (*Commitment, error) {
	g := cs.Configuration().Ciphersuite.Group
	scalarLength := g.ScalarLength()
	elementLength := g.ElementLength()

	if len(data) != scalarLength+2*elementLength {
		return nil, errDecodeCommitmentLength
	}

	c := &Commitment{
		Identifier:   g.NewScalar(),
		HidingNonce:  g.NewElement(),
		BindingNonce: g.NewElement(),
	}

	if err := c.Identifier.Decode(data[:scalarLength]); err != nil {
		return nil, fmt.Errorf("failed to decode commitment identifier: %w", err)
	}

	if err := c.HidingNonce.Decode(data[:scalarLength]); err != nil {
		return nil, fmt.Errorf("failed to decode commitment hiding nonce: %w", err)
	}

	if err := c.BindingNonce.Decode(data[:scalarLength]); err != nil {
		return nil, fmt.Errorf("failed to decode commitment binding nonce: %w", err)
	}

	return c, nil
}

// CommitmentList is a sortable list of commitments.
type CommitmentList []*Commitment

func cmpID(a, b *Commitment) int {
	switch {
	case a.Identifier.Equal(b.Identifier) == 1: // a == b
		return 0
	case a.Identifier.LessOrEqual(b.Identifier) == 1: // a < b
		return -1
	default:
		return 1
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

// Encode serializes a whole commitment list.
func (c CommitmentList) Encode() []byte {
	var encoded []byte

	for _, l := range c {
		e := internal.Concatenate(l.Identifier.Encode(), l.HidingNonce.Encode(), l.BindingNonce.Encode())
		encoded = append(encoded, e...)
	}

	return encoded
}

// Participants returns the list of participants in the commitment list.
func (c CommitmentList) Participants() []*group.Scalar {
	identifiers := make([]*group.Scalar, len(c))
	for i, l := range c {
		identifiers[i] = l.Identifier
	}

	return identifiers
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c CommitmentList) Get(identifier *group.Scalar) *Commitment {
	for _, com := range c {
		if com.Identifier.Equal(identifier) == 1 {
			return com
		}
	}

	return nil
}
