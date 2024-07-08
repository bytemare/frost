// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"encoding/binary"
	"errors"
	"fmt"
	secretsharing "github.com/bytemare/secret-sharing"
	"slices"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

var errDecodeCommitmentLength = errors.New("failed to decode commitment: invalid length")

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	Identifier   uint64
	PublicKey    *group.Element
	HidingNonce  *group.Element
	BindingNonce *group.Element
}

// Encode returns the serialized byte encoding of a participant's commitment.
func (c Commitment) Encode() []byte {
	id := c.Identifier
	hNonce := c.HidingNonce.Encode()
	bNonce := c.BindingNonce.Encode()

	out := make([]byte, 8, 8+len(hNonce)+len(bNonce))
	binary.LittleEndian.PutUint64(out, id)
	copy(out[8:], hNonce)
	copy(out[8+len(hNonce):], bNonce)

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
		Identifier:   0,
		HidingNonce:  g.NewElement(),
		BindingNonce: g.NewElement(),
	}

	c.Identifier = internal.UInt64FromLE(data[:scalarLength])

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
	case a.Identifier != b.Identifier: // a == b
		return 0
	case a.Identifier <= b.Identifier: // a < b
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
		e := internal.Concatenate(internal.UInt64LE(l.Identifier), l.HidingNonce.Encode(), l.BindingNonce.Encode())
		encoded = append(encoded, e...)
	}

	return encoded
}

// Participants returns the list of participants in the commitment list.
func (c CommitmentList) Participants(g group.Group) secretsharing.Polynomial {
	return secretsharing.NewPolynomialFromListFunc(g, c, func(c *Commitment) *group.Scalar {
		return g.NewScalar().SetUInt64(c.Identifier)
	})
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c CommitmentList) Get(identifier uint64) *Commitment {
	for _, com := range c {
		if com.Identifier == identifier {
			return com
		}
	}

	return nil
}
