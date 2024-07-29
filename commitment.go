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
	"slices"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
)

var errDecodeCommitmentLength = errors.New("failed to decode commitment: invalid length")

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	PublicKey     *group.Element
	HidingNonce   *group.Element
	BindingNonce  *group.Element
	CommitmentID  uint64
	ParticipantID uint64
	Ciphersuite   Ciphersuite
}

func commitmentEncodedSize(g group.Group) int {
	return 1 + 8 + 8 + 3*g.ElementLength()
}

// Encode returns the serialized byte encoding of a participant's commitment.
func (c *Commitment) Encode() []byte {
	hNonce := c.HidingNonce.Encode()
	bNonce := c.BindingNonce.Encode()
	pubKey := c.PublicKey.Encode()

	out := make([]byte, 9, commitmentEncodedSize(group.Group(c.Ciphersuite)))
	out[0] = byte(c.Ciphersuite)
	binary.LittleEndian.PutUint64(out[1:], c.CommitmentID)
	binary.LittleEndian.PutUint64(out[9:], c.ParticipantID)
	copy(out[17:], hNonce)
	copy(out[17+len(hNonce):], bNonce)
	copy(out[17+len(hNonce)+len(bNonce):], pubKey)

	return out
}

// Decode attempts to deserialize the encoded commitment given as input, and to return it.
func (c *Commitment) Decode(data []byte) error {
	if len(data) < 16 {
		return errDecodeCommitmentLength
	}

	cs := Ciphersuite(data[0])
	if !cs.Available() {
		return internal.ErrInvalidCiphersuite
	}

	g := cs.Group()

	if len(data) != commitmentEncodedSize(g) {
		return errDecodeCommitmentLength
	}

	cID := binary.LittleEndian.Uint64(data[1:9])
	pID := binary.LittleEndian.Uint64(data[9:17])
	offset := 17 + g.ElementLength()

	hn := g.NewElement()
	if err := hn.Decode(data[17:offset]); err != nil {
		return fmt.Errorf("invalid encoding of hiding nonce: %w", err)
	}

	bn := g.NewElement()
	if err := bn.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("invalid encoding of binding nonce: %w", err)
	}

	offset += g.ElementLength()

	pk := g.NewElement()
	if err := pk.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("invalid encoding of public key: %w", err)
	}

	c.Ciphersuite = cs
	c.CommitmentID = cID
	c.ParticipantID = pID
	c.HidingNonce = hn
	c.BindingNonce = bn
	c.PublicKey = pk

	return nil
}

// CommitmentList is a sortable list of commitments.
type CommitmentList []*Commitment

func cmpID(a, b *Commitment) int {
	switch {
	case a.ParticipantID < b.ParticipantID: // a < b
		return -1
	case a.ParticipantID > b.ParticipantID:
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

// Encode serializes a whole commitment list.
func (c CommitmentList) Encode(g group.Group) []byte {
	var encoded []byte

	for _, l := range c {
		id := g.NewScalar().SetUInt64(l.ParticipantID).Encode()
		e := internal.Concatenate(id, l.HidingNonce.Encode(), l.BindingNonce.Encode())
		encoded = append(encoded, e...)
	}

	return encoded
}

// Participants returns the list of participants in the commitment list in the form of a polynomial.
func (c CommitmentList) Participants(g group.Group) secretsharing.Polynomial {
	return secretsharing.NewPolynomialFromListFunc(g, c, func(c *Commitment) *group.Scalar {
		return g.NewScalar().SetUInt64(c.ParticipantID)
	})
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c CommitmentList) Get(identifier uint64) *Commitment {
	for _, com := range c {
		if com.ParticipantID == identifier {
			return com
		}
	}

	return nil
}
