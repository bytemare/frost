// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package commitment defines the FROST Signer commitment.
package commitment

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	group "github.com/bytemare/crypto"
)

var (
	errDecodeCommitmentLength = errors.New("failed to decode commitment: invalid length")
	errInvalidCiphersuite     = errors.New("ciphersuite not available")
	errInvalidLength          = errors.New("invalid encoding length")
)

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	HidingNonce  *group.Element
	BindingNonce *group.Element
	CommitmentID uint64
	SignerID     uint64
	Group        group.Group
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

// List is a sortable list of commitments.
type List []*Commitment

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
func (c List) Sort() {
	slices.SortFunc(c, cmpID)
}

// IsSorted returns whether the list is sorted in ascending order by identifier.
func (c List) IsSorted() bool {
	return slices.IsSortedFunc(c, cmpID)
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c List) Get(identifier uint64) *Commitment {
	for _, com := range c {
		if com.SignerID == identifier {
			return com
		}
	}

	return nil
}

func (c List) Encode() []byte {
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

func DecodeList(data []byte) (List, error) {
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

	c := make(List, 0, n)

	for offset := uint64(9); offset < uint64(len(data)); offset += es {
		com := new(Commitment)
		if err := com.Decode(data[offset : offset+es]); err != nil {
			return nil, fmt.Errorf("invalid encoding of commitment: %w", err)
		}

		c = append(c, com)
	}

	return c, nil
}
