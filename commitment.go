// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/ecc"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
)

var (
	errInvalidCiphersuite      = errors.New("ciphersuite not available")
	errInvalidLength           = errors.New("invalid encoding length")
	errCommitmentNil           = errors.New("the commitment is nil")
	errCommitmentListEmpty     = errors.New("commitment list is empty")
	errCommitmentListNotSorted = errors.New("commitment list is not sorted by signer identifiers")
	errCommitmentListHasNil    = errors.New("the commitment list has a nil commitment")
)

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	HidingNonceCommitment  *ecc.Element `json:"hidingNonceCommitment"`
	BindingNonceCommitment *ecc.Element `json:"bindingNonceCommitment"`
	CommitmentID           uint64       `json:"commitmentId"`
	SignerID               uint16       `json:"signerId"`
	Group                  ecc.Group    `json:"group"`
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

// CommitmentList is a sortable list of commitments with search functions.
type CommitmentList []*Commitment

// cmpID returns a negative number when the signer identity of a < b, a positive number when
// a > b and zero when a == b.
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
	if !c.IsSorted() {
		slices.SortFunc(c, cmpID)
	}
}

// IsSorted returns whether the list is sorted in ascending order by identifier.
func (c CommitmentList) IsSorted() bool {
	return slices.IsSortedFunc(c, cmpID)
}

// Get returns the commitment of the participant with the corresponding identifier, or nil if it was not found.
func (c CommitmentList) Get(identifier uint16) *Commitment {
	for _, com := range c {
		if com.SignerID == identifier {
			return com
		}
	}

	return nil
}

// Participants returns the uint64 list of participant identifiers in the list.
func (c CommitmentList) Participants() []uint16 {
	out := make([]uint16, len(c))

	for i, com := range c {
		out[i] = com.SignerID
	}

	return out
}

// ParticipantsScalar returns the ecc.Scalar list of participant identifier in the list.
func (c CommitmentList) ParticipantsScalar() []*ecc.Scalar {
	if len(c) == 0 {
		return nil
	}

	if c[0] == nil {
		return nil
	}

	g := c[0].Group

	return secretsharing.NewPolynomialFromListFunc(g, c, func(c *Commitment) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(c.SignerID))
	})
}

// Encode serializes the CommitmentList into a compact byte encoding.
func (c CommitmentList) Encode() []byte {
	n := len(c)
	if n == 0 {
		return nil
	}

	g := c[0].Group
	_, comLength := encodedLength(encCommitment, g)
	size := 1 + 2 + n*comLength
	out := make([]byte, 3, size)
	out[0] = byte(g)
	binary.LittleEndian.PutUint16(out[1:3], uint16(n))

	for _, com := range c {
		out = append(out, com.Encode()...)
	}

	return out
}

// DecodeList decodes a byte string produced by the CommitmentList.Encode() method.
func DecodeList(data []byte) (CommitmentList, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf(errFmt, errDecodeCommitmentListPrefix, internal.ErrInvalidLength)
	}

	g := ecc.Group(data[0])
	if !g.Available() {
		return nil, fmt.Errorf(errFmt, errDecodeCommitmentListPrefix, internal.ErrInvalidCiphersuite)
	}

	n := int(binary.LittleEndian.Uint16(data[1:3]))
	_, comLength := encodedLength(encCommitment, g)
	size := 1 + 2 + n*comLength

	if len(data) != size {
		return nil, fmt.Errorf(errFmt, errDecodeCommitmentListPrefix, internal.ErrInvalidLength)
	}

	c := make(CommitmentList, 0, n)

	for offset := 3; offset < len(data); offset += comLength {
		com := new(Commitment)
		if err := com.Decode(data[offset : offset+comLength]); err != nil {
			return nil, fmt.Errorf("%w: invalid encoding of commitment: %w", errDecodeCommitmentListPrefix, err)
		}

		c = append(c, com)
	}

	return c, nil
}

func (c CommitmentList) groupCommitmentAndBindingFactors(
	publicKey *ecc.Element,
	message []byte,
) (*ecc.Element, BindingFactors) {
	bindingFactors := c.bindingFactors(publicKey, message)
	groupCommitment := c.groupCommitment(bindingFactors)

	return groupCommitment, bindingFactors
}

type commitmentWithEncodedID struct {
	*Commitment   `json:"commitment"`
	ParticipantID []byte `json:"participantId"`
}

func commitmentsWithEncodedID(g ecc.Group, commitments CommitmentList) []*commitmentWithEncodedID {
	r := make([]*commitmentWithEncodedID, len(commitments))
	for i, com := range commitments {
		r[i] = &commitmentWithEncodedID{
			ParticipantID: g.NewScalar().SetUInt64(uint64(com.SignerID)).Encode(),
			Commitment:    com,
		}
	}

	return r
}

func encodeCommitmentList(g ecc.Group, commitments []*commitmentWithEncodedID) []byte {
	size := len(commitments) * (g.ScalarLength() + 2*g.ElementLength())
	encoded := make([]byte, 0, size)

	for _, com := range commitments {
		encoded = append(encoded, com.ParticipantID...)
		encoded = append(encoded, com.HidingNonceCommitment.Encode()...)
		encoded = append(encoded, com.BindingNonceCommitment.Encode()...)
	}

	return encoded
}

// BindingFactors is a map of participant identifiers to BindingFactors.
type BindingFactors map[uint16]*ecc.Scalar

func (c CommitmentList) bindingFactors(publicKey *ecc.Element, message []byte) BindingFactors {
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

func (c CommitmentList) groupCommitment(bf BindingFactors) *ecc.Element {
	g := c[0].Group
	gc := g.NewElement()

	for _, com := range c {
		factor := bf[com.SignerID]
		bindingNonce := com.BindingNonceCommitment.Copy().Multiply(factor)
		gc.Add(com.HidingNonceCommitment).Add(bindingNonce)
	}

	return gc
}

func (c *Configuration) isSignerRegistered(sid uint16) bool {
	for _, peer := range c.SignerPublicKeyShares {
		if peer.ID == sid {
			return true
		}
	}

	return false
}

// ValidateCommitment returns an error if the commitment is not valid.
func (c *Configuration) ValidateCommitment(commitment *Commitment) error {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return err
		}
	}

	if commitment == nil {
		return errCommitmentNil
	}

	if err := c.validateIdentifier(commitment.SignerID); err != nil {
		return fmt.Errorf("invalid identifier for signer in commitment %d, the %w", commitment.CommitmentID, err)
	}

	if commitment.Group != c.group {
		return fmt.Errorf(
			"commitment %d for participant %d has an unexpected ciphersuite: expected %s, got %d",
			commitment.CommitmentID,
			commitment.SignerID,
			c.group,
			commitment.Group,
		)
	}

	if err := c.validateGroupElement(commitment.HidingNonceCommitment); err != nil {
		return fmt.Errorf(
			"invalid commitment %d for signer %d, the hiding nonce commitment %w",
			commitment.CommitmentID,
			commitment.SignerID,
			err,
		)
	}

	if err := c.validateGroupElement(commitment.BindingNonceCommitment); err != nil {
		return fmt.Errorf(
			"invalid commitment %d for signer %d, the binding nonce commitment %w",
			commitment.CommitmentID,
			commitment.SignerID,
			err,
		)
	}

	// Validate that the commitment comes from a registered signer.
	if !c.isSignerRegistered(commitment.SignerID) {
		return fmt.Errorf(
			"signer identifier %d for commitment %d is not registered in the configuration",
			commitment.SignerID,
			commitment.CommitmentID,
		)
	}

	return nil
}

func (c *Configuration) validateCommitmentListLength(commitments CommitmentList) error {
	length := uint16(len(commitments))

	if length == 0 {
		return errCommitmentListEmpty
	}

	if length < c.Threshold {
		return fmt.Errorf("too few commitments: expected at least %d but got %d", c.Threshold, length)
	}

	if length > c.MaxSigners {
		return fmt.Errorf("too many commitments: expected %d or less but got %d", c.MaxSigners, length)
	}

	return nil
}

// ValidateCommitmentList returns an error if at least one of the following conditions is not met:
// - list length is within [threshold;max].
// - no signer identifier in commitments is 0.
// - no singer identifier in commitments is > max signers.
// - no duplicated in signer identifiers.
// - all commitment signer identifiers are registered in the configuration.
func (c *Configuration) ValidateCommitmentList(commitments CommitmentList) error {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return err
		}
	}

	if err := c.validateCommitmentListLength(commitments); err != nil {
		return err
	}

	// set to detect duplication
	set := make(map[uint16]struct{}, len(commitments))

	for i, commitment := range commitments {
		// Check general validity of the commitment.
		if err := c.ValidateCommitment(commitment); err != nil {
			return err
		}

		// Check for duplicate participant entries.
		if _, exists := set[commitment.SignerID]; exists {
			return fmt.Errorf("commitment list contains multiple commitments of participant %d", commitment.SignerID)
		}

		set[commitment.SignerID] = struct{}{}

		// List must be sorted, compare with the next commitment.
		if i <= len(commitments)-2 {
			if err := compareCommitments(commitment, commitments[i+1]); err != nil {
				return err
			}
		}
	}

	return nil
}

func compareCommitments(c1, c2 *Commitment) error {
	if c2 == nil {
		return errCommitmentListHasNil
	}

	// if the current commitment has an id higher than the next one, return error.
	if cmpID(c1, c2) > 0 {
		return errCommitmentListNotSorted
	}

	return nil
}
