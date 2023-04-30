// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"sort"

	group "github.com/bytemare/crypto"
)

// Commitment represent a participant's commitment.
type Commitment struct {
	ID           *group.Scalar
	HidingNonce  *group.Element
	BindingNonce *group.Element
}

// CommitmentList is a sortable list of commitments.
type CommitmentList []*Commitment

// Len implements the sort.Interface Len method.
func (c CommitmentList) Len() int {
	return len(c)
}

// Less implements the sort.Interface Less method.
func (c CommitmentList) Less(i, j int) bool {
	return c[i].ID.LessOrEqual(c[j].ID) == 1
}

// Swap implements the sort.Interface Swap method.
func (c CommitmentList) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// Sort sorts the list the ascending order of identifiers.
func (c CommitmentList) Sort() {
	sort.Sort(c)
}

// IsSorted returns whether the list is sorted in ascending order by identifier.
func (c CommitmentList) IsSorted() bool {
	return sort.IsSorted(c)
}

// Encode serializes a whole commitment list.
func (c CommitmentList) Encode() []byte {
	var encoded []byte

	for _, l := range c {
		e := Concatenate(l.ID.Encode(), l.HidingNonce.Encode(), l.BindingNonce.Encode())
		encoded = append(encoded, e...)
	}

	return encoded
}

// Participants returns the list of participants in the commitment list.
func (c CommitmentList) Participants() []*group.Scalar {
	identifiers := make([]*group.Scalar, len(c))
	for i, l := range c {
		identifiers[i] = l.ID
	}

	return identifiers
}

// ComputeBindingFactors computes binding factors based on the participant commitment list and the message to be signed.
// The rhoInputs are temporarily added for testing purposes and can be ignored.
func (c CommitmentList) ComputeBindingFactors(cs Ciphersuite, msg []byte) (l BindingFactorList, r [][]byte) {
	if !c.IsSorted() {
		panic(nil)
	}

	h := cs.H4(msg)
	encodedCommitHash := cs.H5(c.Encode())
	rhoInputPrefix := Concatenate(h, encodedCommitHash)

	bindingFactorList := make(BindingFactorList, len(c))
	rhoInputs := make([][]byte, len(c))

	for i, l := range c {
		rhoInput := Concatenate(rhoInputPrefix, l.ID.Encode())
		bindingFactor := cs.H1(rhoInput)

		bindingFactorList[i] = &BindingFactor{
			Identifier:    l.ID,
			BindingFactor: bindingFactor,
		}
		rhoInputs[i] = rhoInput
	}

	return bindingFactorList, rhoInputs
}

// ComputeGroupCommitment creates the group commitment from a commitment list.
func (c CommitmentList) ComputeGroupCommitment(cs Ciphersuite, list BindingFactorList) *group.Element {
	if !c.IsSorted() {
		panic(nil)
	}

	gc := cs.Group.NewElement().Identity()

	for _, commitment := range c {
		factor := list.BindingFactorForParticipant(commitment.ID)
		gc.Add(commitment.HidingNonce).Add(commitment.BindingNonce.Copy().Multiply(factor))
	}

	return gc
}
