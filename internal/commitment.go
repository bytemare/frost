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

type Commitment struct {
	ID           *group.Scalar
	HidingNonce  *group.Element
	BindingNonce *group.Element
	IDint        int
}

type CommitmentList []Commitment

func (c CommitmentList) Len() int {
	return len(c)
}

func (c CommitmentList) Less(i, j int) bool {
	return c[i].ID.LessOrEqual(c[j].ID) == 1
}

func (c CommitmentList) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c CommitmentList) Sort() {
	sort.Sort(c)
}

// IsSorted returns whether the list is sorted in ascending order by identifier.
func (c CommitmentList) IsSorted() bool {
	return sort.IsSorted(c)
}

func (c CommitmentList) Encode() []byte {
	var encoded []byte
	for _, l := range c {
		e := Concatenate(l.ID.Encode(), l.HidingNonce.Encode(), l.BindingNonce.Encode())
		encoded = append(encoded, e...)
	}

	return encoded
}

func (c CommitmentList) Participants() []*group.Scalar {
	identifiers := make([]*group.Scalar, 0, len(c))
	for _, l := range c {
		identifiers = append(identifiers, l.ID)
	}

	return identifiers
}

func (c CommitmentList) ComputeBindingFactors(cs Ciphersuite, msg []byte) BindingFactorList {
	if !c.IsSorted() {
		panic(nil)
	}

	h := cs.H4(nil, msg)
	encodedCommitHash := cs.H5([]byte(""), c.Encode())
	rhoInputPrefix := append(h, encodedCommitHash...)

	bindingFactorList := make([]*BindingFactor, 0, len(c))
	rhoInputs := make([][]byte, 0, len(c))

	rhoInput := make([]byte, 0, len(rhoInputPrefix)+int(cs.Group.ScalarLength()))
	for _, l := range c {
		copy(rhoInput, rhoInputPrefix)
		rhoInput = append(rhoInput, l.ID.Encode()...)
		bindingFactor := cs.H1(rhoInput)

		bindingFactorList = append(bindingFactorList, &BindingFactor{
			Identifier:    l.ID,
			BindingFactor: bindingFactor,
		})
		rhoInputs = append(rhoInputs, rhoInput)
	}

	return bindingFactorList
}

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
