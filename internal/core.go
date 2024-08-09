// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/commitment"
)

// GroupCommitmentAndBindingFactors computes and returns the group commitment element and signers' binding factors.
func GroupCommitmentAndBindingFactors(
	g group.Group,
	message []byte,
	commitments commitment.List,
	pk *group.Element,
) (*group.Element, BindingFactors) {
	bindingFactors := computeBindingFactors(g, pk, commitments, message)
	groupCommitment := computeGroupCommitment(g, commitments, bindingFactors)

	return groupCommitment, bindingFactors
}

func computeLambda(g group.Group, commitments commitment.List, id uint64) (*group.Scalar, error) {
	participantList := commitments.Participants(g)

	l, err := participantList.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(id))
	if err != nil {
		return nil, fmt.Errorf("anomaly in participant identifiers: %w", err)
	}

	return l, nil
}

// ComputeChallengeFactor computes and returns the Schnorr challenge factor used in signing and verification.
func ComputeChallengeFactor(
	g group.Group,
	groupCommitment *group.Element,
	lambda *group.Scalar,
	id uint64,
	message []byte,
	commitments commitment.List,
	groupPublicKey *group.Element,
) (*group.Scalar, error) {
	// Compute the interpolating value
	if lambda == nil || lambda.IsZero() {
		l, err := computeLambda(g, commitments, id)
		if err != nil {
			return nil, err
		}

		lambda = l
	}

	// Compute per message challenge
	chall := SchnorrChallenge(g, message, groupCommitment, groupPublicKey)

	return chall.Multiply(lambda), nil
}

// BindingFactors is a map of participant identifier to BindingFactors.
type BindingFactors map[uint64]*group.Scalar

type commitmentWithEncodedID struct {
	*commitment.Commitment
	ParticipantID []byte
}

func commitmentsWithEncodedID(g group.Group, commitments commitment.List) []*commitmentWithEncodedID {
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

// computeBindingFactors computes binding factors based on the participant commitment list and the message to be signed.
func computeBindingFactors(
	g group.Group,
	publicKey *group.Element,
	commitments commitment.List,
	message []byte,
) BindingFactors {
	coms := commitmentsWithEncodedID(g, commitments)
	encodedCommitHash := H5(g, encodeCommitmentList(g, coms))
	h := H4(g, message)
	rhoInputPrefix := Concatenate(publicKey.Encode(), h, encodedCommitHash)
	bindingFactors := make(BindingFactors, len(commitments))

	for _, com := range coms {
		rhoInput := Concatenate(rhoInputPrefix, com.ParticipantID)
		bindingFactors[com.Commitment.SignerID] = H1(g, rhoInput)
	}

	return bindingFactors
}

func computeGroupCommitment(g group.Group, commitments commitment.List, bf BindingFactors) *group.Element {
	gc := g.NewElement()

	for _, com := range commitments {
		factor := bf[com.SignerID]
		bindingNonce := com.BindingNonce.Copy().Multiply(factor)
		gc.Add(com.HidingNonce).Add(bindingNonce)
	}

	return gc
}

// SchnorrChallenge computes the per-message SchnorrChallenge.
func SchnorrChallenge(g group.Group, msg []byte, r, pk *group.Element) *group.Scalar {
	return H2(g, Concatenate(r.Encode(), pk.Encode(), msg))
}

func verifyCommitment(g group.Group, com *commitment.Commitment) error {
	if com.Group != g {
		return fmt.Errorf(
			"commitment for participant %d has an unexpected ciphersuite: expected %s, got %s",
			com.SignerID,
			g,
			com.Group,
		)
	}

	if com.HidingNonce == nil || com.HidingNonce.IsIdentity() {
		return fmt.Errorf("hiding nonce for participant %d is nil or identity element", com.SignerID)
	}

	if com.BindingNonce == nil || com.BindingNonce.IsIdentity() {
		return fmt.Errorf("binding nonce for participant %d is nil or identity element", com.SignerID)
	}

	return nil
}

// VerifyCommitmentList checks for the Commitment list integrity.
func VerifyCommitmentList(g group.Group, coms commitment.List, threshold uint64) error {
	// Verify number of commitments.
	if uint64(len(coms)) < threshold {
		return fmt.Errorf("too few commitments: expected at least %d but got %d", threshold, len(coms))
	}

	// Ensure the list is sorted
	if !coms.IsSorted() {
		coms.Sort()
	}

	// set to detect duplication
	set := make(map[uint64]struct{}, len(coms))

	for _, com := range coms {
		// Check for duplicate participant entries.
		if _, exists := set[com.SignerID]; exists {
			return fmt.Errorf("commitment list contains multiple commitments of participant %d", com.SignerID)
		}

		set[com.SignerID] = struct{}{}

		// Check general consistency.
		if err := verifyCommitment(g, com); err != nil {
			return err
		}
	}

	return nil
}
