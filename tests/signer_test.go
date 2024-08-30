// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"fmt"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
)

func TestLambdaRegistry(t *testing.T) {
	g := group.Ristretto255Sha512
	id := uint64(2)
	participants := []uint64{1, 2, 3, 4}
	lambdas := make(internal.LambdaRegistry)

	// Get should return nil
	if lambda := lambdas.Get(participants); lambda != nil {
		t.Fatal("unexpected result")
	}

	// Create a new entry
	lambda := lambdas.New(g, id, participants)

	if lambda == nil {
		t.Fatal("unexpected result")
	}

	// Getting the same entry
	lambda2 := lambdas.Get(participants)
	if lambda.Equal(lambda2) != 1 {
		t.Fatal("expected equality")
	}

	lambda3 := lambdas.GetOrNew(g, id, participants)

	if lambda.Equal(lambda3) != 1 {
		t.Fatal("expected equality")
	}

	// Getting another entry must result in another returned value
	lambda4 := lambdas.GetOrNew(g, id, participants[:3])

	if lambda.Equal(lambda4) == 1 {
		t.Fatal("unexpected equality")
	}

	lambda5 := lambdas.GetOrNew(g, id, participants[:3])

	if lambda4.Equal(lambda5) != 1 {
		t.Fatal("expected equality")
	}

	// Removing and checking for the same entry
	lambdas.Delete(participants)
	if lambda = lambdas.Get(participants); lambda != nil {
		t.Fatal("unexpected result")
	}

	// Setting must return the same value
	lambda6 := g.NewScalar().Random()
	lambdas.Set(participants, lambda6)
	lambda7 := lambdas.Get(participants)

	if lambda6.Equal(lambda7) != 1 {
		t.Fatal("expected equality")
	}
}

func TestSigner_VerifyCommitmentList_InvalidCommitmentList(t *testing.T) {
	expectedErrorPrefix := "invalid list of commitments: commitment list is empty"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	_, signers := fullSetup(t, tt)

	if err := signers[0].VerifyCommitmentList(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestSigner_VerifyCommitmentList_MissingCommitment(t *testing.T) {
	expectedErrorPrefix := "signer identifier 1 not found in the commitment list"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	_, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if err := signers[0].VerifyCommitmentList(coms[1:]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestSigner_VerifyCommitmentList_MissingNonce(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	_, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	delete(signers[0].NonceCommitments, coms[0].CommitmentID)
	expectedErrorPrefix := fmt.Sprintf(
		"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
		coms[0].CommitmentID,
		coms[0].SignerID,
	)

	if err := signers[0].VerifyCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestSigner_VerifyCommitmentList_BadHidingNonce(t *testing.T) {
	expectedErrorPrefix := "invalid hiding nonce in commitment list for signer 1"

	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	_, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	signers[0].NonceCommitments[coms[0].CommitmentID].HidingNonceCommitment.Base()

	if err := signers[0].VerifyCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestSigner_VerifyCommitmentList_BadBindingNonce(t *testing.T) {
	expectedErrorPrefix := "invalid binding nonce in commitment list for signer 1"

	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	_, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	signers[0].NonceCommitments[coms[0].CommitmentID].BindingNonceCommitment.Base()

	if err := signers[0].VerifyCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}
