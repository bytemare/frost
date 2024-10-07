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
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/frost"
)

func TestCommitment_Validate_InvalidConfiguration(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration := &frost.Configuration{
		Ciphersuite:           tt.Ciphersuite,
		Threshold:             tt.threshold,
		MaxSigners:            tt.maxSigners,
		GroupPublicKey:        nil,
		SignerPublicKeyShares: nil,
	}

	if err := configuration.ValidateCommitment(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_NilCommitment(t *testing.T) {
	expectedErrorPrefix := "the commitment is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration := makeConf(t, tt)

	if err := configuration.ValidateCommitment(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_SignerIDs0(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	commitment := signers[0].Commit()
	commitment.SignerID = 0
	expectedErrorPrefix := fmt.Sprintf(
		"invalid identifier for signer in commitment %d, the identifier is 0",
		commitment.CommitmentID,
	)

	if err := configuration.ValidateCommitment(commitment); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_SignerIDInvalid(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	commitment := signers[0].Commit()
	commitment.SignerID = tt.maxSigners + 1
	expectedErrorPrefix := fmt.Sprintf(
		"invalid identifier for signer in commitment %d, the identifier %d is above authorized range [1:%d]",
		commitment.CommitmentID,
		commitment.SignerID,
		tt.maxSigners,
	)

	if err := configuration.ValidateCommitment(commitment); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_WrongGroup(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	com := signers[0].Commit()
	commitment := &frost.Commitment{
		HidingNonceCommitment:  com.HidingNonceCommitment,
		BindingNonceCommitment: com.BindingNonceCommitment,
		CommitmentID:           com.CommitmentID,
		SignerID:               com.SignerID,
		Group:                  0,
	}
	expectedErrorPrefix := fmt.Sprintf(
		"commitment %d for participant 1 has an unexpected ciphersuite: expected ristretto255_XMD:SHA-512_R255MAP_RO_, got 0",
		com.CommitmentID,
	)

	if err := configuration.ValidateCommitment(commitment); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_BadHidingNonceCommitment(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	com := signers[0].Commit()

	// nil
	expectedErrorPrefix := fmt.Sprintf(
		"invalid commitment %d for signer %d, the hiding nonce commitment is nil",
		com.CommitmentID,
		com.SignerID,
	)

	com.HidingNonceCommitment = nil
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// point at infinity
	expectedErrorPrefix = fmt.Sprintf(
		"invalid commitment %d for signer %d, the hiding nonce commitment is the identity element",
		com.CommitmentID,
		com.SignerID,
	)

	com.HidingNonceCommitment = tt.Group().NewElement()
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// generator
	expectedErrorPrefix = fmt.Sprintf(
		"invalid commitment %d for signer %d, the hiding nonce commitment is the group generator (base element)",
		com.CommitmentID,
		com.SignerID,
	)

	com.HidingNonceCommitment.Base()
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitment_Validate_BadBindingNonceCommitment(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	com := signers[0].Commit()

	// nil
	expectedErrorPrefix := fmt.Sprintf(
		"invalid commitment %d for signer %d, the binding nonce commitment is nil",
		com.CommitmentID,
		com.SignerID,
	)

	com.BindingNonceCommitment = nil
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// point at infinity
	expectedErrorPrefix = fmt.Sprintf(
		"invalid commitment %d for signer %d, the binding nonce commitment is the identity element",
		com.CommitmentID,
		com.SignerID,
	)

	com.BindingNonceCommitment = tt.Group().NewElement()
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// generator
	expectedErrorPrefix = fmt.Sprintf(
		"invalid commitment %d for signer %d, the binding nonce commitment is the group generator (base element)",
		com.CommitmentID,
		com.SignerID,
	)

	com.BindingNonceCommitment.Base()
	if err := configuration.ValidateCommitment(com); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Sort(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))

		// signer A < signer B
		coms[0] = signers[0].Commit()
		coms[1] = signers[1].Commit()
		coms[2] = signers[2].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}

		// signer B > singer A
		coms[0] = signers[1].Commit()
		coms[1] = signers[0].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}

		// signer B > singer A
		coms[0] = signers[0].Commit()
		coms[1] = signers[2].Commit()
		coms[2] = signers[2].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}
	})
}

func TestCommitmentList_Validate_InvalidConfiguration(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration := &frost.Configuration{
		Ciphersuite:           tt.Ciphersuite,
		Threshold:             tt.threshold,
		MaxSigners:            tt.maxSigners,
		GroupPublicKey:        nil,
		SignerPublicKeyShares: nil,
	}

	if err := configuration.ValidateCommitmentList(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_NoCommitments(t *testing.T) {
	expectedErrorPrefix := "commitment list is empty"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if err := configuration.ValidateCommitmentList(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	if err := configuration.ValidateCommitmentList(frost.CommitmentList{}); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_InsufficientCommitments(t *testing.T) {
	expectedErrorPrefix := "too few commitments: expected at least 2 but got 1"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if err := configuration.ValidateCommitmentList(coms[:tt.threshold-1]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_TooManyCommitments(t *testing.T) {
	expectedErrorPrefix := "too many commitments: expected 3 or less but got 4"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers)+1)

	for i, s := range signers {
		coms[i] = s.Commit()
	}
	coms[len(signers)] = coms[0].Copy()

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_DuplicateSignerIDs(t *testing.T) {
	expectedErrorPrefix := "commitment list contains multiple commitments of participant 2"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[2].SignerID = coms[1].SignerID

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_InvalidCommitment(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[2].BindingNonceCommitment.Base()
	expectedErrorPrefix := fmt.Sprintf(
		"invalid commitment %d for signer %d, the binding nonce commitment is the group generator (base element)",
		coms[2].CommitmentID,
		coms[2].SignerID,
	)

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_NilCommitment(t *testing.T) {
	expectedErrorPrefix := "the commitment list has a nil commitment"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[2] = nil

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_NotSorted(t *testing.T) {
	expectedErrorPrefix := "commitment list is not sorted by signer identifiers"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[1].SignerID, coms[2].SignerID = coms[2].SignerID, coms[1].SignerID

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_Validate_UnregisteredKey(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  4,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	configuration.SignerPublicKeyShares = slices.Delete(configuration.SignerPublicKeyShares, 1, 2)
	expectedErrorPrefix := fmt.Sprintf(
		"signer identifier %d for commitment %d is not registered in the configuration",
		coms[1].SignerID,
		coms[1].CommitmentID,
	)

	if err := configuration.ValidateCommitmentList(coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestCommitmentList_ParticipantsScalar_Empty(t *testing.T) {
	com := frost.CommitmentList{}
	if out := com.ParticipantsScalar(); out != nil {
		t.Fatal("unexpected output")
	}

	com = frost.CommitmentList{nil, nil}
	if out := com.ParticipantsScalar(); out != nil {
		t.Fatal("unexpected output")
	}
}
