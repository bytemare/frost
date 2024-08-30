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

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
)

func TestMaliciousSigner(t *testing.T) {
}

func TestVerifySignature_BadCiphersuite(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	if err := frost.VerifySignature(2, nil, nil, nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	expectedErrorPrefix := "invalid Signature"
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration, _ := fullSetup(t, test)

		signature := &frost.Signature{
			R: test.ECGroup().Base(),
			Z: test.ECGroup().NewScalar().Random(),
		}

		if err := frost.VerifySignature(test.Ciphersuite, message, signature, configuration.GroupPublicKey); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestSigner_Sign_NoNonceForCommitmentID(t *testing.T) {
	message := []byte("message")
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}

	signers := makeSigners(t, tt)

	coms := make(frost.CommitmentList, len(signers))
	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[0].CommitmentID = 0
	expectedErrorPrefix := fmt.Sprintf(
		"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
		coms[0].CommitmentID,
		coms[0].SignerID,
	)

	if _, err := signers[0].Sign(message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

/*
func TestSigner_Sign_FailedLambdaGeneration(t *testing.T) {
	call signer.Sign
}

func TestSigner_Sign_VerifyCommitmentList_BadCommitment(t *testing.T) {
	call signer.Sign
}

func TestSigner_Sign_VerifyCommitmentList_NoCommitmentForSigner(t *testing.T) {
	call signer.Sign
}

func TestSigner_Sign_VerifyNonces_BadCommitmentID(t *testing.T) {

}

func TestSigner_Sign_VerifyNonces_BadHidingNonceCommitment(t *testing.T) {

}

func TestSigner_Sign_VerifyNonces_BadBindingNonceCommitment(t *testing.T) {

}

*/
