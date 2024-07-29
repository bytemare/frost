// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

type tableTest struct {
	frost.Configuration
	frost.Ciphersuite
}

var testTable = []tableTest{
	{
		Ciphersuite: frost.Ed25519,
		Configuration: frost.Configuration{
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte("FROST-ED25519-SHA512-v1"),
				Hash:          hash.SHA512,
				Group:         group.Edwards25519Sha512,
			},
		},
	},
	{
		Ciphersuite: frost.Ristretto255,
		Configuration: frost.Configuration{
			Ciphersuite: internal.Ciphersuite{
				Group:         group.Ristretto255Sha512,
				Hash:          hash.SHA512,
				ContextString: []byte("FROST-RISTRETTO255-SHA512-v1"),
			},
		},
	},
	{
		Ciphersuite: frost.P256,
		Configuration: frost.Configuration{
			Ciphersuite: internal.Ciphersuite{
				Group:         group.P256Sha256,
				Hash:          hash.SHA256,
				ContextString: []byte("FROST-P256-SHA256-v1"),
			},
		},
	},
	{
		Ciphersuite: frost.Secp256k1,
		Configuration: frost.Configuration{
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte("FROST-secp256k1-SHA256-v1"),
				Hash:          hash.SHA256,
				Group:         group.Secp256k1,
			},
		},
	},
}

func TestTrustedDealerKeygen(t *testing.T) {
	threshold := 3
	maxSigners := 5

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()

		groupSecretKey := g.NewScalar().Random()

		keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
			frost.Ciphersuite(g),
			groupSecretKey,
			maxSigners,
			threshold,
		)

		if len(secretsharingCommitment) != threshold {
			t.Fatalf("%d / %d", len(secretsharingCommitment), threshold)
		}

		recoveredKey, err := debug.RecoverGroupSecret(g, keyShares[:threshold])
		if err != nil {
			t.Fatal(err)
		}

		if recoveredKey.Equal(groupSecretKey) != 1 {
			t.Fatal()
		}

		groupPublicKey, participantPublicKeys := debug.RecoverPublicKeys(g, maxSigners, secretsharingCommitment)
		if len(participantPublicKeys) != maxSigners {
			t.Fatal()
		}

		if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
			t.Fatal()
		}

		for i, shareI := range keyShares {
			if !debug.VerifyVSS(g, shareI, secretsharingCommitment) {
				t.Fatal(i)
			}
		}

		pkEnc := groupPublicKey.Encode()

		recoveredPK := g.NewElement()
		if err := recoveredPK.Decode(pkEnc); err != nil {
			t.Fatal(err)
		}

		if recoveredPK.Equal(groupPublicKey) != 1 {
			t.Fatal()
		}
	})
}

func TestFrost_WithTrustedDealer(t *testing.T) {
	maxSigner := 3
	threshold := 2
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()
		sk := g.NewScalar().Random()

		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, sk, maxSigner, threshold)

		// Create Participants
		participants := make(ParticipantList, threshold)
		for i, share := range keyShares[:threshold] {
			participants[i] = test.Ciphersuite.Participant(share)
		}

		// Round One: Commitment
		commitments := make(frost.CommitmentList, threshold)
		for i, p := range participants {
			commitments[i] = p.Commit()
		}

		commitments.Sort()

		// Round Two: Sign
		sigShares := make([]*frost.SignatureShare, threshold)
		for i, p := range participants {
			var err error
			commitmentID := commitments.Get(p.Identifier()).CommitmentID
			sigShares[i], err = p.Sign(commitmentID, message, commitments)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Final step: aggregate
		signature := test.AggregateSignatures(message, sigShares, commitments, groupPublicKey)
		if !test.VerifySignature(message, signature, groupPublicKey) {
			t.Fatal()
		}

		// Sanity Check
		groupSecretKey, err := debug.RecoverGroupSecret(g, keyShares)
		if err != nil {
			t.Fatal(err)
		}

		if groupSecretKey.Equal(sk) != 1 {
			t.Fatal("expected equality in group secret key")
		}

		singleSig := test.Sign(message, groupSecretKey)
		if !test.VerifySignature(message, singleSig, groupPublicKey) {
			t.Fatal()
		}
	})
}

func TestFrost_WithDKG(t *testing.T) {
	maxSigner := 3
	threshold := 2
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()

		keyShares, groupPublicKey, _ := runDKG(t, g, maxSigner, threshold)

		// Create Participants
		participants := make(ParticipantList, threshold)
		for i, share := range keyShares[:threshold] {
			participants[i] = test.Ciphersuite.Participant(share)
		}

		// Round One: Commitment
		commitments := make(frost.CommitmentList, threshold)
		for i, p := range participants {
			commitments[i] = p.Commit()
		}

		commitments.Sort()

		// Round Two: Sign
		sigShares := make([]*frost.SignatureShare, threshold)
		for i, p := range participants {
			var err error
			commitmentID := commitments.Get(p.Identifier()).CommitmentID
			sigShares[i], err = p.Sign(commitmentID, message, commitments)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Final step: aggregate
		signature := test.AggregateSignatures(message, sigShares, commitments, groupPublicKey)
		if !test.VerifySignature(message, signature, groupPublicKey) {
			t.Fatal()
		}

		// Sanity Check
		groupSecretKey, err := debug.RecoverGroupSecret(g, keyShares)
		if err != nil {
			t.Fatal(err)
		}

		singleSig := test.Sign(message, groupSecretKey)
		if !test.VerifySignature(message, singleSig, groupPublicKey) {
			t.Fatal()
		}
	})
}

func testAll(t *testing.T, f func(*testing.T, *tableTest)) {
	for _, test := range testTable {
		t.Run(string(test.Configuration.ContextString), func(t *testing.T) {
			f(t, &test)
		})
	}
}

func TestMaliciousSigner(t *testing.T) {
}
