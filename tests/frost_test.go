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

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/commitment"
	"github.com/bytemare/frost/debug"
)

type tableTest struct {
	frost.Ciphersuite
}

var testTable = []tableTest{
	{
		Ciphersuite: frost.Ed25519,
	},
	{
		Ciphersuite: frost.Ristretto255,
	},
	{
		Ciphersuite: frost.P256,
	},
	{
		Ciphersuite: frost.Secp256k1,
	},
}

func TestTrustedDealerKeygen(t *testing.T) {
	threshold := uint64(3)
	maxSigners := uint64(5)

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()

		groupSecretKey := g.NewScalar().Random()

		keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			groupSecretKey,
			threshold,
			maxSigners,
		)

		if uint64(len(secretsharingCommitment)) != threshold {
			t.Fatalf("%d / %d", len(secretsharingCommitment), threshold)
		}

		recoveredKey, err := debug.RecoverGroupSecret(test.Ciphersuite, keyShares[:threshold])
		if err != nil {
			t.Fatal(err)
		}

		if recoveredKey.Equal(groupSecretKey) != 1 {
			t.Fatal()
		}

		groupPublicKey, participantPublicKeys, err := debug.RecoverPublicKeys(
			test.Ciphersuite,
			maxSigners,
			secretsharingCommitment,
		)
		if err != nil {
			t.Fatal(err)
		}

		if uint64(len(participantPublicKeys)) != maxSigners {
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

func runFrost(
	t *testing.T,
	test *tableTest,
	threshold, maxSigners uint64,
	message []byte,
	keyShares []*frost.KeyShare,
	groupPublicKey *group.Element,
) {
	// At key generation, each participant must send their public key share to the coordinator, and the collection
	// must be broadcast to every participant.
	publicKeyShares := make([]*frost.PublicKeyShare, 0, len(keyShares))
	for _, ks := range keyShares {
		publicKeyShares = append(publicKeyShares, ks.Public())
	}

	// Set up configuration.
	configuration := &frost.Configuration{
		Ciphersuite:      test.Ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		panic(err)
	}

	// Create Participants
	participants := make(ParticipantList, threshold)
	for i, ks := range keyShares[:threshold] {
		signer, err := configuration.Signer(ks)
		if err != nil {
			panic(err)
		}

		participants[i] = signer
	}

	// Round One: Commitment
	commitments := make(commitment.List, threshold)
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
	signature, err := configuration.AggregateSignatures(message, sigShares, commitments, true)
	if err != nil {
		t.Fatal(err)
	}

	if err = frost.VerifySignature(test.Ciphersuite, message, signature, groupPublicKey); err != nil {
		t.Fatal(err)
	}

	// Sanity Check
	groupSecretKey, err := debug.RecoverGroupSecret(test.Ciphersuite, keyShares)
	if err != nil {
		t.Fatal(err)
	}

	singleSig, err := debug.Sign(test.Ciphersuite, message, groupSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = frost.VerifySignature(test.Ciphersuite, message, singleSig, groupPublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestFrost_WithTrustedDealer(t *testing.T) {
	maxSigners := uint64(3)
	threshold := uint64(2)
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()
		sk := g.NewScalar().Random()
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, sk, threshold, maxSigners)
		runFrost(t, test, threshold, maxSigners, message, keyShares, groupPublicKey)
	})
}

func TestFrost_WithDKG(t *testing.T) {
	maxSigners := uint64(3)
	threshold := uint64(2)
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()
		keyShares, groupPublicKey, _ := runDKG(t, g, maxSigners, threshold)
		runFrost(t, test, threshold, maxSigners, message, keyShares, groupPublicKey)
	})
}

func testAll(t *testing.T, f func(*testing.T, *tableTest)) {
	for _, test := range testTable {
		t.Run(string(test.ECGroup()), func(t *testing.T) {
			f(t, &test)
		})
	}
}

func TestMaliciousSigner(t *testing.T) {
}
