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
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
)

type tableTest struct {
	frost.Ciphersuite
	threshold, maxSigners uint64
}

var testTable = []tableTest{
	{
		Ciphersuite: frost.Ed25519,
		threshold:   2,
		maxSigners:  3,
	},
	{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	},
	{
		Ciphersuite: frost.P256,
		threshold:   2,
		maxSigners:  3,
	},
	{
		Ciphersuite: frost.Secp256k1,
		threshold:   2,
		maxSigners:  3,
	},
}

func runFrost(
	t *testing.T,
	test *tableTest,
	threshold, maxSigners uint64,
	message []byte,
	keyShares []*frost.KeyShare,
	groupPublicKey *group.Element,
) {
	// Collect public keys.
	publicKeyShares := getPublicKeyShares(keyShares)

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

	// Commit
	commitments := make(frost.CommitmentList, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}

	commitments.Sort()

	// Sign
	sigShares := make([]*frost.SignatureShare, threshold)
	for i, p := range participants {
		var err error
		sigShares[i], err = p.Sign(message, commitments)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Aggregate
	_, err := configuration.AggregateSignatures(message, sigShares, commitments, true)
	if err != nil {
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
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()
		sk := g.NewScalar().Random()
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, sk, test.threshold, test.maxSigners)
		runFrost(t, test, test.threshold, test.maxSigners, message, keyShares, groupPublicKey)
	})
}

func TestFrost_WithDKG(t *testing.T) {
	message := []byte("test")

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()
		keyShares, groupPublicKey, _ := runDKG(t, g, test.threshold, test.maxSigners)
		runFrost(t, test, test.threshold, test.maxSigners, message, keyShares, groupPublicKey)
	})
}

func testAll(t *testing.T, f func(*testing.T, *tableTest)) {
	for _, test := range testTable {
		t.Run(fmt.Sprintf("%s", test.ECGroup()), func(t *testing.T) {
			f(t, &test)
		})
	}
}

func TestMaliciousSigner(t *testing.T) {
}
