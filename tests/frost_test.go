// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
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
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/hash"
)

var configurationTable = []frost.Configuration{
	{
		GroupPublicKey: nil,
		Ciphersuite: internal.Ciphersuite{
			ContextString: []byte("FROST-ED25519-SHA512-v1"),
			Hash:          hash.SHA512,
			Group:         group.Edwards25519Sha512,
		},
	},
	{
		Ciphersuite: internal.Ciphersuite{
			Group:         group.Ristretto255Sha512,
			Hash:          hash.SHA512,
			ContextString: []byte("FROST-RISTRETTO255-SHA512-v1"),
		},
		GroupPublicKey: nil,
	},
	{
		Ciphersuite: internal.Ciphersuite{
			Group:         group.P256Sha256,
			Hash:          hash.SHA256,
			ContextString: []byte("FROST-P256-SHA256-v1"),
		},
		GroupPublicKey: nil,
	},
	{
		GroupPublicKey: nil,
		Ciphersuite: internal.Ciphersuite{
			ContextString: []byte("FROST-secp256k1-SHA256-v1"),
			Hash:          hash.SHA256,
			Group:         group.Secp256k1,
		},
	},
}

func TestTrustedDealerKeygen(t *testing.T) {
	threshold := 3
	maxSigners := 5

	testAll(t, func(t2 *testing.T, configuration *frost.Configuration) {
		g := configuration.Ciphersuite.Group

		groupSecretKey := g.NewScalar().Random()

		keyShares, dealerGroupPubKey, secretsharingCommitment, err := frost.TrustedDealerKeygen(
			g,
			groupSecretKey,
			maxSigners,
			threshold,
		)
		if err != nil {
			t.Fatal(err)
		}

		if len(secretsharingCommitment) != threshold {
			t2.Fatalf("%d / %d", len(secretsharingCommitment), threshold)
		}

		recoveredKey, err := configuration.RecoverGroupSecret(keyShares[:threshold])
		if err != nil {
			t.Fatal(err)
		}

		if recoveredKey.Equal(groupSecretKey) != 1 {
			t.Fatal()
		}

		groupPublicKey, participantPublicKeys := frost.DeriveGroupInfo(g, maxSigners, secretsharingCommitment)
		if len(participantPublicKeys) != maxSigners {
			t2.Fatal()
		}

		if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
			t2.Fatal()
		}

		configuration.GroupPublicKey = dealerGroupPubKey

		for i, shareI := range keyShares {
			if !frost.VerifyVSS(g, shareI, secretsharingCommitment) {
				t2.Fatal(i)
			}
		}

		pkEnc := groupPublicKey.Encode()

		recoveredPK := g.NewElement()
		if err := recoveredPK.Decode(pkEnc); err != nil {
			t2.Fatal(err)
		}

		if recoveredPK.Equal(groupPublicKey) != 1 {
			t2.Fatal()
		}
	})
}

func TestFrost(t *testing.T) {
	maxSigner := 3
	threshold := 2
	message := []byte("test")

	testAll(t, func(t2 *testing.T, configuration *frost.Configuration) {
		g := configuration.Ciphersuite.Group

		keyShares, groupPublicKey := simulateDKG(t, g, maxSigner, threshold)
		configuration.GroupPublicKey = groupPublicKey

		// Create Participants
		participants := make(ParticipantList, threshold)
		for i, share := range keyShares[:threshold] {
			participants[i] = configuration.Participant(share)
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
			sigShares[i], err = p.Sign(message, commitments)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Final step: aggregate
		signature := configuration.AggregateSignatures(message, sigShares, commitments)
		if !configuration.VerifySignature(message, signature) {
			t2.Fatal()
		}

		// Sanity Check
		groupSecretKey, err := configuration.RecoverGroupSecret(keyShares)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(groupSecretKey.Hex())

		singleSig := configuration.Sign(message, groupSecretKey)
		if !configuration.VerifySignature(message, singleSig) {
			t2.Fatal()
		}
	})
}

func testAll(t *testing.T, f func(*testing.T, *frost.Configuration)) {
	for _, test := range configurationTable {
		t.Run(string(test.Ciphersuite.ContextString), func(t *testing.T) {
			f(t, &test)
		})
	}
}

func TestMaliciousSigner(t *testing.T) {

}
