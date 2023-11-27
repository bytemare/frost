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
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
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
	min := 2
	max := 3

	testAll(t, func(t2 *testing.T, configuration *frost.Configuration) {
		g := configuration.Ciphersuite.Group

		groupSecretKey := g.NewScalar().Random()

		privateKeyShares, dealerGroupPubKey, secretsharingCommitment, err := frost.TrustedDealerKeygen(
			g,
			groupSecretKey,
			max,
			min,
		)
		if err != nil {
			t.Fatal(err)
		}

		if len(secretsharingCommitment) != min {
			t2.Fatalf("%d / %d", len(secretsharingCommitment), min)
		}

		recoveredKey, err := secretsharing.Combine(g, uint(min), privateKeyShares)
		if err != nil {
			t.Fatal(err)
		}

		if recoveredKey.Equal(groupSecretKey) != 1 {
			t.Fatal()
		}

		groupPublicKey, participantPublicKeys := frost.DeriveGroupInfo(g, max, secretsharingCommitment)
		if len(participantPublicKeys) != max {
			t2.Fatal()
		}

		if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
			t2.Fatal()
		}

		configuration.GroupPublicKey = dealerGroupPubKey

		for i, shareI := range privateKeyShares {
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
	max := 3
	threshold := 2
	participantListInt := []int{1, 3}
	message := []byte("test")

	testAll(t, func(t2 *testing.T, configuration *frost.Configuration) {
		g := configuration.Ciphersuite.Group

		privateKeyShares, _, groupPublicKey := SimulateDKG(configuration, max, threshold)
		configuration.GroupPublicKey = groupPublicKey

		// Create Participants
		participants := make(ParticipantList, max)
		for i, share := range privateKeyShares {
			participants[i] = configuration.Participant(share.Identifier, share.SecretKey)
		}

		signatureAggregator := &frost.Participant{
			Configuration: *configuration,
		}

		// Round One: Commitment
		participantList := make([]*group.Scalar, len(participantListInt))
		for i, p := range participantListInt {
			participantList[i] = internal.IntegerToScalar(g, p)
		}

		comList := make(frost.CommitmentList, len(participantList))
		for i, id := range participantList {
			p := participants.Get(id)
			comList[i] = p.Commit()
		}

		comList.Sort()

		// Round Two: Sign
		sigShares := make([]*frost.SignatureShare, len(participantList))
		for i, id := range participantList {
			p := participants.Get(id)

			sigShare, err := p.Sign(message, comList)
			if err != nil {
				t.Fatal(err)
			}

			sigShares[i] = sigShare
		}

		// Final step: aggregate
		_ = signatureAggregator.Aggregate(comList, message, sigShares)

		// Sanity Check
		groupSecretKey, err := secretsharing.Combine(g, uint(threshold), privateKeyShares)
		if err != nil {
			t.Fatal(err)
		}

		singleSig := frost.Sign(configuration.Ciphersuite, message, groupSecretKey)
		if !frost.Verify(configuration.Ciphersuite, message, singleSig, groupPublicKey) {
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
