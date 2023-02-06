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
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
	"github.com/bytemare/frost/internal/shamir"
)

var ciphersuiteTable = []frost.Ciphersuite{
	frost.Ristretto255, frost.P256, frost.Ed25519,
}

func TestFrost(t *testing.T) {
	min := 2
	max := 3
	participantListInt := []int{1, 3}
	message := []byte("test")

	testAll(t, func(t2 *testing.T, ciphersuite frost.Ciphersuite) {
		configuration := ciphersuite.Configuration()
		g := configuration.Ciphersuite.Group

		groupSecretKey := g.NewScalar().Random()

		privateKeyShares, dealerGroupPubKey, vssCommitment := frost.TrustedDealerKeygen(g, groupSecretKey, max, min)
		if len(vssCommitment) != min {
			t2.Fatalf("%d / %d", len(vssCommitment), min)
		}

		recoveredKey := shamir.Combine(g, privateKeyShares, min)
		if recoveredKey.Equal(groupSecretKey) != 1 {
			t.Fatal()
		}

		groupPublicKey, participantPublicKeys := frost.DeriveGroupInfo(g, max, vssCommitment)
		if len(participantPublicKeys) != max {
			t2.Fatal()
		}

		if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
			t2.Fatal()
		}

		configuration.GroupPublicKey = dealerGroupPubKey

		for i, shareI := range privateKeyShares {
			if !frost.Verify(g, shareI, vssCommitment) {
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

		// Create Participants
		participants := make(ParticipantList, len(privateKeyShares))
		for i, share := range privateKeyShares {
			participants[i] = configuration.Participant(share.Identifier, share.SecretKey)
		}

		// Round One: Commitment
		participantList := make([]*group.Scalar, len(participantListInt))
		for i, p := range participantListInt {
			participantList[i] = internal.IntegerToScalar(g, p)
		}

		comList := make(internal.CommitmentList, len(participantList))
		for i, id := range participantList {
			p := participants.Get(id)
			p.Commit()
			comList[i] = *p.Commit()
		}

		comList.Sort()
		_, _ = comList.ComputeBindingFactors(configuration.Ciphersuite, message)

		// Round Two: Sign
		sigShares := make([]*group.Scalar, len(participantList))
		for i, id := range participantList {
			p := participants.Get(id)
			sigShare := p.Sign(message, comList)
			sigShares[i] = sigShare
		}

		// Final step: aggregate
		signature := participants[1].Aggregate(comList, message, sigShares)

		// Sanity Check
		if !schnorr.Verify(configuration.Ciphersuite, message, signature, groupPublicKey) {
			t2.Fatal()
		}
	})
}

func testAll(t *testing.T, f func(*testing.T, frost.Ciphersuite)) {
	for _, ciphersuite := range ciphersuiteTable {
		t.Run(ciphersuite.String(), func(t *testing.T) {
			f(t, ciphersuite)
		})
	}
}
