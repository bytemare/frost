// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

import (
	"encoding/hex"
	"fmt"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
	"github.com/bytemare/frost/internal/shamir"
	"github.com/bytemare/frost/internal/vss"
)

var configurationTable = []frost.Configuration{
	{
		Ciphersuite: internal.Ciphersuite{
			Group: group.Ristretto255Sha512,
			Hash:  hash.SHA512,
		},
		ContextString:  "FROST-RISTRETTO255-SHA512-v11",
		GroupPublicKey: nil,
	},
	{
		Ciphersuite: internal.Ciphersuite{
			Group: group.P256Sha256,
			Hash:  hash.SHA256,
		},
		ContextString:  "FROST-P256-SHA256-v11",
		GroupPublicKey: nil,
	},
}

func TestFrost(t *testing.T) {
	min := 2
	max := 3
	participantList := []int{1, 3}
	message := []byte("test")

	testAll(t, func(t2 *testing.T, configuration *frost.Configuration) {
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

		groupPublicKey, participantPublicKey := frost.DeriveGroupInfo(g, max, vssCommitment)
		if len(participantPublicKey) != max {
			t2.Fatal()
		}

		if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
			t2.Fatal()
		}

		for i, shareI := range privateKeyShares {
			if !vss.Verify(g, shareI, vssCommitment) {
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
		participants := make([]*frost.Participant, max)
		for i, share := range privateKeyShares {
			participants[i] = &frost.Participant{
				Configuration:   *configuration,
				ParticipantInfo: frost.ParticipantInfo{KeyShare: share},
			}
		}

		// Round One: Commitment
		comList := make(internal.CommitmentList, max)
		for _, id := range participantList {
			_, commI := participants[id].Commit()
			comList[id] = internal.Commitment{
				ID:           internal.IntegerToScalar(g, id),
				IDint:        id,
				HidingNonce:  commI[0],
				BindingNonce: commI[1],
			}
		}

		comList.Sort()

		_ = comList.ComputeBindingFactors(configuration.Ciphersuite, message)

		// Round Two: Sign
		sigShares := make([]*group.Scalar, max)
		for _, id := range participantList {
			sigShare := participants[id].Sign(message, comList)
			sigShares[id] = sigShare
		}

		// Final step: aggregate
		sig := participants[1].Aggregate(comList, message, sigShares)
		fmt.Printf("Signature: %v", hex.EncodeToString(sig.Encode()))

		// Sanity Check
		singleSig := schnorr.Sign(configuration.Ciphersuite, message, groupSecretKey)
		if !schnorr.Verify(configuration.Ciphersuite, message, singleSig, groupPublicKey) {
			t2.Fatal()
		}
	})
}

func testAll(t *testing.T, f func(*testing.T, *frost.Configuration)) {
	for _, test := range configurationTable {
		t.Run(test.ContextString, func(t *testing.T) {
			f(t, &test)
		})
	}
}
