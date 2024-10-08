// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"testing"

	"github.com/bytemare/dkg"
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"
)

func dkgMakeParticipants(t *testing.T, ciphersuite dkg.Ciphersuite, threshold, maxSigners uint16) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, maxSigners)
	for i := range maxSigners {
		p, err := ciphersuite.NewParticipant(i+1, threshold, maxSigners)
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func runDKG(
	t *testing.T,
	g ecc.Group,
	threshold, maxSigners uint16,
) ([]*keys.KeyShare, *ecc.Element, []*ecc.Element) {
	c := dkg.Ciphersuite(g)

	// valid r1DataSet set with and without own package
	participants := dkgMakeParticipants(t, c, threshold, maxSigners)
	r1 := make([]*dkg.Round1Data, maxSigners)
	commitments := make([][]*ecc.Element, maxSigners)

	// Step 1: Start and assemble packages.
	for i := range maxSigners {
		r1[i] = participants[i].Start()
		commitments[i] = r1[i].Commitment
	}

	pubKey, err := dkg.VerificationKeyFromRound1(c, r1)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Continue and assemble + triage packages.
	r2 := make(map[uint16][]*dkg.Round2Data, maxSigners)
	for i := range maxSigners {
		r, err := participants[i].Continue(r1)
		if err != nil {
			t.Fatal(err)
		}

		for id, data := range r {
			if r2[id] == nil {
				r2[id] = make([]*dkg.Round2Data, 0, maxSigners-1)
			}
			r2[id] = append(r2[id], data)
		}
	}

	// Step 3: Clean the proofs.
	// This must be called by each participant on their copy of the r1DataSet.
	for _, d := range r1 {
		d.ProofOfKnowledge.Clear()
	}

	// Step 4: Finalize and test outputs.
	keyShares := make([]*keys.KeyShare, 0, maxSigners)

	for _, p := range participants {
		keyShare, err := p.Finalize(r1, r2[p.Identifier])
		if err != nil {
			t.Fatal()
		}

		//if !secretsharing.VerifyPublicKeyShare(keyShare.Public()) {
		//	t.Fatal("expected validity")
		//}

		if !keyShare.VerificationKey.Equal(pubKey) {
			t.Fatal("expected same public key")
		}

		if !keyShare.PublicKey.Equal(g.Base().Multiply(keyShare.SecretKey())) {
			t.Fatal("expected equality")
		}

		if err := dkg.VerifyPublicKey(c, p.Identifier, keyShare.PublicKey, commitments); err != nil {
			t.Fatal(err)
		}

		keyShares = append(keyShares, keyShare)
	}

	return keyShares, pubKey, nil
}
