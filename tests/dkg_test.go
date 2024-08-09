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

	group "github.com/bytemare/crypto"
	"github.com/bytemare/dkg"

	"github.com/bytemare/frost"
)

func dkgMakeParticipants(t *testing.T, ciphersuite dkg.Ciphersuite, maxSigners, threshold uint64) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, maxSigners)
	for i := range maxSigners {
		p, err := ciphersuite.NewParticipant(i+1, uint(maxSigners), uint(threshold))
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func runDKG(
	t *testing.T,
	g group.Group,
	maxSigners, threshold uint64,
) ([]*frost.KeyShare, *group.Element, []*group.Element) {
	c := dkg.Ciphersuite(g)

	// valid r1DataSet set with and without own package
	participants := dkgMakeParticipants(t, c, maxSigners, threshold)
	r1 := make([]*dkg.Round1Data, maxSigners)
	commitments := make([][]*group.Element, maxSigners)

	// Step 1: Start and assemble packages.
	for i := range maxSigners {
		r1[i] = participants[i].Start()
		commitments[i] = r1[i].Commitment
	}

	pubKey, err := dkg.GroupPublicKeyFromRound1(c, r1)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Continue and assemble + triage packages.
	r2 := make(map[uint64][]*dkg.Round2Data, maxSigners)
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
	keyShares := make([]*frost.KeyShare, 0, maxSigners)

	for _, p := range participants {
		keyShare, err := p.Finalize(r1, r2[p.Identifier])
		if err != nil {
			t.Fatal()
		}

		if keyShare.GroupPublicKey.Equal(pubKey) != 1 {
			t.Fatalf("expected same public key")
		}

		if keyShare.PublicKey.Equal(g.Base().Multiply(keyShare.SecretKey())) != 1 {
			t.Fatal("expected equality")
		}

		if err := dkg.VerifyPublicKey(c, p.Identifier, keyShare.PublicKey, commitments); err != nil {
			t.Fatal(err)
		}

		keyShares = append(keyShares, (*frost.KeyShare)(keyShare))
	}

	return keyShares, pubKey, nil
}
