// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/shamir"
	"github.com/bytemare/frost/internal/vss"
)

func (v test) test(t *testing.T) {
	g := v.Config.Group

	coeffs := v.Inputs.SharePolynomialCoefficients

	privateKeyShares, dealerGroupPubKey, vssCommitment := frost.TrustedDealerKeygen(
		g,
		v.Inputs.GroupSecretKey,
		v.Config.MaxParticipants,
		v.Config.MinParticipants,
		coeffs...)
	if len(vssCommitment) != v.Config.MinParticipants {
		t.Fatalf("%d / %d", len(vssCommitment), v.Config.MinParticipants)
	}

	// Check whether key shares are the same
	cpt := len(privateKeyShares)
	for _, p := range privateKeyShares {
		for _, p2 := range v.Inputs.Participants {
			if p2.ID.Equal(p.ID) == 1 {
				cpt--
			}
		}
	}

	if cpt != 0 {
		t.Fatal("Some key shares do not match.")
	}

	recoveredKey := shamir.Combine(g, privateKeyShares, v.Config.MinParticipants)
	if recoveredKey.Equal(v.Inputs.GroupSecretKey) != 1 {
		t.Fatal()
	}

	groupPublicKey, participantPublicKey := frost.DeriveGroupInfo(g, v.Config.MaxParticipants, vssCommitment)
	if len(participantPublicKey) != v.Config.MaxParticipants {
		t.Fatal()
	}

	if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
		t.Fatal()
	}

	for i, shareI := range privateKeyShares {
		if !vss.Verify(g, shareI, vssCommitment) {
			t.Fatal(i)
		}
	}

	// Create participants
	participants := make(frost.ParticipantList, len(privateKeyShares))
	for i, pks := range privateKeyShares {
		participants[i] = &frost.Participant{
			ParticipantInfo: frost.ParticipantInfo{
				KeyShare: pks,
				Lambda:   nil,
			},
			Nonce:      [2]*group.Scalar{},
			Commitment: [2]*group.Element{},
			Configuration: frost.Configuration{
				GroupPublicKey: groupPublicKey,
				ContextString:  v.Config.ContextString,
				Ciphersuite: internal.Ciphersuite{
					Group: g,
					Hash:  v.Config.Hash,
				},
			},
		}
	}

	// Round One: Commitment
	commitmentList := make(internal.CommitmentList, len(v.RoundOneOutputs.ParticipantList))
	for i, pid := range v.RoundOneOutputs.ParticipantList {
		p := participants.Get(pid)
		if p == nil {
			t.Fatal(i)
		}

		var pv *participant
		for _, pp := range v.RoundOneOutputs.Participants {
			if pp.ID.Equal(pid) == 1 {
				pv = pp
			}
		}
		if pv == nil {
			t.Fatal(i)
		}

		p.HidingRandom = pv.HidingNonceRandomness
		p.BindingRandom = pv.BindingNonceRandomness

		p.Commit()

		if p.Nonce[0].Equal(pv.HidingNonce) != 1 {
			t.Fatal(i)
		}
		if p.Nonce[1].Equal(pv.BindingNonce) != 1 {
			t.Fatal(i)
		}
		if p.Commitment[0].Equal(pv.HidingNonceCommitment) != 1 {
			t.Fatal(i)
		}
		if p.Commitment[1].Equal(pv.BindingNonceCommitment) != 1 {
			t.Fatal(i)
		}

		commitmentList[i] = internal.Commitment{
			ID:           p.KeyShare.ID,
			HidingNonce:  p.Commitment[0],
			BindingNonce: p.Commitment[1],
		}
	}

	_, rhoInputs := commitmentList.ComputeBindingFactors(
		internal.Ciphersuite{Group: g, Hash: v.Config.Hash},
		v.Config.ContextString,
		v.Inputs.Message,
	)
	for i, rho := range rhoInputs {
		if !bytes.Equal(rho, v.RoundOneOutputs.Participants[i].BindingFactorInput) {
			t.Fatal()
		}
	}

	// Round two: sign
	sigShares := make([]*group.Scalar, len(v.RoundTwoOutputs.ParticipantList))
	for i, pid := range v.RoundTwoOutputs.ParticipantList {
		p := participants.Get(pid)
		if p == nil {
			t.Fatal(i)
		}

		sigShares[i] = p.Sign(v.Inputs.Message, commitmentList)
	}

	for i, ks := range v.RoundTwoOutputs.Participants {
		if ks.SecretKey.Equal(sigShares[i]) != 1 {
			t.Fatal(i)
		}
	}

	// Aggregate
	sig := participants[1].Aggregate(commitmentList, v.Inputs.Message, sigShares)
	if !bytes.Equal(sig.Encode(), v.FinalOutput) {
		t.Fatal()
	}
}

func loadFrostVectors(t *testing.T, filepath string) (*test, error) {
	contents, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var v *testVector
	errJSON := json.Unmarshal(contents, &v)
	if errJSON != nil {
		return nil, errJSON
	}

	tst := v.decode(t)

	return tst, nil
}

func TestFrostVectors(t *testing.T) {
	vectorFiles := "vectors"

	if err := filepath.Walk(vectorFiles,
		func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			v, err := loadFrostVectors(t, file)
			if err != nil || v == nil {
				t.Fatal(err)
			}

			if v.Config.Name != "FROST(ristretto255, SHA-512)" {
				return nil
			}

			t.Run(fmt.Sprintf("%s - %s", v.Config.Name, v.Config.Group), v.test)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
