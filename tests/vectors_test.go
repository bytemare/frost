// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
)

func (v test) test(t *testing.T) {
	g := v.Config.Ciphersuite.Group

	coeffs := v.Inputs.SharePolynomialCoefficients

	privateKeyShares, dealerGroupPubKey, secretsharingCommitment, err := frost.TrustedDealerKeygen(
		g,
		v.Inputs.GroupSecretKey,
		v.Config.MaxParticipants,
		v.Config.MinParticipants,
		coeffs...)
	if err != nil {
		t.Fatal(err)
	}

	if len(secretsharingCommitment) != v.Config.MinParticipants {
		t.Fatalf(
			"%d / %d", len(secretsharingCommitment), v.Config.MinParticipants)
	}

	// Check whether key shares are the same
	cpt := len(privateKeyShares)
	for _, p := range privateKeyShares {
		for _, p2 := range v.Inputs.Participants {
			if p2.Identifier.Equal(p.Identifier) == 1 {
				cpt--
			}
		}
	}

	if cpt != 0 {
		t.Fatal("Some key shares do not match.")
	}

	// Test recovery of the full secret signing key.
	recoveredKey, err := secretsharing.Combine(g, uint(v.Config.MinParticipants), privateKeyShares)
	if err != nil {
		t.Fatal(err)
	}

	if recoveredKey.Equal(v.Inputs.GroupSecretKey) != 1 {
		t.Fatal()
	}

	groupPublicKey, participantPublicKey := frost.DeriveGroupInfo(g, v.Config.MaxParticipants, secretsharingCommitment)
	if len(participantPublicKey) != v.Config.MaxParticipants {
		t.Fatal()
	}

	if groupPublicKey.Equal(dealerGroupPubKey) != 1 {
		t.Fatal()
	}

	for i, shareI := range privateKeyShares {
		if !frost.VerifyVSS(g, shareI, secretsharingCommitment) {
			t.Fatal(i)
		}
	}

	// Create participants
	participants := make(ParticipantList, len(privateKeyShares))
	conf := v.Config
	conf.GroupPublicKey = groupPublicKey
	for i, pks := range privateKeyShares {
		participants[i] = conf.Participant(pks.Identifier, pks.SecretKey)
	}

	// Round One: Commitment
	commitmentList := make(internal.CommitmentList, len(v.RoundOneOutputs.Outputs))
	for i, pid := range v.RoundOneOutputs.Outputs {
		p := participants.Get(pid.ID)
		if p == nil {
			t.Fatal(i)
		}

		var pv *participant
		for _, pp := range v.RoundOneOutputs.Outputs {
			if pp.ID.Equal(pid.ID) == 1 {
				pv = pp
			}
		}
		if pv == nil {
			t.Fatal(i)
		}

		p.HidingRandom = pv.HidingNonceRandomness
		p.BindingRandom = pv.BindingNonceRandomness

		commitment := p.Commit()

		if p.Nonce[0].Equal(pv.HidingNonce) != 1 {
			t.Fatal(i)
		}
		if p.Nonce[1].Equal(pv.BindingNonce) != 1 {
			t.Fatal(i)
		}
		if commitment.HidingNonce.Equal(pv.HidingNonceCommitment) != 1 {
			t.Fatal(i)
		}
		if commitment.BindingNonce.Equal(pv.BindingNonceCommitment) != 1 {
			t.Fatal(i)
		}

		commitmentList[i] = commitment
	}

	//_, rhoInputs := commitmentList.ComputeBindingFactors(
	//	v.Config.Ciphersuite,
	//	v.Inputs.Message,
	//)
	//for i, rho := range rhoInputs {
	//	if !bytes.Equal(rho, v.RoundOneOutputs.Outputs[i].BindingFactorInput) {
	//		t.Fatal()
	//	}
	//}

	// Round two: sign
	sigShares := make([]*frost.SignatureShare, len(v.RoundTwoOutputs.Outputs))
	for i, pid := range v.RoundTwoOutputs.Outputs {
		p := participants.Get(pid.Identifier)
		if p == nil {
			t.Fatal(i)
		}

		sigShares[i], err = p.Sign(v.Inputs.Message, commitmentList)
		if err != nil {
			t.Fatal(err)
		}
	}

	for i, ks := range v.RoundTwoOutputs.Outputs {
		if ks.SecretKey.Equal(sigShares[i].SignatureShare) != 1 {
			t.Fatal(i)
		}
	}

	// Aggregate
	sig := participants[1].Aggregate(commitmentList, v.Inputs.Message, sigShares)
	if !bytes.Equal(sig.Encode(), v.FinalOutput) {
		t.Fatal()
	}

	// Sanity Check
	if !schnorr.Verify(conf.Ciphersuite, v.Inputs.Message, sig, groupPublicKey) {
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

			t.Run(fmt.Sprintf("%s", v.Config.Name), v.test)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
