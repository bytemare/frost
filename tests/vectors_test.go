// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
)

func (v test) testTrustedDealer(t *testing.T) ([]*keys.KeyShare, *ecc.Element) {
	g := v.Config.Ciphersuite.Group()

	keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
		v.Config.Ciphersuite,
		v.Inputs.GroupSecretKey,
		v.Config.Configuration.Threshold,
		v.Config.Configuration.MaxSigners,
		v.Inputs.SharePolynomialCoefficients...)

	if len(secretsharingCommitment) != int(v.Config.Configuration.Threshold) {
		t.Fatalf(
			"%d / %d", len(secretsharingCommitment), v.Config.Configuration.Threshold)
	}

	// Test recovery of the full secret signing key.
	recoveredKey, err := debug.RecoverGroupSecret(v.Config.Ciphersuite, keyShares)
	if err != nil {
		t.Fatal(err)
	}

	if !recoveredKey.Equal(v.Inputs.GroupSecretKey) {
		t.Fatal()
	}

	groupPublicKey, participantPublicKey, err := debug.RecoverPublicKeys(
		v.Config.Ciphersuite,
		v.Config.Configuration.MaxSigners,
		secretsharingCommitment,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(participantPublicKey) != int(v.Config.Configuration.MaxSigners) {
		t.Fatal()
	}

	if !groupPublicKey.Equal(dealerGroupPubKey) {
		t.Fatal()
	}

	for i, shareI := range keyShares {
		if !debug.VerifyVSS(g, shareI, secretsharingCommitment) {
			t.Fatal(i)
		}
	}

	return keyShares, dealerGroupPubKey
}

func (v test) test(t *testing.T) {
	keyShares, groupPublicKey := v.testTrustedDealer(t)

	// Check whether key shares are the same
	cpt := len(keyShares)
	for _, p := range keyShares {
		for _, p2 := range v.Inputs.Participants {
			if p2.Identifier() == p.Identifier() && p2.SecretKey().Equal(p.Secret) {
				cpt--
			}
		}
	}

	if cpt != 0 {
		t.Fatal("Some key shares do not match.")
	}

	// Create participants
	participants := make(ParticipantList, len(keyShares))
	conf := v.Config
	for i, keyShare := range keyShares {
		signer, err := conf.Configuration.Signer(keyShare)
		if err != nil {
			t.Fatal(err)
		}

		participants[i] = signer
	}

	// Round One: Commitment
	commitmentList := make(frost.CommitmentList, len(v.RoundOneOutputs.Outputs))
	for i, pid := range v.RoundOneOutputs.Outputs {
		p := participants.Get(pid.ID)
		if p == nil {
			t.Fatal(i)
		}

		var pv *participant
		for _, pp := range v.RoundOneOutputs.Outputs {
			if pp.ID == pid.ID {
				pv = pp
			}
		}
		if pv == nil {
			t.Fatal(i)
		}

		p.HidingRandom = pv.HidingNonceRandomness
		p.BindingRandom = pv.BindingNonceRandomness

		com := p.Commit()

		if !p.NonceCommitments[com.CommitmentID].HidingNonce.Equal(pv.HidingNonce) {
			t.Fatal(i)
		}
		if !p.NonceCommitments[com.CommitmentID].BindingNonce.Equal(pv.BindingNonce) {
			t.Fatal(i)
		}
		if !com.HidingNonceCommitment.Equal(pv.HidingNonceCommitment) {
			t.Fatal(i)
		}
		if !com.BindingNonceCommitment.Equal(pv.BindingNonceCommitment) {
			t.Fatal(i)
		}

		commitmentList[i] = com
	}

	// Round two: sign
	sigShares := make([]*frost.SignatureShare, len(v.RoundTwoOutputs.Outputs))
	for i, share := range v.RoundTwoOutputs.Outputs {
		p := participants.Get(share.SignerIdentifier)
		if p == nil {
			t.Fatal(i)
		}

		var err error
		sigShares[i], err = p.Sign(v.Inputs.Message, commitmentList)
		if err != nil {
			t.Fatal(err)
		}

		// Check against vector
		if !share.SignatureShare.Equal(sigShares[i].SignatureShare) {
			t.Fatalf("%s\n%s\n", share.SignatureShare.Hex(), sigShares[i].SignatureShare.Hex())
		}

		if err = v.Config.VerifySignatureShare(sigShares[i], v.Inputs.Message, commitmentList); err != nil {
			t.Fatalf("signature share matched but verification failed: %s", err)
		}
	}

	// AggregateSignatures
	sig, err := v.Config.AggregateSignatures(v.Inputs.Message, sigShares, commitmentList, true)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig.Encode()[1:], v.FinalOutput) {
		t.Fatal("")
	}

	// Sanity Check
	if err = frost.VerifySignature(conf.Ciphersuite, v.Inputs.Message, sig, groupPublicKey); err != nil {
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
