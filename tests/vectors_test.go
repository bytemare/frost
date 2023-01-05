// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytemare/frost"
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
