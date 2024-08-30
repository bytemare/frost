// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

func TestConfiguration_Verify_InvalidCiphersuite(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      2,
			Threshold:        test.threshold,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   groupPublicKey,
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_Threshold_0(t *testing.T) {
	expectedErrorPrefix := "threshold is 0 or higher than maxSigners"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      test.Ciphersuite,
			Threshold:        0,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   groupPublicKey,
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_Threshold_Max(t *testing.T) {
	expectedErrorPrefix := "threshold is 0 or higher than maxSigners"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      test.Ciphersuite,
			Threshold:        test.maxSigners + 1,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   groupPublicKey,
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Nil(t *testing.T) {
	expectedErrorPrefix := "invalid group public key (nil, identity, or generator)"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      test.Ciphersuite,
			Threshold:        test.threshold,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   nil,
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Identity(t *testing.T) {
	expectedErrorPrefix := "invalid group public key (nil, identity, or generator)"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      test.Ciphersuite,
			Threshold:        test.threshold,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   test.ECGroup().NewElement(),
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Generator(t *testing.T) {
	expectedErrorPrefix := "invalid group public key (nil, identity, or generator)"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:      test.Ciphersuite,
			Threshold:        test.threshold,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   test.ECGroup().Base(),
			SignerPublicKeys: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_VerifySignerPublicKeys_InvalidNumber(t *testing.T) {
	expectedErrorPrefix := "invalid number of public keys (lower than threshold or above maximum)"

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	// nil
	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: nil,
	}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// empty
	configuration.SignerPublicKeys = []*frost.PublicKeyShare{}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// too few
	configuration.SignerPublicKeys = publicKeyShares[:threshold-1]

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// too many
	configuration.SignerPublicKeys = append(publicKeyShares, &frost.PublicKeyShare{})

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Nil(t *testing.T) {
	expectedErrorPrefix := "empty public key share at index 1"

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)
	publicKeyShares[threshold-1] = nil

	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_BadPublicKey(t *testing.T) {
	expectedErrorPrefix := "invalid signer public key (nil, identity, or generator) for participant 2"

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	// nil pk
	configuration.SignerPublicKeys[threshold-1].PublicKey = nil

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// identity
	configuration.SignerPublicKeys[threshold-1].PublicKey = ciphersuite.ECGroup().NewElement()

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// generator
	configuration.SignerPublicKeys[threshold-1].PublicKey = ciphersuite.ECGroup().Base()

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Duplicate_Identifiers(t *testing.T) {
	expectedErrorPrefix := "found duplicate identifier for signer 1"

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	// duplicate id
	id1 := configuration.SignerPublicKeys[0].ID
	configuration.SignerPublicKeys[1].ID = id1

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Duplicate_PublicKeys(t *testing.T) {
	expectedErrorPrefix := "found duplicate public keys for signers 2 and 1"

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	// duplicate id
	pk1 := configuration.SignerPublicKeys[0].PublicKey.Copy()
	configuration.SignerPublicKeys[1].PublicKey = pk1

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_Signer_NotVerified(t *testing.T) {
	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if _, err := configuration.Signer(keyShares[0]); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguration_Signer_BadConfig(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite
	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      2,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if _, err := configuration.Signer(keyShares[0]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_PrepareSignatureShareVerification_BadNonVerifiedConfiguration(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite
	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      2,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if _, _, _, err := configuration.PrepareSignatureShareVerification(nil, nil); err == nil ||
		err.Error() != expectedErrorPrefix.Error() {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_PrepareSignatureShareVerification_InvalidCommitments(t *testing.T) {
	expectedErrorPrefix := "invalid list of commitments: too few commitments: expected at least 2 but got 1"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if _, _, _, err := configuration.PrepareSignatureShareVerification(nil, coms[:1]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_BadPrep(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      2,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.VerifySignatureShare(nil, nil, nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_NilShare(t *testing.T) {
	expectedErrorPrefix := "nil signature share"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if err := configuration.VerifySignatureShare(nil, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_SignerID0(t *testing.T) {
	expectedErrorPrefix := "signature share's signer identifier is 0 (invalid)"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	sigShare.SignerIdentifier = 0

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_InvalidSignerID(t *testing.T) {
	expectedErrorPrefix := "signature share has invalid ID 4, above authorized range [1:3]"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	sigShare.SignerIdentifier = tt.maxSigners + 1

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_BadGroup(t *testing.T) {
	expectedErrorPrefix := "signature share has invalid group parameter, want ristretto255_XMD:SHA-512_R255MAP_RO_ got 2"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	sigShare.Group = 2

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_MissingPublicKey(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	configuration.SignerPublicKeys = slices.Delete(configuration.SignerPublicKeys, 0, 1)
	expectedErrorPrefix := fmt.Sprintf("no public key registered for signer 1")

	if err := configuration.VerifySignatureShare(sigShare, message, coms[1:]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_MissingCommitment(t *testing.T) {
	expectedErrorPrefix := "commitment for signer 1 is missing"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  4,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	if err := configuration.VerifySignatureShare(sigShare, message, coms[1:]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_BadCommitment_BadSignerID(t *testing.T) {
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare, err := signers[0].Sign(message, coms)
	if err != nil {
		t.Fatal(err)
	}

	coms[1].SignerID = 0
	expectedErrorPrefix := fmt.Sprintf(
		"invalid list of commitments: signer identifier for commitment %d is 0",
		coms[1].CommitmentID,
	)

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_InvalidSignatureShare(t *testing.T) {
	expectedErrorPrefix := "invalid signature share for signer 1"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShare := &frost.SignatureShare{
		SignatureShare:   tt.Ciphersuite.ECGroup().NewScalar().Random(),
		SignerIdentifier: 1,
		Group:            tt.Ciphersuite.ECGroup(),
	}

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_AggregateSignatures_InvalidCommitments(t *testing.T) {
	expectedErrorPrefix := "invalid list of commitments: too few commitments: expected at least 3 but got 2"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration, signers := fullSetup(t, tt)
	coms := make(frost.CommitmentList, len(signers))

	for i, s := range signers {
		coms[i] = s.Commit()
	}

	if _, err := configuration.AggregateSignatures(nil, nil, coms[:2], false); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_AggregateSignatures_BadSigShare1(t *testing.T) {
	expectedErrorPrefix := "invalid signature share for signer 2"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)

	coms := make(frost.CommitmentList, len(signers))
	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShares := make([]*frost.SignatureShare, len(signers))
	for i, s := range signers {
		var err error
		sigShares[i], err = s.Sign(message, coms)
		if err != nil {
			t.Fatal(err)
		}
	}

	sigShares[1].SignatureShare.Random()

	if _, err := configuration.AggregateSignatures(message, sigShares, coms, true); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_AggregateSignatures_BadSigShare2(t *testing.T) {
	expectedErrorPrefix := "nil signature share"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)

	coms := make(frost.CommitmentList, len(signers))
	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShares := make([]*frost.SignatureShare, len(signers))
	for i, s := range signers {
		var err error
		sigShares[i], err = s.Sign(message, coms)
		if err != nil {
			t.Fatal(err)
		}
	}

	sigShares[1] = nil

	if _, err := configuration.AggregateSignatures(message, sigShares, coms, false); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_AggregateSignatures_BadSigShare3(t *testing.T) {
	expectedErrorPrefix := "invalid signature share (nil or zero scalar)"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	message := []byte("message")
	configuration, signers := fullSetup(t, tt)

	coms := make(frost.CommitmentList, len(signers))
	for i, s := range signers {
		coms[i] = s.Commit()
	}

	sigShares := make([]*frost.SignatureShare, len(signers))
	for i, s := range signers {
		var err error
		sigShares[i], err = s.Sign(message, coms)
		if err != nil {
			t.Fatal(err)
		}
	}

	sigShares[1].SignatureShare.Zero()

	if _, err := configuration.AggregateSignatures(message, sigShares, coms, false); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}
