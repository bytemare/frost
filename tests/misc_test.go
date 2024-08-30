// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/dkg"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

func TestCommitmentList_Sort(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))

		// signer A < signer B
		coms[0] = signers[0].Commit()
		coms[1] = signers[1].Commit()
		coms[2] = signers[2].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}

		// signer B > singer A
		coms[0] = signers[1].Commit()
		coms[1] = signers[0].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}

		// signer B > singer A
		coms[0] = signers[0].Commit()
		coms[1] = signers[2].Commit()
		coms[2] = signers[2].Commit()

		coms.Sort()

		if !coms.IsSorted() {
			t.Fatal("expected sorted")
		}
	})
}

func verifyTrustedDealerKeygen(
	t *testing.T,
	test *tableTest,
	ks []*frost.KeyShare,
	pk *group.Element,
	coms []*group.Element,
) {
	if uint64(len(coms)) != test.threshold {
		t.Fatalf("%d / %d", len(coms), test.threshold)
	}

	recoveredKey, err := debug.RecoverGroupSecret(test.Ciphersuite, ks[:test.threshold])
	if err != nil {
		t.Fatal(err)
	}

	groupPublicKey, participantPublicKeys, err := debug.RecoverPublicKeys(
		test.Ciphersuite,
		test.maxSigners,
		coms,
	)
	if err != nil {
		t.Fatal(err)
	}

	if uint64(len(participantPublicKeys)) != test.maxSigners {
		t.Fatal()
	}

	if groupPublicKey.Equal(pk) != 1 {
		t.Fatal()
	}

	g := test.Ciphersuite.ECGroup()

	for i, shareI := range ks {
		if !debug.VerifyVSS(g, shareI, coms) {
			t.Fatal(i)
		}
	}

	sig, err := debug.Sign(test.Ciphersuite, []byte("message"), recoveredKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = frost.VerifySignature(test.Ciphersuite, []byte("message"), sig, groupPublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedDealerKeygen(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.ECGroup()
		groupSecretKey := g.NewScalar().Random()
		keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			groupSecretKey,
			test.threshold,
			test.maxSigners,
		)

		verifyTrustedDealerKeygen(t, test, keyShares, dealerGroupPubKey, secretsharingCommitment)
	})
}

func TestTrustedDealerKeygenNoSecret(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)

		verifyTrustedDealerKeygen(t, test, keyShares, dealerGroupPubKey, secretsharingCommitment)
	})
}

func TestTrustedDealerKeygenWrongParams(t *testing.T) {
	errTooFewShares := errors.New("number of shares must be equal or greater than the threshold")

	testAll(t, func(t *testing.T, test *tableTest) {
		if err := testPanic("wrong params", errTooFewShares, func() {
			_, _, _ = debug.TrustedDealerKeygen(
				test.Ciphersuite,
				nil,
				5,
				3,
			)
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRecoverGroupSecretInvalidCiphersuite(t *testing.T) {
	expectedError := internal.ErrInvalidCiphersuite
	if _, err := debug.RecoverGroupSecret(0, nil); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestRecoverGroupSecretNoShares(t *testing.T) {
	expectedError := "failed to reconstruct group secret: "
	if _, err := debug.RecoverGroupSecret(frost.Ristretto255, nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedError) {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestSchnorrSign(t *testing.T) {
	message1 := []byte("message-1")
	message2 := []byte("message-2")
	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.ECGroup()
		secretKey1 := g.NewScalar().Random()
		verificationKey1 := g.Base().Multiply(secretKey1)
		secretKey2 := g.NewScalar().Random()

		// Signature must be valid.
		signature, err := debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		if err = frost.VerifySignature(test.Ciphersuite, message1, signature, verificationKey1); err != nil {
			t.Fatal(err)
		}

		// Same key, different messages = different signatures
		signature1, err := debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err := debug.Sign(test.Ciphersuite, message2, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, false); err != nil {
			t.Fatal(err)
		}

		// Same key, same message = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, false); err != nil {
			t.Fatal(err)
		}

		// Same key, same message, same random = same signatures
		k := g.NewScalar().Random()

		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1, k)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey1, k)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, true); err != nil {
			t.Fatal(err)
		}

		// Same key, same message, explicit different random = same signatures
		k1 := g.NewScalar().Random()
		k2 := g.NewScalar().Random()

		if k1.Equal(k2) == 1 {
			t.Fatal("unexpected equality")
		}

		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1, k1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey1, k2)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, false); err != nil {
			t.Fatal(err)
		}

		// Different keys, same message = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey2)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, false); err != nil {
			t.Fatal(err)
		}

		// Different keys, different messages = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message2, secretKey2)
		if err != nil {
			t.Fatal(err)
		}

		if err = compareSignatures(signature1, signature2, false); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSign_InvalidCiphersuite(t *testing.T) {
	expectedError := internal.ErrInvalidCiphersuite
	if _, err := debug.Sign(0, nil, nil); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestRecoverPublicKeys(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, dealerGroupPubKey, secretsharingCommitment := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)

		groupPublicKey, participantPublicKeys, err := debug.RecoverPublicKeys(
			test.Ciphersuite,
			test.maxSigners,
			secretsharingCommitment,
		)
		if err != nil {
			t.Fatal(err)
		}

		if dealerGroupPubKey.Equal(groupPublicKey) != 1 {
			t.Fatal("expected equality")
		}

		if len(participantPublicKeys) != len(keyShares) {
			t.Fatal("expected equality")
		}

		for i, keyShare := range keyShares {
			if keyShare.PublicKey.Equal(participantPublicKeys[i]) != 1 {
				t.Fatal("expected equality")
			}
		}
	})
}

func TestRecoverPublicKeys_InvalidCiphersuite(t *testing.T) {
	expectedError := internal.ErrInvalidCiphersuite
	if _, _, err := debug.RecoverPublicKeys(0, 0, nil); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestRecoverPublicKeys_BadCommitment(t *testing.T) {
	expectedError := "commitment has nil element"
	ciphersuite := frost.Ristretto255
	threshold := uint64(2)
	maxSigners := uint64(3)
	_, _, secretsharingCommitment := debug.TrustedDealerKeygen(
		ciphersuite,
		nil,
		threshold,
		maxSigners,
	)

	secretsharingCommitment[1] = nil

	_, _, err := debug.RecoverPublicKeys(
		ciphersuite,
		maxSigners,
		secretsharingCommitment,
	)
	if err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestPublicKeyShareVerification(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, dealerGroupPubKey, _ := runDKG(
			t,
			test.Ciphersuite.ECGroup(),
			test.threshold,
			test.maxSigners,
		)

		vssComs := make([][]*group.Element, test.maxSigners)
		pkShares := make([]*frost.PublicKeyShare, test.maxSigners)

		for i, keyShare := range keyShares {
			pk := keyShare.Public()
			vssComs[i] = pk.Commitment
			pkShares[i] = pk
		}

		if err := dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), 0, dealerGroupPubKey, vssComs); err != nil {
			t.Fatal(err)
		}

		for _, pk := range pkShares {
			if !pk.Verify(vssComs) {
				t.Fatal("expected validity")
			}
		}
	})
}

func TestPublicKeyShareVerificationFail(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, dealerGroupPubKey, _ := runDKG(
			t,
			test.Ciphersuite.ECGroup(),
			test.threshold,
			test.maxSigners,
		)

		vssComs := make([][]*group.Element, test.maxSigners)
		pkShares := make([]*frost.PublicKeyShare, test.maxSigners)

		for i, keyShare := range keyShares {
			pk := keyShare.Public()
			vssComs[i] = pk.Commitment
			pk.PublicKey = nil
			pkShares[i] = pk
		}

		if err := dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), 0, dealerGroupPubKey, vssComs); err != nil {
			t.Fatal(err)
		}

		for _, pk := range pkShares {
			if pk.Verify(vssComs) {
				t.Fatal("expected invalidity")
			}
		}
	})
}

func TestLambda_BadID(t *testing.T) {
	// expectedErrorPrefix := "anomaly in participant identifiers: one of the polynomial's coefficients is zero"
	g := group.Ristretto255Sha512
	polynomial := []*group.Scalar{
		g.NewScalar().SetUInt64(1),
		g.NewScalar().SetUInt64(0),
		g.NewScalar().SetUInt64(1),
	}

	// todo : what happens if the participant list is not vetted?
	fmt.Println(internal.Lambda(g, 1, polynomial).Hex())
}

func TestLambdaRegistry(t *testing.T) {
	g := group.Ristretto255Sha512
	id := uint64(2)
	participants := []uint64{1, 2, 3, 4}
	lambdas := make(internal.LambdaRegistry)

	// Get should return nil
	if lambda := lambdas.Get(participants); lambda != nil {
		t.Fatal("unexpected result")
	}

	// Create a new entry
	lambda := lambdas.New(g, id, participants)

	if lambda == nil {
		t.Fatal("unexpected result")
	}

	// Getting the same entry
	lambda2 := lambdas.Get(participants)
	if lambda.Equal(lambda2) != 1 {
		t.Fatal("expected equality")
	}

	lambda3 := lambdas.GetOrNew(g, id, participants)

	if lambda.Equal(lambda3) != 1 {
		t.Fatal("expected equality")
	}

	// Getting another entry must result in another returned value
	lambda4 := lambdas.GetOrNew(g, id, participants[:3])

	if lambda.Equal(lambda4) == 1 {
		t.Fatal("unexpected equality")
	}

	lambda5 := lambdas.GetOrNew(g, id, participants[:3])

	if lambda4.Equal(lambda5) != 1 {
		t.Fatal("expected equality")
	}

	// Removing and checking for the same entry
	lambdas.Delete(participants)
	if lambda = lambdas.Get(participants); lambda != nil {
		t.Fatal("unexpected result")
	}

	// Setting must return the same value
	lambda6 := g.NewScalar().Random()
	lambdas.Set(participants, lambda6)
	lambda7 := lambdas.Get(participants)

	if lambda6.Equal(lambda7) != 1 {
		t.Fatal("expected equality")
	}
}
