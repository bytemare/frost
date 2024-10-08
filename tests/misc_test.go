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
	"strings"
	"testing"

	"github.com/bytemare/dkg"
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

func verifyTrustedDealerKeygen(
	t *testing.T,
	test *tableTest,
	ks []*keys.KeyShare,
	pk *ecc.Element,
	coms []*ecc.Element,
) {
	if len(coms) != int(test.threshold) {
		t.Fatalf("%d / %d", len(coms), test.threshold)
	}

	recoveredKey, err := debug.RecoverGroupSecret(test.Ciphersuite, ks[:test.threshold])
	if err != nil {
		t.Fatal(err)
	}

	verificationKey, participantPublicKeys, err := debug.RecoverPublicKeys(
		test.Ciphersuite,
		test.maxSigners,
		coms,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(participantPublicKeys) != int(test.maxSigners) {
		t.Fatal()
	}

	if !verificationKey.Equal(pk) {
		t.Fatal()
	}

	g := test.Ciphersuite.Group()

	for i, shareI := range ks {
		if !debug.VerifyVSS(g, shareI, coms) {
			t.Fatal(i)
		}
	}

	sig, err := debug.Sign(test.Ciphersuite, []byte("message"), recoveredKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = frost.VerifySignature(test.Ciphersuite, []byte("message"), sig, verificationKey); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedDealerKeygen(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()
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
		g := test.Group()
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

		compareSignatures(t, signature1, signature2, false)

		// Same key, same message = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		compareSignatures(t, signature1, signature2, false)

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

		compareSignatures(t, signature1, signature2, true)

		// Same key, same message, explicit different random = same signatures
		k1 := g.NewScalar().Random()
		k2 := g.NewScalar().Random()

		if k1.Equal(k2) {
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

		compareSignatures(t, signature1, signature2, false)

		// Different keys, same message = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message1, secretKey2)
		if err != nil {
			t.Fatal(err)
		}

		compareSignatures(t, signature1, signature2, false)

		// Different keys, different messages = different signatures
		signature1, err = debug.Sign(test.Ciphersuite, message1, secretKey1)
		if err != nil {
			t.Fatal(err)
		}

		signature2, err = debug.Sign(test.Ciphersuite, message2, secretKey2)
		if err != nil {
			t.Fatal(err)
		}

		compareSignatures(t, signature1, signature2, false)
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

		verificationKey, participantPublicKeys, err := debug.RecoverPublicKeys(
			test.Ciphersuite,
			test.maxSigners,
			secretsharingCommitment,
		)
		if err != nil {
			t.Fatal(err)
		}

		if !dealerGroupPubKey.Equal(verificationKey) {
			t.Fatal("expected equality")
		}

		if len(participantPublicKeys) != len(keyShares) {
			t.Fatal("expected equality")
		}

		for i, keyShare := range keyShares {
			if !keyShare.PublicKey.Equal(participantPublicKeys[i]) {
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
	expectedError := "can't recover public keys: commitment has nil element"
	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)
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
			test.Ciphersuite.Group(),
			test.threshold,
			test.maxSigners,
		)

		vssComs := make([][]*ecc.Element, test.maxSigners)
		pkShares := make([]*keys.PublicKeyShare, test.maxSigners)

		for i, keyShare := range keyShares {
			pk := keyShare.Public()
			vssComs[i] = pk.VssCommitment
			pkShares[i] = pk
		}

		if err := dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), 0, dealerGroupPubKey, vssComs); err != nil {
			t.Fatal(err)
		}

		for _, pk := range pkShares {
			if err := dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), pk.ID, pk.PublicKey, vssComs); err != nil {
				t.Fatalf("expected validity: %s", err)
			}
		}
	})
}

func TestPublicKeyShareVerificationFail(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, dealerGroupPubKey, _ := runDKG(
			t,
			test.Ciphersuite.Group(),
			test.threshold,
			test.maxSigners,
		)

		vssComs := make([][]*ecc.Element, test.maxSigners)
		pkShares := make([]*keys.PublicKeyShare, test.maxSigners)

		for i, keyShare := range keyShares {
			pk := keyShare.Public()
			vssComs[i] = pk.VssCommitment
			pk.PublicKey = test.Group().Base()
			pkShares[i] = pk
		}

		if err := dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), 0, dealerGroupPubKey, vssComs); err != nil {
			t.Fatal(err)
		}

		for _, pk := range pkShares {
			if dkg.VerifyPublicKey(dkg.Ciphersuite(test.Ciphersuite), pk.ID, pk.PublicKey, vssComs) == nil {
				t.Fatal("expected invalidity")
			}
		}
	})
}

func runComputeLambda(g ecc.Group, id uint16, expectedValue *ecc.Scalar, participants ...int) *ecc.Scalar {
	ps := make([]*ecc.Scalar, len(participants))
	for i, p := range participants {
		ps[i] = g.NewScalar().SetUInt64(uint64(p))
	}

	if s := internal.ComputeLambda(g, id, ps); !s.Equal(expectedValue) {
		return s
	}

	return nil
}

func TestComputeLambda_BadID(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Group()

		// id is 0
		expected := g.NewScalar().SetUInt64(1)
		if s := runComputeLambda(g, 0, expected, 1, 2, 3); s != nil {
			t.Fatalf("expected %v, got %v", expected.Hex(), s.Hex())
		}

		// no participants
		if s := runComputeLambda(g, 1, expected); s != nil {
			t.Fatalf("expected %v, got %v", expected.Hex(), s.Hex())
		}

		// participants has 0 id
		expected = g.NewScalar()
		if s := runComputeLambda(g, 1, expected, 2, 0, 3); s != nil {
			t.Fatalf("expected %v, got %v", expected.Hex(), s.Hex())
		}

		// participants has only 0 ids
		expected = g.NewScalar()
		if s := runComputeLambda(g, 1, expected, 0, 0, 0); s != nil {
			t.Fatalf("expected %v, got %v", expected.Hex(), s.Hex())
		}
	})
}
