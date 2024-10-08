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
	"strings"
	"testing"

	debugec "github.com/bytemare/ecc/debug"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
)

func TestMaliciousSigner(t *testing.T) {
}

func TestVerifySignature_BadCiphersuite(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	if err := frost.VerifySignature(2, nil, nil, nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	expectedErrorPrefix := "invalid Signature"
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration, _ := fullSetup(t, test)

		signature := &frost.Signature{
			R: test.Group().Base(),
			Z: test.Group().NewScalar().Random(),
		}

		if err := frost.VerifySignature(test.Ciphersuite, message, signature, configuration.VerificationKey); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestSigner_Sign_NoNonceForCommitmentID(t *testing.T) {
	message := []byte("message")
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}

	signers := makeSigners(t, tt)

	coms := make(frost.CommitmentList, len(signers))
	for i, s := range signers {
		coms[i] = s.Commit()
	}

	coms[0].CommitmentID = 0
	expectedErrorPrefix := fmt.Sprintf(
		"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
		coms[0].CommitmentID,
		coms[0].SignerID,
	)

	if _, err := signers[0].Sign(message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestFrost_NewPublicKeyShare(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration, keyShares := makeConfAndShares(t, test)
		publicKeyShare := keyShares[0].Public()

		newPublicKeyShare, err := frost.NewPublicKeyShare(
			configuration.Ciphersuite,
			publicKeyShare.ID,
			publicKeyShare.PublicKey.Encode(),
		)
		if err != nil {
			t.Fatal(err)
		}

		comparePublicKeyShare(t, publicKeyShare, newPublicKeyShare, true)
	})
}

func TestFrost_NewPublicKeyShare_InvalidCiphersuite(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	if _, err := frost.NewPublicKeyShare(0, 0, nil); err == nil ||
		err.Error() != expectedErrorPrefix.Error() {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestFrost_NewPublicKeyShare_IdentifierIs0(t *testing.T) {
	expectedErrorPrefix := internal.ErrIdentifierIs0

	if _, err := frost.NewPublicKeyShare(frost.Default, 0, nil); err == nil ||
		err.Error() != expectedErrorPrefix.Error() {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestFrost_NewPublicKeyShare_BadPublicKey(t *testing.T) {
	expectedErrorPrefix := "could not decode public share: element Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		bad := debugec.BadElementOffCurve(test.Group())

		if _, err := frost.NewPublicKeyShare(test.Ciphersuite, 1, bad); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestFrost_NewKeyShare(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration, keyShares := makeConfAndShares(t, test)
		keyShare := keyShares[0]

		newKeyShare, err := frost.NewKeyShare(configuration.Ciphersuite, keyShare.ID, keyShare.SecretKey().Encode(),
			keyShare.PublicKey.Encode(), configuration.VerificationKey.Encode())
		if err != nil {
			t.Fatal(err)
		}

		compareKeyShares(t, keyShare, newKeyShare, true)
	})
}

func TestFrost_NewKeyShare_InvalidPublicKey(t *testing.T) {
	expectedErrorPrefix := "could not decode public share: element Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		randomSecret := test.Ciphersuite.Group().NewScalar().Random().Encode()
		bad := debugec.BadElementOffCurve(test.Group())

		if _, err := frost.NewKeyShare(test.Ciphersuite, 1, randomSecret, bad, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestFrost_NewKeyShare_BadSecretKey(t *testing.T) {
	expectedErrorPrefix := "could not decode secret share: scalar Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		bad := debugec.BadScalarHigh(test.Group())
		pk := test.Group().NewElement().Base().Encode()

		if _, err := frost.NewKeyShare(test.Ciphersuite, 1, bad, pk, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestFrost_NewKeyShare_BadPublicKey(t *testing.T) {
	expectedErrorPrefix := "provided key share has non-matching secret and public keys"

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()
		secret := g.NewScalar().Random().Encode()
		badPublic := g.NewElement().Base().Encode()

		if _, err := frost.NewKeyShare(test.Ciphersuite, 1, secret, badPublic, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestFrost_NewKeyShare_InvalidVerificationKey(t *testing.T) {
	expectedErrorPrefix := "could not decode the group public key: element Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		g := test.Ciphersuite.Group()
		secret := g.NewScalar().Random()
		public := g.NewElement().Base().Multiply(secret).Encode()
		bad := debugec.BadElementOffCurve(g)

		if _, err := frost.NewKeyShare(test.Ciphersuite, 1, secret.Encode(), public, bad); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}
