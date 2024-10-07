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
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	debugec "github.com/bytemare/ecc/debug"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

func makeConfAndShares(t *testing.T, test *tableTest) (*frost.Configuration, []*keys.KeyShare) {
	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           test.Ciphersuite,
		Threshold:             test.threshold,
		MaxSigners:            test.maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		t.Fatal(err)
	}

	return configuration, keyShares
}

func makeConf(t *testing.T, test *tableTest) *frost.Configuration {
	c, _ := makeConfAndShares(t, test)
	return c
}

func getPublicKeyShares(keyShares []*keys.KeyShare) []*keys.PublicKeyShare {
	publicKeyShares := make([]*keys.PublicKeyShare, 0, len(keyShares))
	for _, ks := range keyShares {
		publicKeyShares = append(publicKeyShares, ks.Public())
	}

	return publicKeyShares
}

func fullSetup(t *testing.T, test *tableTest) (*frost.Configuration, []*frost.Signer) {
	configuration, keyShares := makeConfAndShares(t, test)
	signers := make([]*frost.Signer, test.maxSigners)

	for i, keyShare := range keyShares {
		s, err := configuration.Signer(keyShare)
		if err != nil {
			t.Fatal(err)
		}

		signers[i] = s
	}

	return configuration, signers
}

func makeSigners(t *testing.T, test *tableTest) []*frost.Signer {
	_, s := fullSetup(t, test)
	return s
}

func compareConfigurations(t *testing.T, a, b serde, expectedMatch bool) {
	c1, ok := a.(*frost.Configuration)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	c2, ok := b.(*frost.Configuration)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if (c1 == nil || c2 == nil) && expectedMatch {
		t.Fatal("nil config")
	}

	if c1.Ciphersuite != c2.Ciphersuite && expectedMatch {
		t.Fatalf("expected matching ciphersuite: %q / %q", c1.Ciphersuite, c2.Ciphersuite)
	}

	if c1.Threshold != c2.Threshold && expectedMatch {
		t.Fatalf("expected matching threshold: %q / %q", c1.Threshold, c2.Threshold)
	}

	if c1.MaxSigners != c2.MaxSigners && expectedMatch {
		t.Fatalf("expected matching max signers: %q / %q", c1.MaxSigners, c2.MaxSigners)
	}

	if ((c1.GroupPublicKey == nil || c2.GroupPublicKey == nil) || !c1.GroupPublicKey.Equal(c2.GroupPublicKey)) &&
		expectedMatch {
		t.Fatalf("expected matching GroupPublicKey: %q / %q", c1.Ciphersuite, c2.Ciphersuite)
	}

	if len(c1.SignerPublicKeyShares) != len(c2.SignerPublicKeyShares) && expectedMatch {
		t.Fatalf(
			"expected matching SignerPublicKeyShares lengths: %q / %q",
			len(c1.SignerPublicKeyShares),
			len(c2.SignerPublicKeyShares),
		)
	}

	for i, p1 := range c1.SignerPublicKeyShares {
		p2 := c2.SignerPublicKeyShares[i]
		comparePublicKeyShare(t, p1, p2, expectedMatch)
	}
}

func comparePublicKeyShare(t *testing.T, a, b serde, expectedMatch bool) {
	p1, ok := a.(*keys.PublicKeyShare)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	p2, ok := b.(*keys.PublicKeyShare)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if !p1.PublicKey.Equal(p2.PublicKey) && expectedMatch {
		t.Fatalf("Expected equality on PublicKey:\n\t%s\n\t%s\n", p1.PublicKey.Hex(), p2.PublicKey.Hex())
	}

	if p1.ID != p2.ID && expectedMatch {
		t.Fatalf("Expected equality on ID:\n\t%d\n\t%d\n", p1.ID, p2.ID)
	}

	if p1.Group != p2.Group && expectedMatch {
		t.Fatalf("Expected equality on Group:\n\t%v\n\t%v\n", p1.Group, p2.Group)
	}

	lenP1Com := len(p1.VssCommitment)
	lenP2Com := len(p2.VssCommitment)

	if lenP1Com != 0 && lenP2Com != 0 {
		if lenP1Com != lenP2Com && expectedMatch {
			t.Fatalf(
				"Expected equality on Commitment length:\n\t%d\n\t%d\n",
				len(p1.VssCommitment),
				len(p2.VssCommitment),
			)
		}

		for i := range p1.VssCommitment {
			if !p1.VssCommitment[i].Equal(p2.VssCommitment[i]) && expectedMatch {
				t.Fatalf(
					"Expected equality on Commitment %d:\n\t%s\n\t%s\n",
					i,
					p1.VssCommitment[i].Hex(),
					p2.VssCommitment[i].Hex(),
				)
			}
		}
	}
}

func compareKeyShares(t *testing.T, a, b serde, expectedMatch bool) {
	s1, ok := a.(*keys.KeyShare)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	s2, ok := b.(*keys.KeyShare)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if !s1.Secret.Equal(s2.Secret) && expectedMatch {
		t.Fatalf("Expected equality on Secret:\n\t%s\n\t%s\n", s1.Secret.Hex(), s2.Secret.Hex())
	}

	if !s1.GroupPublicKey.Equal(s2.GroupPublicKey) && expectedMatch {
		t.Fatalf(
			"Expected equality on GroupPublicKey:\n\t%s\n\t%s\n",
			s1.GroupPublicKey.Hex(),
			s2.GroupPublicKey.Hex(),
		)
	}

	comparePublicKeyShare(t, s1.Public(), s2.Public(), expectedMatch)
}

func compareCommitments(t *testing.T, a, b serde, expectedMatch bool) {
	c1, ok := a.(*frost.Commitment)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	c2, ok := b.(*frost.Commitment)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if c1.SignerID != c2.SignerID && expectedMatch {
		t.Fatal("different SignerID")
	}

	if c1.CommitmentID != c2.CommitmentID && expectedMatch {
		t.Fatal("different CommitmentID")
	}

	if !c1.HidingNonceCommitment.Equal(c2.HidingNonceCommitment) && expectedMatch {
		t.Fatal("different HidingNonceCommitment")
	}

	if !c1.BindingNonceCommitment.Equal(c2.BindingNonceCommitment) && expectedMatch {
		t.Fatal("different BindingNonceCommitment")
	}
}

func compareNonceCommitments(t *testing.T, a, b serde, expectedMatch bool) {
	c1, ok := a.(*frost.Nonce)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	c2, ok := b.(*frost.Nonce)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if !c1.HidingNonce.Equal(c2.HidingNonce) && expectedMatch {
		t.Fatalf("different HidingNonce:\n\t%s\n\t%s\n", c1.HidingNonce.Hex(), c2.HidingNonce.Hex())
	}

	if !c1.BindingNonce.Equal(c2.BindingNonce) && expectedMatch {
		t.Fatalf("different BindingNonce:\n\t%s\n\t%s\n", c1.BindingNonce.Hex(), c2.BindingNonce.Hex())
	}

	compareCommitments(t, c1.Commitment, c2.Commitment, expectedMatch)
}

func compareLambdaRegistries(t *testing.T, m1, m2 map[string]*internal.Lambda, expectedMatch bool) {
	if len(m1) != len(m2) && expectedMatch {
		t.Fatalf("unequal lengths: %d / %d", len(m1), len(m2))
	}

	for k1, v1 := range m1 {
		v2, exists := m2[k1]
		if !exists && expectedMatch {
			t.Fatalf("key %s is not present in second map", k1)
		}

		if v1.Group != v2.Group && expectedMatch {
			t.Fatalf("unequal lambdas for the participant list %s", k1)
		}

		if !v1.Value.Equal(v2.Value) && expectedMatch {
			t.Fatalf("unequal lambdas for the participant list %s", k1)
		}
	}
}

func compareSigners(t *testing.T, a, b serde, expectedMatch bool) {
	s1, ok := a.(*frost.Signer)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	s2, ok := b.(*frost.Signer)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	compareKeyShares(t, s1.KeyShare, s2.KeyShare, expectedMatch)
	compareLambdaRegistries(t, s1.LambdaRegistry, s2.LambdaRegistry, expectedMatch)

	if len(s1.NonceCommitments) != len(s2.NonceCommitments) && expectedMatch {
		t.Fatal("expected equality")
	}

	for id, com := range s1.NonceCommitments {
		if com2, exists := s2.NonceCommitments[id]; !exists {
			t.Fatalf("com id %d does not exist in s2", id)
		} else {
			compareNonceCommitments(t, com, com2, expectedMatch)
		}
	}

	if bytes.Compare(s1.HidingRandom, s2.HidingRandom) != 0 && expectedMatch {
		t.Fatal("expected equality")
	}

	if bytes.Compare(s1.BindingRandom, s2.BindingRandom) != 0 && expectedMatch {
		t.Fatal("expected equality")
	}

	compareConfigurations(t, s1.Configuration, s2.Configuration, expectedMatch)
}

func compareSignatureShares(t *testing.T, a, b serde, expectedMatch bool) {
	s1, ok := a.(*frost.SignatureShare)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	s2, ok := b.(*frost.SignatureShare)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if s1.Group != s2.Group && expectedMatch {
		t.Fatal("unexpected group")
	}

	if s1.SignerIdentifier != s2.SignerIdentifier {
		t.Fatal("expected equality")
	}

	if !s1.SignatureShare.Equal(s2.SignatureShare) {
		t.Fatal("expected equality")
	}
}

func compareSignatures(t *testing.T, a, b serde, expectedMatch bool) {
	s1, ok := a.(*frost.Signature)
	if !ok && expectedMatch {
		t.Fatal("first argument is of wrong type")
	}

	s2, ok := b.(*frost.Signature)
	if !ok && expectedMatch {
		t.Fatal("second argument is of wrong type")
	}

	if !s1.R.Equal(s2.R) && expectedMatch {
		t.Fatalf("expected %v R", expectedMatch)
	}

	if !s1.Z.Equal(s2.Z) && expectedMatch {
		t.Fatalf("expected %v Z", expectedMatch)
	}
}

func TestEncoding_Configuration(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)

		testAndCompareSerde(t, configuration, true, compareConfigurations, func() serde {
			return new(frost.Configuration)
		})
	})
}

func TestEncoding_Configuration_InvalidHeaderLength(t *testing.T) {
	expectedError := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded[:24]); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("expected %q, got %q", expectedError, err)
		}
	})
}

func TestEncoding_Configuration_InvalidCiphersuite(t *testing.T) {
	expectedError := "failed to decode Configuration: " + internal.ErrInvalidCiphersuite.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()
		encoded[0] = 2

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError {
			t.Fatalf("expected %q, got %q", expectedError, err)
		}
	})
}

func TestEncoding_Configuration_InvalidLength(t *testing.T) {
	expectedError := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded[:len(encoded)-1]); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("expected %q, got %q", expectedError, err)
		}

		encoded = append(encoded, []byte{0, 1}...)
		if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("expected %q, got %q", expectedError, err)
		}
	})
}

func TestEncoding_Configuration_InvalidConfigEncoding(t *testing.T) {
	expectedErrorPrefix := "failed to decode Configuration: the threshold in the encoded configuration is higher than the number of maximum participants"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration := makeConf(t, tt)
	configuration.Threshold = configuration.MaxSigners + 1
	encoded := configuration.Encode()

	decoded := new(frost.Configuration)
	if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestEncoding_Configuration_InvalidGroupPublicKey(t *testing.T) {
	expectedErrorPrefix := "failed to decode Configuration: could not decode group public key: element Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		g := ecc.Group(test.Ciphersuite)
		encoded := configuration.Encode()
		bad := debugec.BadElementOffCurve(g)
		encoded = slices.Replace(encoded, 7, 7+g.ElementLength(), bad...)

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Configuration_BadPublicKeyShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode Configuration: could not decode signer public key share for signer 1: "

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        groupPublicKey,
			SignerPublicKeyShares: publicKeyShares,
		}
		g := ecc.Group(test.Ciphersuite)
		pksSize := len(publicKeyShares[0].Encode())
		bad := debugec.BadElementOffCurve(g)
		offset := 7 + g.ElementLength() + pksSize + 1 + 2 + 4
		encoded := configuration.Encode()
		encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), bad...)

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Configuration_InvalidPublicKeyShares(t *testing.T) {
	expectedErrorPrefix := "failed to decode Configuration: invalid number of public keys (lower than threshold or above maximum)"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(
			test.Ciphersuite,
			nil,
			test.threshold,
			test.maxSigners,
		)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        groupPublicKey,
			SignerPublicKeyShares: publicKeyShares,
		}
		configuration.SignerPublicKeyShares = configuration.SignerPublicKeyShares[:test.threshold-1]
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Configuration_CantVerify_InvalidGroupPublicKey(t *testing.T) {
	expectedErrorPrefix := "failed to decode Configuration: invalid group public key, the key is the group generator (base element)"

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		configuration.GroupPublicKey.Base()
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Configuration_BadHex(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		testDecodingHexFails(t, configuration, new(frost.Configuration), "failed to decode Configuration:")
	})
}

func TestEncoding_Configuration_BadJSON(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		errInvalidJSON := "failed to decode Configuration: failed to decode PublicKeyShare: invalid JSON encoding"
		testDecodingJSONFails(t, "failed to decode Configuration",
			errInvalidJSON, configuration, new(frost.Configuration))
	})
}

func TestEncoding_Signer(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[1]
		s.Commit()
		s.Commit()

		participants := make([]uint16, test.maxSigners)
		for i := range test.maxSigners {
			participants[i] = i + 1
		}

		s.LambdaRegistry.New(test.Group(), s.Identifier(), participants)
		// s.LambdaRegistry.New(test.Group(), s.Identifier(), participants[1:])

		testAndCompareSerde(t, s, true, compareSigners, func() serde {
			return new(frost.Signer)
		})
	})
}

func TestEncoding_Signer_BadConfHeader(t *testing.T) {
	expectedErr := "failed to decode Signer: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:20]); err == nil || err.Error() != expectedErr {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_BadConf(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: failed to decode Configuration: could not decode group public key:"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		eLen := s.Configuration.Ciphersuite.Group().ElementLength()
		encoded := s.Encode()
		encoded = slices.Replace(encoded, 7, 7+eLen, debugec.BadElementOffCurve(test.Group())...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidLength1(t *testing.T) {
	expectedErr := "failed to decode Signer: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()
		eLen := s.Configuration.Ciphersuite.Group().ElementLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:confLen+2]); err == nil || err.Error() != expectedErr {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_InvalidLength2(t *testing.T) {
	expectedErr := "failed to decode Signer: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:len(encoded)-1]); err == nil || err.Error() != expectedErr {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}

		if err := decoded.Decode(append(encoded, []byte{0}...)); err == nil || err.Error() != expectedErr {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_InvalidLambda(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: failed to decode lambda registry in signer:"

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)

		g := ecc.Group(test.Ciphersuite)
		message := []byte("message")

		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		s := signers[0]

		_, err := s.Sign(message, coms)
		if err != nil {
			t.Fatal(err)
		}

		confLen := len(s.Configuration.Encode())
		ksLen := len(s.KeyShare.Encode())
		encoded := s.Encode()
		bad := debugec.BadScalarHigh(g)
		offset := confLen + 6 + ksLen + 32
		encoded = slices.Replace(encoded, offset, offset+g.ScalarLength(), bad...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_BadKeyShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: failed to decode KeyShare: invalid group identifier"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		confLen := len(s.Configuration.Encode())
		offset := confLen + 6

		// Set an invalid group in the key share encoding.
		encoded := s.Encode()
		encoded = slices.Replace(encoded, offset, offset+1, []byte{2}...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidKeyShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: invalid key share: invalid identifier for public key share, the identifier is 0"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		confLen := len(s.Configuration.Encode())
		offset := confLen + 6 + 1

		// Set an invalid identifier.
		encoded := s.Encode()
		badID := [2]byte{}
		encoded = slices.Replace(encoded, offset, offset+2, badID[:]...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidCommitmentNonces_DuplicateID(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: multiple encoded commitments with the same id:"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		s.Commit()
		s.Commit()
		g := ecc.Group(test.Ciphersuite)
		sLen := g.ScalarLength()
		confLen := len(s.Configuration.Encode())
		keyShareLen := len(s.KeyShare.Encode())
		commitmentLength := 1 + 8 + 2 + 2*uint64(g.ElementLength())
		nonceCommitmentLength := 8 + 2*sLen + int(commitmentLength)
		offset := confLen + 6 + keyShareLen
		offset2 := offset + nonceCommitmentLength

		encoded := s.Encode()
		data := slices.Replace(encoded, offset2, offset2+8, encoded[offset:offset+8]...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidHidingNonceCommitment(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: can't decode hiding nonce for commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := ecc.Group(test.Ciphersuite)
		confLen := len(s.Configuration.Encode())
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 6 + keyShareLen + 8

		encoded := s.Encode()
		data := slices.Replace(encoded, offset, offset+g.ScalarLength(), debugec.BadScalarHigh(g)...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidBindingNonceCommitment(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: can't decode binding nonce for commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := ecc.Group(test.Ciphersuite)
		confLen := len(s.Configuration.Encode())
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 6 + keyShareLen + 8 + g.ScalarLength()

		encoded := s.Encode()
		data := slices.Replace(encoded, offset, offset+g.ScalarLength(), debugec.BadScalarHigh(g)...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidCommitment(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signer: can't decode nonce commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := ecc.Group(test.Ciphersuite)
		sLen := g.ScalarLength()
		confLen := len(s.Configuration.Encode())
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 6 + keyShareLen + 8 + 2*sLen

		encoded := s.Encode()
		encoded[offset] = 0

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_BadHex(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		testDecodingHexFails(t, s, new(frost.Signer), "failed to decode Signer:")
	})
}

func TestEncoding_Signer_BadJSON(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		errInvalidJSON := "failed to decode Signer: failed to decode KeyShare: invalid JSON encoding"
		testDecodingJSONFails(t, "failed to decode Signer",
			errInvalidJSON, s, new(frost.Signer))
	})
}

func TestEncoding_SignatureShare(t *testing.T) {
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		for _, s := range signers {
			sigShare, err := s.Sign(message, coms)
			if err != nil {
				t.Fatal(err)
			}

			testAndCompareSerde(t, sigShare, true, compareSignatureShares, func() serde {
				return new(frost.SignatureShare)
			})
		}
	})
}

func TestEncoding_SignatureShare_InvalidCiphersuite(t *testing.T) {
	expectedError := "failed to decode SignatureShare: " + internal.ErrInvalidCiphersuite.Error()

	encoded := make([]byte, 3)

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidLength1(t *testing.T) {
	expectedError := "failed to decode SignatureShare: " + internal.ErrInvalidLength.Error()

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode([]byte{}); err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidLength2(t *testing.T) {
	expectedError := "failed to decode SignatureShare: " + internal.ErrInvalidLength.Error()

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode([]byte{1, 0, 0}); err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidIdentifier(t *testing.T) {
	// todo: check for zero id in all decodings
	expectedError := errors.New("failed to decode SignatureShare: identifier cannot be 0")
	encoded := make([]byte, 35)
	encoded[0] = 1

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode SignatureShare: scalar Decode: invalid scalar encoding"
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		s := signers[0]

		sigShare, err := s.Sign(message, coms)
		if err != nil {
			t.Fatal(err)
		}

		encoded := sigShare.Encode()
		slices.Replace(encoded, 3, 3+test.Group().ScalarLength(), debugec.BadScalarHigh(test.Group())...)

		decoded := new(frost.SignatureShare)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_SignatureShare_BadHex(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		s := signers[0]

		sigShare, err := s.Sign([]byte("message"), coms)
		if err != nil {
			t.Fatal(err)
		}

		testDecodingHexFails(t, sigShare, new(frost.SignatureShare), "failed to decode SignatureShare:")
	})
}

func TestEncoding_SignatureShare_BadJSON(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		s := signers[0]

		sigShare, err := s.Sign([]byte("message"), coms)
		if err != nil {
			t.Fatal(err)
		}

		errInvalidJSON := "failed to decode SignatureShare: invalid JSON encoding"
		testDecodingJSONFails(t, "failed to decode SignatureShare",
			errInvalidJSON, sigShare, new(frost.SignatureShare))
	})
}

func TestEncoding_Signature(t *testing.T) {
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.Group().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		testAndCompareSerde(t, signature, true, compareSignatures, func() serde {
			return new(frost.Signature)
		})
	})
}

func TestEncoding_Signature_InvalidCiphersuite(t *testing.T) {
	expectedError := "failed to decode Signature: " + internal.ErrInvalidCiphersuite.Error()
	decoded := new(frost.Signature)

	if err := decoded.Decode([]byte{2, 0}); err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_Signature_InvalidLength(t *testing.T) {
	expectedError := "failed to decode Signature: " + internal.ErrInvalidLength.Error()
	decoded := new(frost.Signature)
	b := make([]byte, 63)
	b[0] = 1
	if err := decoded.Decode(b); err == nil || err.Error() != expectedError {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_Signature_InvalidR(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signature: invalid encoding of R proof: element Decode: "
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.Group().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		encoded := signature.Encode()

		bad := debugec.BadElementOffCurve(test.Ciphersuite.Group())
		slices.Replace(
			encoded,
			1,
			1+test.Ciphersuite.Group().ElementLength(),
			bad...)

		decoded := new(frost.Signature)
		if err = decoded.Decode(encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signature_InvalidZ(t *testing.T) {
	expectedErrorPrefix := "failed to decode Signature: invalid encoding of z proof: scalar Decode: "
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.Group().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		encoded := signature.Encode()
		g := test.Ciphersuite.Group()
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		slices.Replace(encoded, 1+eLen, 1+eLen+sLen, debugec.BadScalarHigh(g)...)

		decoded := new(frost.Signature)
		if err := decoded.Decode(encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signature_BadHex(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.Group().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, []byte("message"), key)
		if err != nil {
			t.Fatal(err)
		}

		testDecodingHexFails(t, signature, new(frost.Signature), "failed to decode Signature:")
	})
}

func TestEncoding_Signature_BadJSON(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.Group().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, []byte("message"), key)
		if err != nil {
			t.Fatal(err)
		}

		errInvalidJSON := "failed to decode Signature: invalid JSON encoding"
		testDecodingJSONFails(t, "failed to decode Signature",
			errInvalidJSON, signature, new(frost.Signature))
	})
}

func TestEncoding_Commitment(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()

		testAndCompareSerde(t, com, true, compareCommitments, func() serde {
			return new(frost.Commitment)
		})
	})
}

func TestEncoding_Commitment_BadCiphersuite(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: " + internal.ErrInvalidCiphersuite.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		encoded := com.Encode()
		encoded[0] = 0

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_InvalidLength1(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		encoded := com.Encode()

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded[:16]); err == nil || err.Error() != expectedErrorPrefix {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_InvalidLength2(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		encoded := com.Encode()

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded[:35]); err == nil || err.Error() != expectedErrorPrefix {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_InvalidIdentifier(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: identifier cannot be 0"

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		com.SignerID = 0
		encoded := com.Encode()

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_InvalidHidingNonce(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: invalid encoding of hiding nonce commitment: "

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		encoded := com.Encode()
		bad := debugec.BadElementOffCurve(test.Group())
		slices.Replace(encoded, 11, 11+test.Group().ElementLength(), bad...)

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_InvalidBindingNonce(t *testing.T) {
	expectedErrorPrefix := "failed to decode Commitment: invalid encoding of binding nonce commitment: "

	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()
		encoded := com.Encode()
		g := test.Group()
		bad := debugec.BadElementOffCurve(g)
		slices.Replace(encoded, 11+g.ElementLength(), 11+2*g.ElementLength(), bad...)

		decoded := new(frost.Commitment)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Commitment_BadHex(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()

		testDecodingHexFails(t, com, new(frost.Commitment), "failed to decode Commitment:")
	})
}

func TestEncoding_Commitment_BadJSON(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signer := makeSigners(t, test)[0]
		com := signer.Commit()

		errInvalidJSON := "failed to decode Commitment: invalid JSON encoding"
		testDecodingJSONFails(t, "failed to decode Commitment",
			errInvalidJSON, com, new(frost.Commitment))
	})
}

func TestEncoding_CommitmentList(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		encoded := coms.Encode()

		list, err := frost.DecodeList(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if len(list) != len(coms) {
			t.Fatalf("want %d, got %d", len(coms), len(list))
		}

		for i, com := range coms {
			compareCommitments(t, com, list[i], true)
		}
	})
}

func TestEncoding_CommitmentList_Empty(t *testing.T) {
	com := frost.CommitmentList{}
	if out := com.Encode(); out != nil {
		t.Fatal("unexpected output")
	}
}

func TestEncoding_CommitmentList_InvalidCiphersuite(t *testing.T) {
	expectedErrorPrefix := "failed to decode CommitmentList: " + internal.ErrInvalidCiphersuite.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		encoded := coms.Encode()
		encoded[0] = 0

		if _, err := frost.DecodeList(encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_CommitmentList_InvalidLength_Short(t *testing.T) {
	expectedErrorPrefix := "failed to decode CommitmentList: " + internal.ErrInvalidLength.Error()

	if _, err := frost.DecodeList([]byte{0, 0}); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestEncoding_CommitmentList_InvalidLength1(t *testing.T) {
	expectedErrorPrefix := "failed to decode CommitmentList: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		encoded := coms.Encode()

		if _, err := frost.DecodeList(encoded[:8]); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_CommitmentList_InvalidLength2(t *testing.T) {
	expectedErrorPrefix := "failed to decode CommitmentList: " + internal.ErrInvalidLength.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		encoded := coms.Encode()

		if _, err := frost.DecodeList(encoded[:9]); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_CommitmentList_InvalidCommitment(t *testing.T) {
	expectedErrorPrefix := "failed to decode CommitmentList: invalid encoding of commitment: failed to decode Commitment: " + internal.ErrInvalidCiphersuite.Error()

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make(frost.CommitmentList, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
		}

		encoded := coms.Encode()
		encoded[3] = 0

		if _, err := frost.DecodeList(encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

/*

 */

type serde interface {
	Encode() []byte
	Decode([]byte) error
	Hex() string
	DecodeHex(string) error
	json.Unmarshaler
}

type tester func(t *testing.T, in, out serde) error

func testByteEncoding(t *testing.T, in, out serde) error {
	bEnc := in.Encode()

	if err := out.Decode(bEnc); err != nil {
		return err
	}

	return nil
}

func testHexEncoding(t *testing.T, in, out serde) error {
	h := in.Hex()

	if err := out.DecodeHex(h); err != nil {
		return err
	}

	return nil
}

func testJSONEncoding(t *testing.T, in, out serde) error {
	jsonEnc, err := json.Marshal(in)
	if err != nil {
		return err
	}

	t.Log(string(jsonEnc))

	if err = json.Unmarshal(jsonEnc, out); err != nil {
		return err
	}

	return nil
}

func testAndCompareSerdeSimple(
	t *testing.T,
	in serde,
	maker func() serde,
	expectedMatch bool,
	tester tester,
	compare func(t *testing.T, a, b serde, expectedMatch bool),
) {
	out := maker()
	if err := tester(t, in, out); err != nil {
		t.Fatal(err)
	}
	compare(t, in, out, expectedMatch)
}

func testAndCompareSerde(
	t *testing.T,
	in serde,
	expectedMatch bool,
	compare func(t *testing.T, a, b serde, expectedMatch bool),
	maker func() serde,
) {
	testAndCompareSerdeSimple(t, in, maker, expectedMatch, testByteEncoding, compare)
	testAndCompareSerdeSimple(t, in, maker, expectedMatch, testHexEncoding, compare)
	testAndCompareSerdeSimple(t, in, maker, expectedMatch, testJSONEncoding, compare)
}

func testDecodingHexFails(t *testing.T, thing1, thing2 serde, expectedErrorPrefix string) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatal("expected error on empty string")
	}

	// uneven length
	e := thing1.Hex()
	if err := thing2.DecodeHex(e[:len(e)-1]); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatal("expected error on empty string")
	}

	// malformed string
	hexed := thing1.Hex()
	malformed := []rune(hexed)
	malformed[0] = []rune("_")[0]

	expectedError := expectedErrorPrefix + " encoding/hex: invalid byte: U+005F '_'"

	if err := thing2.DecodeHex(string(malformed)); err == nil {
		t.Fatal("expected error on malformed string")
	} else if err.Error() != expectedError {
		t.Fatalf("unexpected error: want %q, got %q", expectedError, err)
	}
}

type jsonTesterBaddie struct {
	key, value, expectedError string
}

func testJSONBaddie(in any, decoded json.Unmarshaler, baddie jsonTesterBaddie) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}

	data = replaceStringInBytes(data, baddie.key, baddie.value)

	err = json.Unmarshal(data, decoded)

	if len(baddie.expectedError) != 0 { // we're expecting an error
		if err == nil ||
			!strings.HasPrefix(err.Error(), baddie.expectedError) {
			return fmt.Errorf("expected error %q, got %q", baddie.expectedError, err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("unexpected error %q", err)
		}
	}

	return nil
}

func testDecodingJSONFails(
	t *testing.T,
	errPrefix, badJSONErr string,
	in any,
	decoded json.Unmarshaler,
	baddies ...jsonTesterBaddie,
) {
	errInvalidCiphersuite := errPrefix + ": invalid group"

	// JSON: bad json
	baddie := jsonTesterBaddie{
		key:           "\"group\"",
		value:         "bad",
		expectedError: "invalid character 'b' looking for beginning of object key string",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		t.Fatal(err)
	}

	// UnmarshallJSON: bad group
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":2, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		t.Fatal(err)
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":70, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		t.Fatal(err)
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":-1, \"oldGroup\"",
		expectedError: badJSONErr,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		t.Fatal(err)
	}

	// UnmarshallJSON: bad ciphersuite
	overflow := "9223372036854775808" // MaxInt64 + 1
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":" + overflow + ", \"oldGroup\"",
		expectedError: errPrefix + ": failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		t.Fatal(err)
	}

	// Replace keys and values
	for _, baddie = range baddies {
		if err := testJSONBaddie(in, decoded, baddie); err != nil {
			t.Fatal(err)
		}
	}
}
