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
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/commitment"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/frost/internal"
)

func badScalar(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ScalarLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func badElement(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ElementLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func comparePublicKeyShare(p1, p2 *frost.PublicKeyShare) error {
	if p1.PublicKey.Equal(p2.PublicKey) != 1 {
		return fmt.Errorf("Expected equality on PublicKey:\n\t%s\n\t%s\n", p1.PublicKey.Hex(), p2.PublicKey.Hex())
	}

	if p1.ID != p2.ID {
		return fmt.Errorf("Expected equality on ID:\n\t%d\n\t%d\n", p1.ID, p2.ID)
	}

	if p1.Group != p2.Group {
		return fmt.Errorf("Expected equality on Group:\n\t%v\n\t%v\n", p1.Group, p2.Group)
	}

	if len(p1.Commitment) != len(p2.Commitment) {
		return fmt.Errorf(
			"Expected equality on Commitment length:\n\t%d\n\t%d\n",
			len(p1.Commitment),
			len(p1.Commitment),
		)
	}

	for i := range p1.Commitment {
		if p1.Commitment[i].Equal(p2.Commitment[i]) != 1 {
			return fmt.Errorf(
				"Expected equality on Commitment %d:\n\t%s\n\t%s\n",
				i,
				p1.Commitment[i].Hex(),
				p1.Commitment[i].Hex(),
			)
		}
	}

	return nil
}

func getPublicKeyShares(keyShares []*frost.KeyShare) []*frost.PublicKeyShare {
	publicKeyShares := make([]*frost.PublicKeyShare, 0, len(keyShares))
	for _, ks := range keyShares {
		publicKeyShares = append(publicKeyShares, ks.Public())
	}

	return publicKeyShares
}

func compareConfigurations(t *testing.T, c1, c2 *frost.Configuration, expectedMatch bool) {
	if c1 == nil || c2 == nil {
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

	if ((c1.GroupPublicKey == nil || c2.GroupPublicKey == nil) || (c1.GroupPublicKey.Equal(c2.GroupPublicKey) != 1)) &&
		expectedMatch {
		t.Fatalf("expected matching GroupPublicKey: %q / %q", c1.Ciphersuite, c2.Ciphersuite)
	}

	if len(c1.SignerPublicKeys) != len(c2.SignerPublicKeys) {
		t.Fatalf(
			"expected matching SignerPublicKeys lengths: %q / %q",
			len(c1.SignerPublicKeys),
			len(c2.SignerPublicKeys),
		)
	}

	for i, p1 := range c1.SignerPublicKeys {
		p2 := c2.SignerPublicKeys[i]
		if err := comparePublicKeyShare(p1, p2); !expectedMatch && err != nil {
			t.Fatal(err)
		}
	}
}

func makeConf(t *testing.T, test *tableTest) *frost.Configuration {
	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      test.Ciphersuite,
		Threshold:        test.threshold,
		MaxSigners:       test.maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		t.Fatal(err)
	}

	return configuration
}

func TestEncoding_Configuration(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err != nil {
			t.Fatal(err)
		}

		compareConfigurations(t, configuration, decoded, true)
	})
}

func TestEncoding_Configuration_InvalidHeaderLength(t *testing.T) {
	expectedError := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded[:24]); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("extected %q, got %q", expectedError, err)
		}
	})
}

func TestEncoding_Configuration_InvalidCiphersuite(t *testing.T) {
	expectedError := internal.ErrInvalidCiphersuite

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		encoded := configuration.Encode()
		encoded[0] = 2

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("extected %q, got %q", expectedError, err)
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
			t.Fatalf("extected %q, got %q", expectedError, err)
		}

		encoded = append(encoded, []byte{0, 1}...)
		if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
			t.Fatalf("extected %q, got %q", expectedError, err)
		}
	})
}

func TestEncoding_Configuration_InvalidGroupPublicKey(t *testing.T) {
	expectedErrorPrefix := "could not decode group public key: element Decode: "

	testAll(t, func(t *testing.T, test *tableTest) {
		configuration := makeConf(t, test)
		g := group.Group(test.Ciphersuite)
		encoded := configuration.Encode()
		bad := badElement(t, g)
		encoded = slices.Replace(encoded, 25, 25+g.ElementLength(), bad...)

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("extected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Configuration_InvalidPublicKeyShare(t *testing.T) {
	expectedErrorPrefix := "could not decode signer public key share for signer 1: "

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
			Threshold:        test.threshold,
			MaxSigners:       test.maxSigners,
			GroupPublicKey:   groupPublicKey,
			SignerPublicKeys: publicKeyShares,
		}
		g := group.Group(test.Ciphersuite)
		pksSize := len(publicKeyShares[0].Encode())
		bad := badElement(t, g)
		offset := 25 + g.ElementLength() + pksSize + 1 + 8 + 4
		encoded := configuration.Encode()
		encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), bad...)

		decoded := new(frost.Configuration)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("extected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func compareKeyShares(s1, s2 *frost.KeyShare) error {
	if s1.Secret.Equal(s2.Secret) != 1 {
		return fmt.Errorf("Expected equality on Secret:\n\t%s\n\t%s\n", s1.Secret.Hex(), s2.Secret.Hex())
	}

	if s1.GroupPublicKey.Equal(s2.GroupPublicKey) != 1 {
		return fmt.Errorf(
			"Expected equality on GroupPublicKey:\n\t%s\n\t%s\n",
			s1.GroupPublicKey.Hex(),
			s2.GroupPublicKey.Hex(),
		)
	}

	return comparePublicKeyShare(s1.Public(), s2.Public())
}

func compareCommitments(c1, c2 *commitment.Commitment) error {
	if c1.Group != c2.Group {
		return errors.New("different groups")
	}

	if c1.SignerID != c2.SignerID {
		return errors.New("different SignerID")
	}

	if c1.CommitmentID != c2.CommitmentID {
		return errors.New("different CommitmentID")
	}

	if c1.HidingNonce.Equal(c2.HidingNonce) != 1 {
		return errors.New("different HidingNonce")
	}

	if c1.BindingNonce.Equal(c2.BindingNonce) != 1 {
		return errors.New("different BindingNonce")
	}

	return nil
}

func compareNonceCommitments(c1, c2 *frost.NonceCommitment) error {
	if c1.HidingNonceS.Equal(c2.HidingNonceS) != 1 {
		return errors.New("different HidingNonceS")
	}

	if c1.BindingNonceS.Equal(c2.BindingNonceS) != 1 {
		return errors.New("different BindingNonceS")
	}

	return compareCommitments(c1.Commitment, c2.Commitment)
}

func makeSigners(t *testing.T, test *tableTest) []*frost.Signer {
	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:      test.Ciphersuite,
		Threshold:        test.threshold,
		MaxSigners:       test.maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		t.Fatal(err)
	}

	signers := make([]*frost.Signer, test.maxSigners)

	for i, keyShare := range keyShares {
		s, err := configuration.Signer(keyShare)
		if err != nil {
			t.Fatal(err)
		}

		signers[i] = s
	}

	return signers
}

func compareSigners(t *testing.T, s1, s2 *frost.Signer) {
	if err := compareKeyShares(s1.KeyShare, s2.KeyShare); err != nil {
		t.Fatal(err)
	}

	if !((s1.Lambda == nil && (s2.Lambda == nil || s2.Lambda.IsZero())) || (s2.Lambda == nil && (s1.Lambda == nil || s1.Lambda.IsZero()))) {
		t.Fatalf("expected equality: %v / %v", s1.Lambda, s2.Lambda.IsZero())
	}

	if len(s1.Commitments) != len(s2.Commitments) {
		t.Fatal("expected equality")
	}

	for id, com := range s1.Commitments {
		if com2, exists := s2.Commitments[id]; !exists {
			t.Fatalf("com id %d does not exist in s2", id)
		} else {
			if err := compareNonceCommitments(com, com2); err != nil {
				t.Fatal(err)
			}
		}
	}

	if bytes.Compare(s1.HidingRandom, s2.HidingRandom) != 0 {
		t.Fatal("expected equality")
	}

	if bytes.Compare(s1.BindingRandom, s2.BindingRandom) != 0 {
		t.Fatal("expected equality")
	}

	compareConfigurations(t, s1.Configuration, s2.Configuration, true)
}

func TestEncoding_Signer(t *testing.T) {
	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		s.Commit()
		encoded := s.Encode()

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err != nil {
			t.Fatal(err)
		}

		compareSigners(t, s, decoded)
	})
}

func TestEncoding_Signer_BadConfHeader(t *testing.T) {
	expectedErr := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:20]); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_BadConf(t *testing.T) {
	expectedErr := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()

		eLen := s.Configuration.Ciphersuite.ECGroup().ElementLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:confLen-2]); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_InvalidLength1(t *testing.T) {
	expectedErr := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()
		eLen := s.Configuration.Ciphersuite.ECGroup().ElementLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:confLen+2]); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_InvalidLength2(t *testing.T) {
	expectedErr := internal.ErrInvalidLength

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		encoded := s.Encode()

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded[:len(encoded)-1]); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}

		if err := decoded.Decode(append(encoded, []byte{0}...)); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("expected error %q, got %q", expectedErr, err)
		}
	})
}

func TestEncoding_Signer_InvalidLambda(t *testing.T) {
	expectedErrorPrefix := "failed to decode lambda:"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]

		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		encoded := s.Encode()
		bad := badScalar(t, g)

		encoded = slices.Replace(encoded, confLen+4, confLen+4+g.ScalarLength(), bad...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("extected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidKeyShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode key share:"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]

		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		offset := confLen + 4 + g.ScalarLength()

		// Set an invalid group in the key share encoding.
		kse := s.KeyShare.Encode()
		kse[0] = 2

		encoded := s.Encode()
		encoded = slices.Replace(encoded, offset, offset+len(kse), kse...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("extected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidCommitmentNonces_DuplicateID(t *testing.T) {
	expectedErrorPrefix := "multiple encoded commitments with the same id:"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		s.Commit()
		s.Commit()
		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		keyShareLen := len(s.KeyShare.Encode())
		commitmentLength := 8 + 2*sLen + int(commitment.EncodedSize(g))
		offset := confLen + 4 + sLen + keyShareLen
		offset2 := offset + commitmentLength

		encoded := s.Encode()
		data := slices.Replace(encoded, offset2, offset2+8, encoded[offset:offset+8]...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidHidingNonceCommitment(t *testing.T) {
	expectedErrorPrefix := "can't decode hiding nonce for commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 4 + sLen + keyShareLen + 8

		encoded := s.Encode()
		data := slices.Replace(encoded, offset, offset+g.ScalarLength(), badScalar(t, g)...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidBindingNonceCommitment(t *testing.T) {
	expectedErrorPrefix := "can't decode binding nonce for commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 4 + sLen + keyShareLen + 8 + g.ScalarLength()

		encoded := s.Encode()
		data := slices.Replace(encoded, offset, offset+g.ScalarLength(), badScalar(t, g)...)

		decoded := new(frost.Signer)
		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signer_InvalidCommitment(t *testing.T) {
	expectedErrorPrefix := "can't decode nonce commitment"

	testAll(t, func(t *testing.T, test *tableTest) {
		s := makeSigners(t, test)[0]
		s.Commit()
		g := group.Group(test.Ciphersuite)
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		pksLen := 1 + 8 + 4 + eLen + int(test.threshold)*eLen
		confLen := 1 + 3*8 + eLen + int(test.maxSigners)*pksLen
		keyShareLen := len(s.KeyShare.Encode())
		offset := confLen + 4 + sLen + keyShareLen + 8 + 2*g.ScalarLength()

		encoded := s.Encode()
		encoded[offset] = 0

		decoded := new(frost.Signer)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func compareSignatureShares(t *testing.T, s1, s2 *frost.SignatureShare) {
	if s1.Group != s2.Group {
		t.Fatal("unexpected group")
	}

	if s1.SignerIdentifier != s2.SignerIdentifier {
		t.Fatal("expected equality")
	}

	if s1.SignatureShare.Equal(s2.SignatureShare) != 1 {
		t.Fatal("expected equality")
	}
}

func TestEncoding_SignatureShare(t *testing.T) {
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make([]*commitment.Commitment, len(signers))
		comsMap := make(map[uint64]*commitment.Commitment, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
			comsMap[s.Identifier()] = coms[i]
		}

		for _, s := range signers {
			com := comsMap[s.Identifier()].CommitmentID
			sigShare, err := s.Sign(com, message, coms)
			if err != nil {
				t.Fatal(err)
			}

			encoded := sigShare.Encode()

			decoded := new(frost.SignatureShare)
			if err = decoded.Decode(encoded); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			compareSignatureShares(t, sigShare, decoded)
		}
	})
}

func TestEncoding_SignatureShare_InvalidCiphersuite(t *testing.T) {
	expectedError := internal.ErrInvalidCiphersuite

	encoded := make([]byte, 3)

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidLength1(t *testing.T) {
	expectedError := internal.ErrInvalidLength

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode([]byte{}); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidLength2(t *testing.T) {
	expectedError := internal.ErrInvalidLength

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode([]byte{1, 0, 0}); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_ZeroID(t *testing.T) {
	// todo: check for zero id in all decodings
	expectedError := errors.New("identifier cannot be 0")
	encoded := make([]byte, 41)
	encoded[0] = 1

	decoded := new(frost.SignatureShare)
	if err := decoded.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected %q, got %q", expectedError, err)
	}
}

func TestEncoding_SignatureShare_InvalidShare(t *testing.T) {
	expectedErrorPrefix := "failed to decode signature share: "
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		signers := makeSigners(t, test)
		coms := make([]*commitment.Commitment, len(signers))
		comsMap := make(map[uint64]*commitment.Commitment, len(signers))
		for i, s := range signers {
			coms[i] = s.Commit()
			comsMap[s.Identifier()] = coms[i]
		}

		s := signers[0]
		com := comsMap[s.Identifier()].CommitmentID

		sigShare, err := s.Sign(com, message, coms)
		if err != nil {
			t.Fatal(err)
		}

		encoded := sigShare.Encode()
		slices.Replace(encoded, 9, 9+test.ECGroup().ScalarLength(), badScalar(t, test.ECGroup())...)

		decoded := new(frost.SignatureShare)
		if err := decoded.Decode(encoded); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func compareSignatures(t *testing.T, s1, s2 *frost.Signature) {
	if s1.R.Equal(s2.R) != 1 {
		t.Fatal("expected equality")
	}

	if s1.Z.Equal(s2.Z) != 1 {
		t.Fatal("expected equality")
	}
}

func TestEncoding_Signature(t *testing.T) {
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.ECGroup().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		encoded := signature.Encode()

		decoded := new(frost.Signature)
		if err = decoded.Decode(test.Ciphersuite, encoded); err != nil {
			t.Fatal(err)
		}

		compareSignatures(t, signature, decoded)
	})
}

func TestEncoding_Signature_InvalidCiphersuite(t *testing.T) {
	decoded := new(frost.Signature)
	if err := decoded.Decode(0, nil); err == nil || err.Error() != internal.ErrInvalidCiphersuite.Error() {
		t.Fatalf("expected %q, got %q", internal.ErrInvalidCiphersuite, err)
	}
}

func TestEncoding_Signature_InvalidLength(t *testing.T) {
	decoded := new(frost.Signature)
	if err := decoded.Decode(1, make([]byte, 63)); err == nil || err.Error() != internal.ErrInvalidLength.Error() {
		t.Fatalf("expected %q, got %q", internal.ErrInvalidLength, err)
	}
}

func TestEncoding_Signature_InvalidR(t *testing.T) {
	expectedErrorPrefix := "invalid signature - decoding R:"
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.ECGroup().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		encoded := signature.Encode()
		slices.Replace(
			encoded,
			0,
			test.Ciphersuite.ECGroup().ElementLength(),
			badElement(t, test.Ciphersuite.ECGroup())...)

		decoded := new(frost.Signature)
		if err := decoded.Decode(test.Ciphersuite, encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestEncoding_Signature_InvalidZ(t *testing.T) {
	expectedErrorPrefix := "invalid signature - decoding Z:"
	message := []byte("message")

	testAll(t, func(t *testing.T, test *tableTest) {
		key := test.ECGroup().NewScalar().Random()
		signature, err := debug.Sign(test.Ciphersuite, message, key)
		if err != nil {
			t.Fatal(err)
		}

		encoded := signature.Encode()
		g := test.Ciphersuite.ECGroup()
		eLen := g.ElementLength()
		sLen := g.ScalarLength()
		slices.Replace(encoded, eLen, eLen+sLen, badScalar(t, g)...)

		decoded := new(frost.Signature)
		if err := decoded.Decode(test.Ciphersuite, encoded); err == nil ||
			!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}
