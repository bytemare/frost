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

	"github.com/bytemare/secret-sharing/keys"

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
			Ciphersuite:           2,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        groupPublicKey,
			SignerPublicKeyShares: publicKeyShares,
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
			Ciphersuite:           test.Ciphersuite,
			Threshold:             0,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        groupPublicKey,
			SignerPublicKeyShares: publicKeyShares,
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
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.maxSigners + 1,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        groupPublicKey,
			SignerPublicKeyShares: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Nil(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        nil,
			SignerPublicKeyShares: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Identity(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is the identity element"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        test.Group().NewElement(),
			SignerPublicKeyShares: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_Verify_GroupPublicKey_Generator(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is the group generator (base element)"

	testAll(t, func(t *testing.T, test *tableTest) {
		keyShares, _, _ := debug.TrustedDealerKeygen(test.Ciphersuite, nil, test.threshold, test.maxSigners)
		publicKeyShares := getPublicKeyShares(keyShares)

		configuration := &frost.Configuration{
			Ciphersuite:           test.Ciphersuite,
			Threshold:             test.threshold,
			MaxSigners:            test.maxSigners,
			GroupPublicKey:        test.Group().Base(),
			SignerPublicKeyShares: publicKeyShares,
		}

		if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
		}
	})
}

func TestConfiguration_VerifySignerPublicKeys_InvalidNumber(t *testing.T) {
	expectedErrorPrefix := "invalid number of public keys (lower than threshold or above maximum)"

	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	// nil
	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: nil,
	}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// empty
	configuration.SignerPublicKeyShares = []*keys.PublicKeyShare{}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// too few
	configuration.SignerPublicKeyShares = publicKeyShares[:threshold-1]

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// too many
	configuration.SignerPublicKeyShares = append(publicKeyShares, &keys.PublicKeyShare{})

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Nil(t *testing.T) {
	expectedErrorPrefix := "empty public key share at index 1"

	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)
	publicKeyShares[threshold-1] = nil

	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_BadPublicKey(t *testing.T) {
	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	// nil pk
	expectedErrorPrefix := fmt.Sprintf(
		"invalid public key for participant %d, the key is nil",
		configuration.SignerPublicKeyShares[threshold-1].ID,
	)
	configuration.SignerPublicKeyShares[threshold-1].PublicKey = nil

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// identity
	expectedErrorPrefix = fmt.Sprintf(
		"invalid public key for participant %d, the key is the identity element",
		configuration.SignerPublicKeyShares[threshold-1].ID,
	)
	configuration.SignerPublicKeyShares[threshold-1].PublicKey = ciphersuite.Group().NewElement()

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	// generator
	expectedErrorPrefix = fmt.Sprintf(
		"invalid public key for participant %d, the key is the group generator (base element)",
		configuration.SignerPublicKeyShares[threshold-1].ID,
	)
	configuration.SignerPublicKeyShares[threshold-1].PublicKey = ciphersuite.Group().Base()

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Duplicate_Identifiers(t *testing.T) {
	expectedErrorPrefix := "found duplicate identifier for signer 1"

	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	// duplicate id
	id1 := configuration.SignerPublicKeyShares[0].ID
	configuration.SignerPublicKeyShares[1].ID = id1

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignerPublicKeys_Duplicate_PublicKeys(t *testing.T) {
	expectedErrorPrefix := "found duplicate public keys for signers 2 and 1"

	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	// duplicate id
	pk1 := configuration.SignerPublicKeyShares[0].PublicKey.Copy()
	configuration.SignerPublicKeyShares[1].PublicKey = pk1

	if err := configuration.Init(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_InvalidConfiguration(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration := &frost.Configuration{
		Ciphersuite:           tt.Ciphersuite,
		Threshold:             tt.threshold,
		MaxSigners:            tt.maxSigners,
		GroupPublicKey:        nil,
		SignerPublicKeyShares: nil,
	}

	if err := configuration.ValidatePublicKeyShare(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_Nil(t *testing.T) {
	expectedErrorPrefix := "public key share is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	if err := configuration.ValidatePublicKeyShare(nil); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_WrongGroup(t *testing.T) {
	expectedErrorPrefix := "key share has invalid group parameter, want ristretto255_XMD:SHA-512_R255MAP_RO_ got 0"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	pks := &keys.PublicKeyShare{
		Group: 0,
	}

	if err := configuration.ValidatePublicKeyShare(pks); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_ID0(t *testing.T) {
	expectedErrorPrefix := "invalid identifier for public key share, the identifier is 0"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	pks := &keys.PublicKeyShare{
		Group: tt.Group(),
		ID:    0,
	}

	if err := configuration.ValidatePublicKeyShare(pks); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_InvalidID(t *testing.T) {
	expectedErrorPrefix := "invalid identifier for public key share, the identifier 4 is above authorized range [1:3]"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	pks := &keys.PublicKeyShare{
		Group: tt.Group(),
		ID:    tt.maxSigners + 1,
	}

	if err := configuration.ValidatePublicKeyShare(pks); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidatePublicKeyShare_InvalidPublicKey(t *testing.T) {
	expectedErrorPrefix := "invalid public key for participant 1, the key is the group generator (base element)"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	pks := &keys.PublicKeyShare{
		Group:     tt.Group(),
		ID:        1,
		PublicKey: tt.Group().Base(),
	}

	if err := configuration.ValidatePublicKeyShare(pks); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_InvalidConfiguration(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration := &frost.Configuration{
		Ciphersuite:           tt.Ciphersuite,
		Threshold:             tt.threshold,
		MaxSigners:            tt.maxSigners,
		GroupPublicKey:        nil,
		SignerPublicKeyShares: nil,
	}

	if err := configuration.ValidateKeyShare(nil); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_Nil(t *testing.T) {
	expectedErrorPrefix := "provided key share is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, _ := makeConfAndShares(t, tt)

	if err := configuration.ValidateKeyShare(nil); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_InvalidGroupPublicKey(t *testing.T) {
	expectedErrorPrefix := "the key share's group public key does not match the one in the configuration"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)
	keyShare := keyShares[0]

	keyShare.GroupPublicKey = nil
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	keyShare.GroupPublicKey = tt.Group().NewElement()
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	keyShare.GroupPublicKey.Base()
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_BadPublicKeyShare(t *testing.T) {
	expectedErrorPrefix := "invalid public key for participant 1, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)
	keyShare := keyShares[0]

	keyShare.PublicKey = nil
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_InvalidSecretKey(t *testing.T) {
	expectedErrorPrefix := "provided key share has invalid secret key"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)
	keyShare := keyShares[0]

	keyShare.Secret = nil
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}

	keyShare.Secret = tt.Group().NewScalar()
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_KeysNotMatching(t *testing.T) {
	expectedErrorPrefix := "provided key share has non-matching secret and public keys"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)
	keyShare := keyShares[0]

	random := tt.Group().NewScalar().Random()
	keyShare.PublicKey = tt.Group().Base().Multiply(random)
	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_SignerIDNotRegistered(t *testing.T) {
	expectedErrorPrefix := "provided key share has no registered signer identifier in the configuration"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)

	pks := make([]*keys.PublicKeyShare, len(keyShares)-1)
	for i, ks := range keyShares[1:] {
		pks[i] = ks.Public()
	}

	configuration.SignerPublicKeyShares = pks

	if err := configuration.ValidateKeyShare(keyShares[0]); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_ValidateKeyShare_WrongPublicKey(t *testing.T) {
	expectedErrorPrefix := "provided key share has a different public key than the one registered for that signer in the configuration"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}
	configuration, keyShares := makeConfAndShares(t, tt)

	random := tt.Group().NewScalar().Random()
	keyShare := &keys.KeyShare{
		Secret:         random,
		GroupPublicKey: keyShares[0].GroupPublicKey,
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey: tt.Group().Base().Multiply(random),
			ID:        keyShares[0].ID,
			Group:     keyShares[0].Group(),
		},
	}

	if err := configuration.ValidateKeyShare(keyShare); err == nil || err.Error() != expectedErrorPrefix {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_Signer_NotVerified(t *testing.T) {
	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	if _, err := configuration.Signer(keyShares[0]); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguration_Signer_BadConfig(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite
	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           2,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	if _, err := configuration.Signer(keyShares[0]); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_Singer_BadKeyShare(t *testing.T) {
	expectedErrorPrefix := "provided key share is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   2,
		maxSigners:  3,
	}

	configuration := makeConf(t, tt)

	if _, err := configuration.Signer(nil); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_VerifySignatureShare_BadPrep(t *testing.T) {
	expectedErrorPrefix := internal.ErrInvalidCiphersuite

	ciphersuite := frost.Ristretto255
	threshold := uint16(2)
	maxSigners := uint16(3)

	keyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	publicKeyShares := getPublicKeyShares(keyShares)

	configuration := &frost.Configuration{
		Ciphersuite:           2,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		GroupPublicKey:        groupPublicKey,
		SignerPublicKeyShares: publicKeyShares,
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
	expectedErrorPrefix := "invalid identifier for signer in signature share, the identifier is 0"
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

	expectedErrorPrefix := fmt.Sprintf(
		"invalid identifier for signer in signature share, the identifier %d is above authorized range [1:%d]",
		sigShare.SignerIdentifier,
		tt.maxSigners,
	)

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

	configuration.SignerPublicKeyShares = slices.Delete(configuration.SignerPublicKeyShares, 0, 1)
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
		"invalid list of commitments: invalid identifier for signer in commitment %d, the identifier is 0",
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
		SignatureShare:   tt.Ciphersuite.Group().NewScalar().Random(),
		SignerIdentifier: 1,
		Group:            tt.Ciphersuite.Group(),
	}

	if err := configuration.VerifySignatureShare(sigShare, message, coms); err == nil ||
		!strings.HasPrefix(err.Error(), expectedErrorPrefix) {
		t.Fatalf("expected %q, got %q", expectedErrorPrefix, err)
	}
}

func TestConfiguration_AggregateSignatures_InvalidConfiguration(t *testing.T) {
	expectedErrorPrefix := "invalid group public key, the key is nil"
	tt := &tableTest{
		Ciphersuite: frost.Ristretto255,
		threshold:   3,
		maxSigners:  5,
	}
	configuration := &frost.Configuration{
		Ciphersuite:           tt.Ciphersuite,
		Threshold:             tt.threshold,
		MaxSigners:            tt.maxSigners,
		GroupPublicKey:        nil,
		SignerPublicKeyShares: nil,
	}

	if _, err := configuration.AggregateSignatures(nil, nil, nil, false); err == nil ||
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
