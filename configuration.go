// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost/internal"
)

// Configuration holds the Configuration for a signing session.
type Configuration struct {
	VerificationKey       *ecc.Element           `json:"verificationKey"`
	SignerPublicKeyShares []*keys.PublicKeyShare `json:"signerPublicKeyShares"`
	Threshold             uint16                 `json:"threshold"`
	MaxSigners            uint16                 `json:"maxSigners"`
	Ciphersuite           Ciphersuite            `json:"ciphersuite"`
	group                 ecc.Group
	verified              bool
	keysVerified          bool
}

var (
	errInvalidThresholdParameter = errors.New("threshold is 0 or higher than maxSigners")
	errInvalidMaxSignersOrder    = errors.New("maxSigners is higher than group order")
	errInvalidNumberOfPublicKeys = errors.New("invalid number of public keys (lower than threshold or above maximum)")
	errKeyShareNotMatch          = errors.New(
		"the key share's group public key does not match the one in the configuration",
	)
	errInvalidSecretKey         = errors.New("provided key share has invalid secret key")
	errKeyShareNil              = errors.New("provided key share is nil")
	errInvalidKeyShare          = errors.New("provided key share has non-matching secret and public keys")
	errInvalidKeyShareUnknownID = errors.New(
		"provided key share has no registered signer identifier in the configuration",
	)
	errPublicKeyShareNoMatch = errors.New(
		"provided key share has a different public key than the one registered for that signer in the configuration",
	)
)

// Init verifies whether the configuration's components are valid, in which case it initializes internal values, or
// returns an error otherwise.
func (c *Configuration) Init() error {
	if !c.verified {
		if err := c.verifyConfiguration(); err != nil {
			return err
		}
	}

	if !c.keysVerified {
		if err := c.verifySignerPublicKeyShares(); err != nil {
			return err
		}
	}

	return nil
}

// Signer returns a new participant of the protocol instantiated from the Configuration and the signer's key share.
func (c *Configuration) Signer(keyShare *keys.KeyShare) (*Signer, error) {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}

	if err := c.ValidateKeyShare(keyShare); err != nil {
		return nil, err
	}

	return &Signer{
		KeyShare:         keyShare,
		LambdaRegistry:   make(internal.LambdaRegistry),
		NonceCommitments: make(map[uint64]*Nonce),
		HidingRandom:     nil,
		BindingRandom:    nil,
		Configuration:    c,
	}, nil
}

// ValidatePublicKeyShare returns an error if they PublicKeyShare has invalid components or properties that not
// compatible with the configuration.
func (c *Configuration) ValidatePublicKeyShare(pks *keys.PublicKeyShare) error {
	if !c.verified {
		if err := c.verifyConfiguration(); err != nil {
			return err
		}
	}

	if pks == nil {
		return errors.New("public key share is nil")
	}

	if pks.Group() != c.group {
		return fmt.Errorf("key share has invalid group parameter, want %s got %d", c.group, pks.Group())
	}

	if err := c.validateIdentifier(pks.Identifier()); err != nil {
		return fmt.Errorf("invalid identifier for public key share, the %w", err)
	}

	if err := c.validateGroupElement(pks.PublicKey()); err != nil {
		return fmt.Errorf("invalid public key for participant %d, the key %w", pks.Identifier(), err)
	}

	return nil
}

// ValidateKeyShare returns an error if they KeyShare has invalid components or properties that not compatible with the
// configuration.
func (c *Configuration) ValidateKeyShare(keyShare *keys.KeyShare) error {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return err
		}
	}

	if keyShare == nil {
		return errKeyShareNil
	}

	if err := c.ValidatePublicKeyShare(keyShare.PublicKeyShare()); err != nil {
		return err
	}

	if !c.VerificationKey.Equal(keyShare.VerificationKey()) {
		return errKeyShareNotMatch
	}

	secret := keyShare.SecretKey()
	if secret == nil || secret.IsZero() {
		return errInvalidSecretKey
	}

	publicKey := keyShare.PublicKey()
	if !c.group.Base().Multiply(secret).Equal(publicKey) {
		return errInvalidKeyShare
	}

	pk := c.getSignerPubKey(keyShare.Identifier())
	if pk == nil {
		return errInvalidKeyShareUnknownID
	}

	if !pk.Equal(publicKey) {
		return errPublicKeyShareNoMatch
	}

	return nil
}

func (c *Configuration) verifySignerPublicKeyShares() error {
	length := len(c.SignerPublicKeyShares)
	if length < int(c.Threshold) || length > int(c.MaxSigners) {
		return errInvalidNumberOfPublicKeys
	}

	// Sets to detect duplicates.
	pkSet := make(map[string]uint16, len(c.SignerPublicKeyShares))
	idSet := make(map[uint16]struct{}, len(c.SignerPublicKeyShares))

	for i, pks := range c.SignerPublicKeyShares {
		if pks == nil {
			return fmt.Errorf("empty public key share at index %d", i)
		}

		if err := c.ValidatePublicKeyShare(pks); err != nil {
			return err
		}

		// Verify whether the ID has duplicates
		id := pks.Identifier()
		if _, exists := idSet[id]; exists {
			return fmt.Errorf("found duplicate identifier for signer %d", id)
		}

		// Verify whether the public key has duplicates
		s := string(pks.PublicKey().Encode())
		if id2, exists := pkSet[s]; exists {
			return fmt.Errorf("found duplicate public keys for signers %d and %d", pks.Identifier(), id2)
		}

		pkSet[s] = id
		idSet[id] = struct{}{}
	}

	c.keysVerified = true

	return nil
}

func getOrder(g ecc.Group) *big.Int {
	bytes := g.Order()

	if g == ecc.Ristretto255Sha512 || g == ecc.Edwards25519Sha512 {
		slices.Reverse(bytes)
	}

	return big.NewInt(0).SetBytes(bytes)
}

func (c *Configuration) verifyConfiguration() error {
	if !c.Ciphersuite.Available() {
		return internal.ErrInvalidCiphersuite
	}

	g := ecc.Group(c.Ciphersuite)

	if c.Threshold == 0 || c.Threshold > c.MaxSigners {
		return errInvalidThresholdParameter
	}

	order := getOrder(g)
	maxSigners := new(big.Int).SetUint64(uint64(c.MaxSigners))

	// This is unlikely to happen, as the usual Group orders cannot be represented in a uint64.
	// Only a new, unregistered Group would make it fail here.
	if order.Cmp(maxSigners) != 1 {
		return errInvalidMaxSignersOrder
	}

	if err := c.validateGroupElement(c.VerificationKey); err != nil {
		return fmt.Errorf("invalid group public key, the key %w", err)
	}

	c.group = g
	c.verified = true

	return nil
}

func (c *Configuration) getSignerPubKey(id uint16) *ecc.Element {
	for _, pks := range c.SignerPublicKeyShares {
		if pks.Identifier() == id {
			return pks.PublicKey()
		}
	}

	return nil
}

func (c *Configuration) validateIdentifier(id uint16) error {
	switch {
	case id == 0:
		return internal.ErrIdentifierIs0
	case id > c.MaxSigners:
		return fmt.Errorf("identifier %d is above authorized range [1:%d]", id, c.MaxSigners)
	}

	return nil
}

func (c *Configuration) validateGroupElement(e *ecc.Element) error {
	switch {
	case e == nil:
		return errors.New("is nil")
	case e.IsIdentity():
		return errors.New("is the identity element")
	case ecc.Group(c.Ciphersuite).Base().Equal(e):
		return errors.New("is the group generator (base element)")
	}

	return nil
}

func (c *Configuration) challenge(lambda *ecc.Scalar, message []byte, groupCommitment *ecc.Element) *ecc.Scalar {
	chall := SchnorrChallenge(c.group, message, groupCommitment, c.VerificationKey)
	return chall.Multiply(lambda)
}
