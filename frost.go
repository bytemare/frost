// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package frost implements FROST, the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol.
package frost

import (
	"errors"
	"fmt"
	"math/big"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

/*
- check RFC
- update description
	- more buzz
	- show supported ciphersuites
- Check for
	- FROST2-CKM: https://eprint.iacr.org/2021/1375 (has duplicate checks)
	- FROST2-BTZ: https://eprint.iacr.org/2022/833
	- FROST3 (ROAST): https://eprint.iacr.org/2022/550 (most efficient variant of FROST)
		- wrapper increasing robustness and apparently reducing some calculations?
	- Chu: https://eprint.iacr.org/2023/899
	- re-randomize keys: https://eprint.iacr.org/2024/436.pdf

Requirements:
- group MUST be of prime order
- threshold <= max
- max < order
- identifier is in [1:max] and must be distinct form other ids
- each participant MUST know the group public key
- each participant MUST know the pub key of each other
- network channels must be authenticated (confidentiality is not required)
- Signers have local secret data
	- secret key is long term
	- committed nonces between commitment and signature

- When receiving the commitment list, each elements must be deserialized, and upon error, the signer MUST abort the
  protocol
- A signer must check whether their id and commitment appear in the commitment list

- A coordinator aggregates, and then should verify the signature. If signature fails, then check shares.

TODO:
- verify serialize and deserialize functions of messages, scalars, and elements

Notes:
- Frost is not robust, i.e.
	- if aggregated signature is not valid, SHOULD abort
	- misbehaving signers can DOS the protocol by providing wrong sig shares or not contributing
- Wrong shares can be identified, and with the authenticated channel associated with the signer, which can then be
denied of further contributions
- R255 is recommended
- the coordinator does not not have any secret or private information
- the coordinator is assumed to behave honestly
- the coordinator may further hedge against nonce reuse by tracking the nonce commitments used for a given group key
- for message pre-hashing, see RFC


*/

// Ciphersuite identifies the group and hash to use for FROST.
type Ciphersuite byte

const (
	// Ed25519 uses Edwards25519 and SHA-512, producing Ed25519-compliant signatures as specified in RFC8032.
	Ed25519 = Ciphersuite(group.Edwards25519Sha512)

	// Ristretto255 uses Ristretto255 and SHA-512.
	Ristretto255 = Ciphersuite(group.Ristretto255Sha512)

	// Ed448 uses Edwards448 and SHAKE256, producing Ed448-compliant signatures as specified in RFC8032.
	// ed448 = Ciphersuite(2).

	// P256 uses P-256 and SHA-256.
	P256 = Ciphersuite(group.P256Sha256)

	// P384 uses P-384 and SHA-384.
	P384 = Ciphersuite(group.P384Sha384)

	// P521 uses P-521 and SHA-512.
	P521 = Ciphersuite(group.P521Sha512)

	// Secp256k1 uses Secp256k1 and SHA-256.
	Secp256k1 = Ciphersuite(group.Secp256k1)
)

// Available returns whether the selected ciphersuite is available.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ed25519, Ristretto255, P256, P384, P521, Secp256k1:
		return true
	default:
		return false
	}
}

// ECGroup returns the elliptic curve group used in the ciphersuite.
func (c Ciphersuite) ECGroup() group.Group {
	if !c.Available() {
		return 0
	}

	return group.Group(c)
}

// Configuration holds the Configuration for a signing session.
type Configuration struct {
	GroupPublicKey        *group.Element
	SignerPublicKeyShares []*PublicKeyShare
	Threshold             uint64
	MaxSigners            uint64
	Ciphersuite           Ciphersuite
	group                 group.Group
	verified              bool
	keysVerified          bool
}

var (
	errInvalidThresholdParameter = errors.New("threshold is 0 or higher than maxSigners")
	errInvalidMaxSignersOrder    = errors.New("maxSigners is higher than group order")
	errInvalidNumberOfPublicKeys = errors.New("invalid number of public keys (lower than threshold or above maximum)")
)

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
func (c *Configuration) Signer(keyShare *KeyShare) (*Signer, error) {
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

func (c *Configuration) ValidatePublicKeyShare(pks *PublicKeyShare) error {
	if !c.verified {
		if err := c.verifyConfiguration(); err != nil {
			return err
		}
	}

	if pks == nil {
		return errors.New("public key share is nil")
	}

	if pks.Group != c.group {
		return fmt.Errorf("key share has invalid group parameter, want %s got %d", c.group, pks.Group)
	}

	if err := c.validateIdentifier(pks.ID); err != nil {
		return fmt.Errorf("invalid identifier for public key share, the %w", err)
	}

	if err := c.validateGroupElement(pks.PublicKey); err != nil {
		return fmt.Errorf("invalid public key for participant %d, the key %w", pks.ID, err)
	}

	return nil
}

func (c *Configuration) ValidateKeyShare(keyShare *KeyShare) error {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return err
		}
	}

	if keyShare == nil {
		return errors.New("provided key share is nil")
	}

	if err := c.ValidatePublicKeyShare(keyShare.Public()); err != nil {
		return err
	}

	if c.GroupPublicKey.Equal(keyShare.GroupPublicKey) != 1 {
		return errors.New(
			"the key share's group public key does not match the one in the configuration",
		)
	}

	if keyShare.Secret == nil || keyShare.Secret.IsZero() {
		return errors.New("provided key share has invalid secret key")
	}

	if c.group.Base().Multiply(keyShare.Secret).Equal(keyShare.PublicKey) != 1 {
		return errors.New("provided key share has non-matching secret and public keys")
	}

	pk := c.getSignerPubKey(keyShare.ID)
	if pk == nil {
		return errors.New("provided key share has no registered signer identifier in the configuration")
	}

	if pk.Equal(keyShare.PublicKey) != 1 {
		return errors.New(
			"provided key share has a different public key than " +
				"the one registered for that signer in the configuration",
		)
	}

	return nil
}

func (c *Configuration) verifySignerPublicKeyShares() error {
	length := uint64(len(c.SignerPublicKeyShares))
	if length < c.Threshold || length > c.MaxSigners {
		return errInvalidNumberOfPublicKeys
	}

	// Sets to detect duplicates.
	pkSet := make(map[string]uint64, len(c.SignerPublicKeyShares))
	idSet := make(map[uint64]struct{}, len(c.SignerPublicKeyShares))

	for i, pks := range c.SignerPublicKeyShares {
		if pks == nil {
			return fmt.Errorf("empty public key share at index %d", i)
		}

		if err := c.ValidatePublicKeyShare(pks); err != nil {
			return err
		}

		// Verify whether the ID has duplicates
		if _, exists := idSet[pks.ID]; exists {
			return fmt.Errorf("found duplicate identifier for signer %d", pks.ID)
		}

		// Verify whether the public key has duplicates
		s := string(pks.PublicKey.Encode())
		if id, exists := pkSet[s]; exists {
			return fmt.Errorf("found duplicate public keys for signers %d and %d", pks.ID, id)
		}

		pkSet[s] = pks.ID
		idSet[pks.ID] = struct{}{}
	}

	c.keysVerified = true

	return nil
}

func (c *Configuration) verifyConfiguration() error {
	if !c.Ciphersuite.Available() {
		return internal.ErrInvalidCiphersuite
	}

	g := group.Group(c.Ciphersuite)

	if c.Threshold == 0 || c.Threshold > c.MaxSigners {
		return errInvalidThresholdParameter
	}

	order, _ := new(big.Int).SetString(g.Order(), 0)
	if order == nil {
		panic("can't set group order number")
	}

	bigMax := new(big.Int).SetUint64(c.MaxSigners)
	if order.Cmp(bigMax) != 1 {
		// This is unlikely to happen, as the usual group orders cannot be represented in a uint64.
		// Only a new, unregistered group would make it fail here.
		return errInvalidMaxSignersOrder
	}

	if err := c.validateGroupElement(c.GroupPublicKey); err != nil {
		return fmt.Errorf("invalid group public key, the key %w", err)
	}

	c.group = g
	c.verified = true

	return nil
}

func (c *Configuration) getSignerPubKey(id uint64) *group.Element {
	for _, pks := range c.SignerPublicKeyShares {
		if pks.ID == id {
			return pks.PublicKey
		}
	}

	return nil
}

func (c *Configuration) validateIdentifier(id uint64) error {
	switch {
	case id == 0:
		return errors.New("identifier is 0")
	case id > c.MaxSigners:
		return fmt.Errorf("identifier %d is above authorized range [1:%d]", id, c.MaxSigners)
	}

	return nil
}

func (c *Configuration) validateGroupElement(e *group.Element) error {
	switch {
	case e == nil:
		return errors.New("is nil")
	case e.IsIdentity():
		return errors.New("is the identity element")
	case group.Group(c.Ciphersuite).Base().Equal(e) == 1:
		return errors.New("is the group generator (base element)")
	}

	return nil
}

func (c *Configuration) challenge(lambda *group.Scalar, message []byte, groupCommitment *group.Element) *group.Scalar {
	chall := SchnorrChallenge(c.group, message, groupCommitment, c.GroupPublicKey)
	return chall.Multiply(lambda)
}

// SchnorrChallenge computes the per-message SchnorrChallenge.
func SchnorrChallenge(g group.Group, msg []byte, r, pk *group.Element) *group.Scalar {
	return internal.H2(g, internal.Concatenate(r.Encode(), pk.Encode(), msg))
}

// VerifySignature returns whether the signature of the message is valid under publicKey.
func VerifySignature(c Ciphersuite, message []byte, signature *Signature, publicKey *group.Element) error {
	g := c.ECGroup()
	if g == 0 {
		return internal.ErrInvalidCiphersuite
	}

	ch := SchnorrChallenge(g, message, signature.R, publicKey)
	r := signature.R.Copy().Add(publicKey.Copy().Multiply(ch))
	l := g.Base().Multiply(signature.Z)

	// Clear the cofactor for Edwards25519.
	if g == group.Edwards25519Sha512 {
		cofactor := group.Edwards25519Sha512.NewScalar().SetUInt64(8)
		l.Multiply(cofactor)
		r.Multiply(cofactor)
	}

	if l.Equal(r) != 1 {
		return errInvalidSignature
	}

	return nil
}
