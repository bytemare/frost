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
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost/internal"
)

const (
	// Default and recommended ciphersuite for FROST.
	Default = Ristretto255

	// Ristretto255 uses Ristretto255 and SHA-512. This ciphersuite is recommended.
	Ristretto255 = Ciphersuite(ecc.Ristretto255Sha512)

	// Ed448 uses Edwards448 and SHAKE256, producing Ed448-compliant signatures as specified in RFC8032.
	// ed448 = Ciphersuite(2).

	// P256 uses P-256 and SHA-256.
	P256 = Ciphersuite(ecc.P256Sha256)

	// P384 uses P-384 and SHA-384.
	P384 = Ciphersuite(ecc.P384Sha384)

	// P521 uses P-521 and SHA-512.
	P521 = Ciphersuite(ecc.P521Sha512)

	// Ed25519 uses Edwards25519 and SHA-512, producing Ed25519-compliant signatures as specified in RFC8032.
	Ed25519 = Ciphersuite(ecc.Edwards25519Sha512)

	// Secp256k1 uses Secp256k1 and SHA-256.
	Secp256k1 = Ciphersuite(ecc.Secp256k1Sha256)
)

// Ciphersuite identifies the group and hash function to use for FROST.
type Ciphersuite byte

// Available returns whether the selected ciphersuite is available.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ed25519, Ristretto255, P256, P384, P521, Secp256k1:
		return true
	default:
		return false
	}
}

// Group returns the elliptic curve group used in the ciphersuite.
func (c Ciphersuite) Group() ecc.Group {
	if !c.Available() {
		return 0
	}

	return ecc.Group(c)
}

// SchnorrChallenge computes the per-message SchnorrChallenge.
func SchnorrChallenge(g ecc.Group, msg []byte, r, pk *ecc.Element) *ecc.Scalar {
	return internal.H2(g, internal.Concatenate(r.Encode(), pk.Encode(), msg))
}

// VerifySignature returns whether the signature of the message is valid under publicKey.
func VerifySignature(c Ciphersuite, message []byte, signature *Signature, publicKey *ecc.Element) error {
	g := c.Group()
	if g == 0 {
		return internal.ErrInvalidCiphersuite
	}

	ch := SchnorrChallenge(g, message, signature.R, publicKey)
	r := signature.R.Copy().Add(publicKey.Copy().Multiply(ch))
	l := g.Base().Multiply(signature.Z)

	// Clear the cofactor for Edwards25519.
	if g == ecc.Edwards25519Sha512 {
		cofactor := ecc.Edwards25519Sha512.NewScalar().SetUInt64(8)
		l.Multiply(cofactor)
		r.Multiply(cofactor)
	}

	if !l.Equal(r) {
		return errInvalidSignature
	}

	return nil
}

// NewPublicKeyShare returns a PublicKeyShare from separately encoded key material. To deserialize a byte string
// produced by the PublicKeyShare.Encode() method, use the PublicKeyShare.Decode() method.
func NewPublicKeyShare(c Ciphersuite, id uint16, signerPublicKey []byte) (*keys.PublicKeyShare, error) {
	if !c.Available() {
		return nil, internal.ErrInvalidCiphersuite
	}

	if id == 0 {
		return nil, internal.ErrIdentifierIs0
	}

	g := c.Group()

	pk := g.NewElement()
	if err := pk.Decode(signerPublicKey); err != nil {
		return nil, fmt.Errorf("could not decode public share: %w", err)
	}

	ks, err := keys.NewPublicKeyShare(g, id, pk, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create public share: %w", err)
	}

	return ks, nil
}

// NewKeyShare returns a KeyShare from separately encoded key material. To deserialize a byte string produced by the
// KeyShare.Encode() method, use the KeyShare.Decode() method.
func NewKeyShare(
	c Ciphersuite,
	id uint16,
	secretShare, signerPublicKey, verificationKey []byte,
) (*keys.KeyShare, error) {
	pks, err := NewPublicKeyShare(c, id, signerPublicKey)
	if err != nil {
		return nil, err
	}

	g := c.Group()

	s := g.NewScalar()
	if err = s.Decode(secretShare); err != nil {
		return nil, fmt.Errorf("could not decode secret share: %w", err)
	}

	vpk := g.Base().Multiply(s)
	if !vpk.Equal(pks.PublicKey()) {
		return nil, errInvalidKeyShare
	}

	gpk := g.NewElement()
	if err = gpk.Decode(verificationKey); err != nil {
		return nil, fmt.Errorf("could not decode the group public key: %w", err)
	}

	ks, err := keys.NewKeyShare(g, id, s, gpk, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create key share: %w", err)
	}

	return ks, nil
}
