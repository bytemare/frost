// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package debug provides tools for key generation and verification for debugging purposes. They might be helpful for
// setups and investigations, but are not recommended to be used with production data (e.g. centralized key generation
// or recovery reveals the group's secret key in one spot, which goes against the principle in a decentralized setup).
package debug

import (
	"fmt"

	"github.com/bytemare/ecc"
	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
)

// TrustedDealerKeygen uses Shamir and Verifiable Secret Sharing to create secret shares of an input group secret. If
// secret is not set, a new random secret will be generated.
// These shares should be distributed securely to relevant participants. Note that this is centralized and combines
// the shared secret at some point. To use a decentralized dealer-less key generation, use the github.com/bytemare/dkg
// package.
func TrustedDealerKeygen(
	c frost.Ciphersuite,
	secret *ecc.Scalar,
	threshold, maxSigners uint16,
	coeffs ...*ecc.Scalar,
) ([]*keys.KeyShare, *ecc.Element, []*ecc.Element) {
	g := ecc.Group(c)

	if secret == nil {
		// If no secret provided, generate a new random secret.
		g.NewScalar().Random()
	}

	privateKeyShares, poly, err := secretsharing.ShardReturnPolynomial(
		g,
		secret,
		threshold,
		maxSigners,
		coeffs...)
	if err != nil {
		panic(err)
	}

	coms := secretsharing.Commit(g, poly)

	shares := make([]*keys.KeyShare, maxSigners)
	for i, k := range privateKeyShares {
		shares[i] = &keys.KeyShare{
			Secret:          k.Secret,
			VerificationKey: coms[0],
			PublicKeyShare: keys.PublicKeyShare{
				PublicKey:     g.Base().Multiply(k.Secret),
				VssCommitment: coms,
				ID:            k.ID,
				Group:         g,
			},
		}
	}

	return shares, coms[0], coms
}

// RecoverGroupSecret returns the groups secret from at least t-among-n (t = threshold) participant key shares. This is
// not recommended, as combining all distributed secret shares can put the group secret at risk.
func RecoverGroupSecret(c frost.Ciphersuite, keyShares []*keys.KeyShare) (*ecc.Scalar, error) {
	if !c.Available() {
		return nil, internal.ErrInvalidCiphersuite
	}

	publicKeys := make([]keys.Share, len(keyShares))
	for i, v := range keyShares {
		publicKeys[i] = v
	}

	secret, err := secretsharing.CombineShares(publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct group secret: %w", err)
	}

	return secret, nil
}

// Sign returns a Schnorr signature over the message msg with the full secret signing key (as opposed to a key share).
// The optional random argument is the random k in Schnorr signatures. Setting it allows for reproducible signatures.
func Sign(c frost.Ciphersuite, msg []byte, key *ecc.Scalar, random ...*ecc.Scalar) (*frost.Signature, error) {
	g := c.Group()
	if g == 0 {
		return nil, internal.ErrInvalidCiphersuite
	}

	var k *ecc.Scalar

	if len(random) != 0 && random[0] != nil {
		k = random[0].Copy()
	} else {
		k = g.NewScalar().Random()
	}

	R := g.Base().Multiply(k)
	pk := g.Base().Multiply(key)
	challenge := frost.SchnorrChallenge(g, msg, R, pk)
	z := k.Add(challenge.Multiply(key))

	return &frost.Signature{
		Group: g,
		R:     R,
		Z:     z,
	}, nil
}

// RecoverPublicKeys returns the group public key as well those from all participants,
// if the identifiers are 1, 2, ..., maxSigners, given the VSS commitment vector.
func RecoverPublicKeys(
	c frost.Ciphersuite,
	maxSigners uint16,
	commitment []*ecc.Element,
) (*ecc.Element, []*ecc.Element, error) {
	if !c.Available() {
		return nil, nil, internal.ErrInvalidCiphersuite
	}

	g := ecc.Group(c)
	publicKeys := make([]*ecc.Element, maxSigners)

	for i := uint16(1); i <= maxSigners; i++ {
		pki, err := secretsharing.PubKeyForCommitment(g, i, commitment)
		if err != nil {
			return nil, nil, fmt.Errorf("can't recover public keys: %w", err)
		}

		publicKeys[i-1] = pki
	}

	return commitment[0], publicKeys, nil
}

// VerifyVSS allows verification of a participant's secret share given a VSS commitment to the secret polynomial.
func VerifyVSS(g ecc.Group, share *keys.KeyShare, commitment []*ecc.Element) bool {
	pk := g.Base().Multiply(share.SecretKey())
	return secretsharing.Verify(g, share.Identifier(), pk, commitment)
}
