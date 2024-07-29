// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
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

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost"
)

// TrustedDealerKeygen uses Shamir and Verifiable Secret Sharing to create secret shares of an input group secret.
// These shares should be distributed securely to relevant participants. Note that this is centralized and combines
// the shared secret at some point. To use a decentralized dealer-less key generation, use the github.com/bytemare/dkg
// package.
func TrustedDealerKeygen(
	c frost.Ciphersuite,
	secret *group.Scalar,
	max, min int,
	coeffs ...*group.Scalar,
) ([]*frost.KeyShare, *group.Element, []*group.Element) {
	g := group.Group(c)

	if secret == nil {
		// If no secret provided, generated a new random secret.
		g.NewScalar().Random()
	}

	privateKeyShares, poly, err := secretsharing.ShardReturnPolynomial(g, secret, uint(min), uint(max), coeffs...)
	if err != nil {
		panic(err)
	}

	coms := secretsharing.Commit(g, poly)

	shares := make([]*frost.KeyShare, max)
	for i, k := range privateKeyShares {
		shares[i] = &frost.KeyShare{
			Secret:         k.Secret,
			GroupPublicKey: coms[0],
			PublicKeyShare: secretsharing.PublicKeyShare{
				PublicKey:  g.Base().Multiply(k.Secret),
				Commitment: coms,
				ID:         k.ID,
				Group:      g,
			},
		}
	}

	return shares, coms[0], coms
}

// RecoverGroupSecret returns the groups secret from at least t-among-n (t = threshold) participant key shares. This is
// not recommended, as combining all distributed secret shares can put the group secret at risk.
func RecoverGroupSecret(g group.Group, keyShares []*frost.KeyShare) (*group.Scalar, error) {
	keys := make([]secretsharing.Share, len(keyShares))
	for i, v := range keyShares {
		keys[i] = v
	}

	secret, err := secretsharing.CombineShares(g, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct group secret: %w", err)
	}

	return secret, nil
}

// RecoverPublicKeys returns the group public key as well those from all participants.
func RecoverPublicKeys(g group.Group, max int, commitment []*group.Element) (*group.Element, []*group.Element) {
	pk := commitment[0]
	keys := make([]*group.Element, max)

	for i := 1; i <= max; i++ {
		pki, err := secretsharing.PubKeyForCommitment(g, uint64(i), commitment)
		if err != nil {
			panic(err)
		}
		keys[i-1] = pki
	}

	return pk, keys
}

// VerifyVSS allows verification of a participant's secret share given a VSS commitment to the secret polynomial.
func VerifyVSS(g group.Group, share *frost.KeyShare, commitment []*group.Element) bool {
	pk := g.Base().Multiply(share.SecretKey())
	return secretsharing.Verify(g, share.Identifier(), pk, commitment)
}
