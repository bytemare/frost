// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package frost implements FROST, the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol.
package frost

import (
	"fmt"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
)

/*
- check RFC
- update description
	- more buzz
	- show supported ciphersuites
- Check for
	- FROST2-BTZ
	- FROST3 (ROAST): https://eprint.iacr.org/2022/550
		- wrapper increasing robustness and apparently reducing some calculations?
	- Chu
	- re-randomize keys: https://eprint.iacr.org/2024/436.pdf

*/

// Ciphersuite identifies the group and hash to use for FROST.
type Ciphersuite byte

const (
	// Ed25519 uses Edwards25519 and SHA-512, producing Ed25519-compliant signatures as specified in RFC8032.
	Ed25519 = Ciphersuite(group.Edwards25519Sha512)

	// Ristretto255 uses Ristretto255 and SHA-512.
	Ristretto255 = Ciphersuite(group.Ristretto255Sha512)

	// Ed448 uses Edwards448 and SHAKE256, producing Ed448-compliant signatures as specified in RFC8032.
	ed448 = Ciphersuite(2)

	// P256 uses P-256 and SHA-256.
	P256 = Ciphersuite(group.P256Sha256)

	// Secp256k1 uses Secp256k1 and SHA-256.
	Secp256k1 = Ciphersuite(group.Secp256k1)

	ed25519ContextString      = "FROST-ED25519-SHA512-v1"
	ristretto255ContextString = "FROST-RISTRETTO255-SHA512-v1"
	p256ContextString         = "FROST-P256-SHA256-v1"
	secp256k1ContextString    = "FROST-secp256k1-SHA256-v1"

	/*
		ed448ContextString        = "FROST-ED448-SHAKE256-v1"
	*/
)

// Available returns whether the selected ciphersuite is available.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ed25519, Ristretto255, P256, Secp256k1:
		return true
	case ed448:
		return false
	default:
		return false
	}
}

func makeConf(pk *group.Element, context string, h hash.Hash, g group.Group) *Configuration {
	return &Configuration{
		GroupPublicKey: pk,
		Ciphersuite: internal.Ciphersuite{
			ContextString: []byte(context),
			Hash:          h,
			Group:         g,
		},
	}
}

// Configuration returns a configuration created for the ciphersuite.
func (c Ciphersuite) Configuration(groupPublicKey ...*group.Element) *Configuration {
	//todo: pubkey as byte slice so that we can check it's a valid point in the group, must be non-nil
	if !c.Available() {
		return nil
	}

	var pk *group.Element
	if len(groupPublicKey) != 0 {
		pk = groupPublicKey[0]
	}

	switch c {
	case Ed25519:
		return makeConf(pk, ed25519ContextString, hash.SHA512, group.Edwards25519Sha512)
	case Ristretto255:
		return makeConf(pk, ristretto255ContextString, hash.SHA512, group.Ristretto255Sha512)
	case P256:
		return makeConf(pk, p256ContextString, hash.SHA256, group.P256Sha256)
	case Secp256k1:
		return makeConf(pk, secp256k1ContextString, hash.SHA256, group.Secp256k1)
	default:
		return nil
	}
}

// Configuration holds long term configuration information.
type Configuration struct {
	GroupPublicKey *group.Element
	Ciphersuite    internal.Ciphersuite
}

// RecoverGroupSecret returns the groups secret from at least t-among-n (t = threshold) participant key shares. This is
// not recommended, as combining all distributed secret shares can put the group secret at risk.
func (c Configuration) RecoverGroupSecret(keyShares []*KeyShare) (*group.Scalar, error) {
	keys := make([]secretsharing.KeyShare, len(keyShares))
	for i, v := range keyShares {
		keys[i] = secretsharing.KeyShare(v)
	}

	secret, err := secretsharing.Combine(c.Ciphersuite.Group, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct group secret: %w", err)
	}

	return secret, nil
}

// Participant returns a new participant of the protocol instantiated from the configuration an input.
func (c Configuration) Participant(keyShare *KeyShare) *Participant {
	return &Participant{
		KeyShare:      keyShare,
		Lambda:        nil,
		Nonce:         [2]*group.Scalar{},
		HidingRandom:  nil,
		BindingRandom: nil,
		Configuration: c,
	}
}

// DeriveGroupInfo returns the group public key as well those from all participants.
func DeriveGroupInfo(g group.Group, max int, coms secretsharing.Commitment) (*group.Element, []*group.Element) {
	pk := coms[0]
	keys := make([]*group.Element, max)

	for i := 1; i <= max; i++ {
		id := g.NewScalar().SetUInt64(uint64(i))
		pki := derivePublicPoint(g, coms, id)
		keys[i-1] = pki
	}

	return pk, keys
}

// TrustedDealerKeygen uses Shamir and Verifiable Secret Sharing to create secret shares of an input group secret.
// These shares should be distributed securely to relevant participants. Note that this is centralized and combines
// the shared secret at some point. To use a decentralized dealer-less key generation, use the github.com/bytemare/dkg
// package.
func TrustedDealerKeygen(
	g group.Group,
	secret *group.Scalar,
	max, min int,
	coeffs ...*group.Scalar,
) ([]*KeyShare, *group.Element, secretsharing.Commitment, error) {
	privateKeyShares, poly, err := secretsharing.ShardReturnPolynomial(g, secret, uint(min), uint(max), coeffs...)
	if err != nil {
		return nil, nil, nil, err
	}

	coms := secretsharing.Commit(g, poly)

	shares := make([]*KeyShare, max)
	for i, k := range privateKeyShares {
		shares[i] = &KeyShare{
			Secret:    k.Secret,
			PublicKey: g.Base().Multiply(k.Secret),
			ID:        k.ID,
		}
	}

	return shares, coms[0], coms, nil
}

func derivePublicPoint(g group.Group, coms secretsharing.Commitment, i *group.Scalar) *group.Element {
	publicPoint := g.NewElement().Identity()
	one := g.NewScalar().One()

	j := g.NewScalar().Zero()
	for _, com := range coms {
		publicPoint.Add(com.Copy().Multiply(i.Copy().Pow(j)))
		j.Add(one)
	}

	return publicPoint
}

// VerifyVSS allows verification of a participant's secret share given a VSS commitment to the secret polynomial.
func VerifyVSS(g group.Group, share secretsharing.KeyShare, coms secretsharing.Commitment) bool {
	pk := g.Base().Multiply(share.SecretKey())
	return secretsharing.Verify(g, share.Identifier(), pk, coms)
}
