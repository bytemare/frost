// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package frost implements FROST, the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol
package frost

import (
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
)

// Ciphersuite identifies the group and hash to use for FROST.
type Ciphersuite byte

const (
	// Ed25519 uses Edwards25519 and SHA-512, producing Ed25519-compliant signatures as specified in RFC8032.
	Ed25519 Ciphersuite = 1 + iota

	// Ristretto255 uses Ristretto255 and SHA-512.
	Ristretto255

	// Ed448 uses Edwards448 and SHAKE256, producing Ed448-compliant signatures as specified in RFC8032.
	ed448

	// P256 uses P-256 and SHA-256.
	P256

	// Secp256k1 uses Secp256k1 and SHA-256.
	Secp256k1

	ed25519ContextString      = "FROST-ED25519-SHA512-v11"
	ristretto255ContextString = "FROST-RISTRETTO255-SHA512-v11"
	p256ContextString         = "FROST-P256-SHA256-v11"
	secp256k1ContextString    = "FROST-secp256k1-SHA256-v11"

	/*

		ed448ContextString        = "FROST-ED448-SHAKE256-v11"
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

// Configuration returns a configuration created for the ciphersuite.
func (c Ciphersuite) Configuration() *Configuration {
	if !c.Available() {
		return nil
	}

	switch c {
	case Ed25519:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte(ed25519ContextString),
				Hash:          hash.SHA512,
				Group:         group.Edwards25519Sha512,
			},
		}
	case Ristretto255:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				Group:         group.Ristretto255Sha512,
				Hash:          hash.SHA512,
				ContextString: []byte(ristretto255ContextString),
			},
		}
	case P256:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				Group:         group.P256Sha256,
				Hash:          hash.SHA256,
				ContextString: []byte(p256ContextString),
			},
		}
	case Secp256k1:
		return &Configuration{
			GroupPublicKey: nil,
			Ciphersuite: internal.Ciphersuite{
				ContextString: []byte(secp256k1ContextString),
				Hash:          hash.SHA256,
				Group:         group.Secp256k1,
			},
		}
	case ed448:
		return nil
	default:
		return nil
	}
}

// Configuration holds long term configuration information.
type Configuration struct {
	GroupPublicKey *group.Element
	Ciphersuite    internal.Ciphersuite
}

// Participant returns a new participant of the protocol instantiated from the configuration an input.
func (c Configuration) Participant(id, keyShare *group.Scalar) *Participant {
	return &Participant{
		ParticipantInfo: ParticipantInfo{
			KeyShare: &secretsharing.KeyShare{
				Identifier: id,
				SecretKey:  keyShare,
			},
			Lambda: nil,
		},
		Nonce:         [2]*group.Scalar{},
		HidingRandom:  nil,
		BindingRandom: nil,
		Configuration: c,
	}
}

// Commitment is the tuple defining a commitment.
type Commitment []*group.Element

// DeriveGroupInfo returns the group public key as well those from all participants.
func DeriveGroupInfo(g group.Group, max int, coms secretsharing.Commitment) (*group.Element, Commitment) {
	pk := coms[0]
	keys := make(Commitment, max)

	for i := 0; i < max; i++ {
		id := internal.IntegerToScalar(g, i)
		pki := derivePublicPoint(g, coms, id)
		keys[i] = pki
	}

	return pk, keys
}

// TrustedDealerKeygen uses Shamir and Verifiable Secret Sharing to create secret shares of an input group secret.
// These shares should be distributed securely to relevant participants.
func TrustedDealerKeygen(
	g group.Group,
	secret *group.Scalar,
	max, min int,
	coeffs ...*group.Scalar,
) ([]*secretsharing.KeyShare, *group.Element, secretsharing.Commitment, error) {
	ss, err := secretsharing.New(g, uint(min)-1, coeffs...)
	if err != nil {
		return nil, nil, nil, err
	}

	privateKeyShares, coeffs, err := ss.Shard(secret, uint(max))
	if err != nil {
		return nil, nil, nil, err
	}

	coms := secretsharing.Commit(g, coeffs)

	return privateKeyShares, coms[0], coms, nil
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

// Verify allows verification of a participant's secret share given a VSS commitment to the secret polynomial.
func Verify(g group.Group, share *secretsharing.KeyShare, coms secretsharing.Commitment) bool {
	pk := g.Base().Multiply(share.SecretKey)
	return secretsharing.Verify(g, share.Identifier, pk, coms)
}
