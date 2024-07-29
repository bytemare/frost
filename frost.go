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
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

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
	default:
		return false
	}
}

// Group returns the elliptic curve group used in the ciphersuite.
func (c Ciphersuite) Group() group.Group {
	if !c.Available() {
		return 0
	}

	return group.Group(c)
}

// Participant returns a new participant of the protocol instantiated from the configuration an input.
func (c Ciphersuite) Participant(keyShare *KeyShare) *Participant {
	return &Participant{
		KeyShare:      keyShare,
		Lambda:        nil,
		Nonces:        make(map[uint64][2]*group.Scalar),
		HidingRandom:  nil,
		BindingRandom: nil,
		Configuration: *c.Configuration(),
	}
}

// Configuration holds long term configuration information.
type Configuration struct {
	internal.Ciphersuite
}

func makeConf(context string, h hash.Hash, g group.Group) *Configuration {
	return &Configuration{
		Ciphersuite: internal.Ciphersuite{
			ContextString: []byte(context),
			Hash:          h,
			Group:         g,
		},
	}
}

// Configuration returns a configuration created for the ciphersuite.
func (c Ciphersuite) Configuration() *Configuration {
	if !c.Available() {
		return nil
	}

	switch c {
	case Ed25519:
		return makeConf(ed25519ContextString, hash.SHA512, group.Edwards25519Sha512)
	case Ristretto255:
		return makeConf(ristretto255ContextString, hash.SHA512, group.Ristretto255Sha512)
	case P256:
		return makeConf(p256ContextString, hash.SHA256, group.P256Sha256)
	case Secp256k1:
		return makeConf(secp256k1ContextString, hash.SHA256, group.Secp256k1)
	default:
		return nil
	}
}
