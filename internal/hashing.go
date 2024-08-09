// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"filippo.io/edwards25519"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	"github.com/gtank/ristretto255"
)

const (
	ed25519ContextString      = "FROST-ED25519-SHA512-v1"
	ristretto255ContextString = "FROST-RISTRETTO255-SHA512-v1"
	ed448ContextString        = "FROST-ED448-SHAKE256-v1"
	p256ContextString         = "FROST-P256-SHA256-v1"
	p384ContextString         = "FROST-P384-SHA384-v1"
	p521ContextString         = "FROST-P521-SHA512-v1"
	secp256k1ContextString    = "FROST-secp256k1-SHA256-v1"
)

type ciphersuite struct {
	hash          hash.Hasher
	contextString []byte
}

var ciphersuites = [group.Secp256k1 + 1]ciphersuite{
	{
		hash:          hash.SHA512.New(),
		contextString: []byte(ristretto255ContextString),
	},
	{
		hash:          hash.SHAKE256.New(),
		contextString: []byte(ed448ContextString),
	},
	{
		hash:          hash.SHA256.New(),
		contextString: []byte(p256ContextString),
	},
	{
		hash:          hash.SHA384.New(),
		contextString: []byte(p384ContextString),
	},
	{
		hash:          hash.SHA512.New(),
		contextString: []byte(p521ContextString),
	},
	{
		hash:          hash.SHA512.New(),
		contextString: []byte(ed25519ContextString),
	},
	{
		hash:          hash.SHA256.New(),
		contextString: []byte(secp256k1ContextString),
	},
}

func h1Ed25519(hashed []byte) *group.Scalar {
	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(hashed); err != nil {
		panic(err)
	}

	s2 := group.Edwards25519Sha512.NewScalar()
	if err := s2.Decode(s.Bytes()); err != nil {
		panic(err)
	}

	return s2
}

func hx(g group.Group, input, dst []byte) *group.Scalar {
	var sc *group.Scalar
	c := ciphersuites[g-1]

	switch g {
	case group.Edwards25519Sha512:
		h := c.hash.Hash(0, c.contextString, dst, input)
		sc = h1Ed25519(h)
	case group.Ristretto255Sha512:
		h := c.hash.Hash(0, c.contextString, dst, input)
		s := ristretto255.NewScalar().FromUniformBytes(h)

		sc = g.NewScalar()
		if err := sc.Decode(s.Encode(nil)); err != nil {
			panic(err)
		}
	case group.P256Sha256, group.P384Sha384, group.P521Sha512, group.Secp256k1:
		sc = g.HashToScalar(input, append(c.contextString, dst...))
	default:
		panic(ErrInvalidParameters)
	}

	return sc
}

// H1 hashes the input and proves the "rho" DST.
func H1(g group.Group, input []byte) *group.Scalar {
	return hx(g, input, []byte("rho"))
}

// H2 hashes the input and proves the "chal" DST.
func H2(g group.Group, input []byte) *group.Scalar {
	if g == group.Edwards25519Sha512 {
		// For compatibility with RFC8032 H2 doesn't use a domain separator for Edwards25519.
		h := ciphersuites[group.Edwards25519Sha512-1].hash.Hash(0, input)
		return h1Ed25519(h)
	}

	return hx(g, input, []byte("chal"))
}

// H3 hashes the input and proves the "nonce" DST.
func H3(g group.Group, input []byte) *group.Scalar {
	return hx(g, input, []byte("nonce"))
}

// H4 hashes the input and proves the "msg" DST.
func H4(g group.Group, msg []byte) []byte {
	cs := ciphersuites[g-1]
	return cs.hash.Hash(0, cs.contextString, []byte("msg"), msg)
}

// H5 hashes the input and proves the "com" DST.
func H5(g group.Group, msg []byte) []byte {
	cs := ciphersuites[g-1]
	return cs.hash.Hash(0, cs.contextString, []byte("com"), msg)
}
