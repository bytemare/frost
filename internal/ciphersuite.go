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

// Ciphersuite combines the group and hashing routines.
type Ciphersuite struct {
	ContextString []byte
	Hash          hash.Hashing
	Group         group.Group
}

func (c Ciphersuite) h1Ed25519(input []byte) *group.Scalar {
	h := c.Hash.Hash(input)

	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(h); err != nil {
		panic(err)
	}

	s2 := c.Group.NewScalar()
	if err := s2.Decode(s.Bytes()); err != nil {
		panic(err)
	}

	return s2
}

func (c Ciphersuite) hx(input, dst []byte) *group.Scalar {
	var sc *group.Scalar

	switch c.Group {
	case group.Edwards25519Sha512:
		sc = c.h1Ed25519(Concatenate(c.ContextString, dst, input))
	case group.Ristretto255Sha512:
		h := c.Hash.Hash(c.ContextString, dst, input)
		s := ristretto255.NewScalar().FromUniformBytes(h)

		sc = c.Group.NewScalar()
		if err := sc.Decode(s.Encode(nil)); err != nil {
			panic(err)
		}
	case group.P256Sha256, group.Secp256k1:
		sc = c.Group.HashToScalar(input, append(c.ContextString, dst...))
	default:
		panic(ErrInvalidParameters)
	}

	return sc
}

// H1 hashes the input and proves the "rho" DST.
func (c Ciphersuite) H1(input []byte) *group.Scalar {
	return c.hx(input, []byte("rho"))
}

// H2 hashes the input and proves the "chal" DST.
func (c Ciphersuite) H2(input []byte) *group.Scalar {
	if c.Group == group.Edwards25519Sha512 {
		// For compatibility with RFC8032 H2 doesn't use a domain separator.
		return c.h1Ed25519(input)
	}

	return c.hx(input, []byte("chal"))
}

// H3 hashes the input and proves the "nonce" DST.
func (c Ciphersuite) H3(input []byte) *group.Scalar {
	return c.hx(input, []byte("nonce"))
}

// H4 hashes the input and proves the "msg" DST.
func (c Ciphersuite) H4(msg []byte) []byte {
	return c.Hash.Hash(c.ContextString, []byte("msg"), msg)
}

// H5 hashes the input and proves the "com" DST.
func (c Ciphersuite) H5(msg []byte) []byte {
	return c.Hash.Hash(c.ContextString, []byte("com"), msg)
}

// HDKG hashes the input to the "dkg" DST.
func (c Ciphersuite) HDKG(msg []byte) *group.Scalar {
	return c.hx(msg, []byte("dkg"))
}
