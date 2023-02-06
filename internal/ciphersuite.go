// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"math/big"

	"filippo.io/edwards25519"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	"github.com/bytemare/hash2curve"
	"github.com/gtank/ristretto255"
)

// Ciphersuite combines the group and hashing routines.
type Ciphersuite struct {
	ContextString []byte
	Hash          hash.Hashing
	Group         group.Group
}

// Ed25519ScalarFrom64Bytes reduces the input modulo the Ed25119 prime order, and returns a corresponding scalar.
func Ed25519ScalarFrom64Bytes(g group.Group, input []byte) *group.Scalar {
	var s *edwards25519.Scalar
	var err error

	if len(input) < 64 {
		wide := make([]byte, 64)
		copy(wide, input)
		input = wide
	}

	s, err = edwards25519.NewScalar().SetUniformBytes(input)
	if err != nil {
		panic(err)
	}

	scalar := g.NewScalar()
	if err := scalar.Decode(s.Bytes()); err != nil {
		panic(err)
	}

	return scalar
}

func (c Ciphersuite) hx(id byte, input, dst []byte) *group.Scalar {
	var sc []byte

	switch c.Group {
	case group.Edwards25519Sha512:
		var h []byte
		if id == 2 {
			h = c.Hash.Hash(input)
		} else {
			h = c.Hash.Hash(c.ContextString, dst, input)
		}

		return Ed25519ScalarFrom64Bytes(group.Edwards25519Sha512, h)
	case group.Ristretto255Sha512:
		h := c.Hash.Hash(c.ContextString, dst, input)
		sc = ristretto255.NewScalar().FromUniformBytes(h).Encode(nil)
	case group.P256Sha256: // NIST curves
		order, ok := new(big.Int).SetString(c.Group.Order(), 10)
		if !ok {
			panic(nil)
		}

		sc = hash2curve.HashToFieldXMD(c.Hash.GetCryptoID(),
			input,
			append(c.ContextString, dst...),
			1,
			1,
			48, order)[0].Bytes()

	default:
		panic(ErrInvalidParameters)
	}

	s := c.Group.NewScalar()
	if err := s.Decode(sc); err != nil {
		panic(err)
	}

	return s
}

// H1 hashes the input and proves the "rho" DST.
func (c Ciphersuite) H1(input []byte) *group.Scalar {
	return c.hx(1, input, []byte("rho"))
}

// H2 hashes the input and proves the "chal" DST.
func (c Ciphersuite) H2(input []byte) *group.Scalar {
	return c.hx(2, input, []byte("chal"))
}

// H3 hashes the input and proves the "nonce" DST.
func (c Ciphersuite) H3(input []byte) *group.Scalar {
	return c.hx(3, input, []byte("nonce"))
}

// H4 hashes the input and proves the "msg" DST.
func (c Ciphersuite) H4(msg []byte) []byte {
	return c.Hash.Hash(c.ContextString, []byte("msg"), msg)
}

// H5 hashes the input and proves the "com" DST.
func (c Ciphersuite) H5(msg []byte) []byte {
	return c.Hash.Hash(c.ContextString, []byte("com"), msg)
}
