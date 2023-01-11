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

func (c Ciphersuite) hashToNist(input, context, dst []byte) []byte {
	order, _ := new(big.Int).SetString(c.Group.Order(), 10)
	var securityLenth int

	switch c.Group {
	case group.P256Sha256:
		securityLenth = 48
	case group.P384Sha384:
		securityLenth = 123
	case group.P521Sha512:
		securityLenth = 123
	default:
		panic(ErrInvalidCiphersuite)
	}

	return hash2curve.HashToFieldXMD(c.Hash.GetCryptoID(),
		input,
		append(context, dst...),
		1,
		1,
		securityLenth, order)[0].Bytes()
}

func (c Ciphersuite) hx(input, dst []byte) *group.Scalar {
	var sc []byte

	switch c.Group {
	case group.Ristretto255Sha512:
		h := c.Hash.Hash(c.ContextString, dst, input)
		sc = ristretto255.NewScalar().FromUniformBytes(h).Encode(nil)
	case group.P256Sha256: // NIST curves
		sc = c.hashToNist(input, c.ContextString, dst)
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
	return c.hx(input, []byte("rho"))
}

// H2 hashes the input and proves the "chal" DST.
func (c Ciphersuite) H2(input []byte) *group.Scalar {
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
