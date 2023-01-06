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

type Ciphersuite struct {
	Group group.Group
	Hash  hash.Hashing
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
	}

	return hash2curve.HashToFieldXMD(c.Hash.GetCryptoID(), input, append(context, dst...), 1, 1, securityLenth, order)[0].Bytes()
}

func (c Ciphersuite) hx(input, context, dst []byte) *group.Scalar {
	var sc []byte

	switch c.Group {
	case group.Ristretto255Sha512:
		h := c.Hash.Hash(context, dst, input)
		sc = ristretto255.NewScalar().FromUniformBytes(h).Encode(nil)
	default: // NIST curves
		sc = c.hashToNist(input, context, dst)
	}

	s := c.Group.NewScalar()
	if err := s.Decode(sc); err != nil {
		panic(err)
	}

	return s
}

func (c Ciphersuite) H1(contextString, input []byte) *group.Scalar {
	return c.hx(input, contextString, []byte("rho"))
}

func (c Ciphersuite) H2(contextString, input []byte) *group.Scalar {
	return c.hx(input, contextString, []byte("chal"))
}

func (c Ciphersuite) H3(contextString, input []byte) *group.Scalar {
	return c.hx(input, contextString, []byte("nonce"))
}

func (c Ciphersuite) H4(contextString, msg []byte) []byte {
	return c.Hash.Hash(contextString, []byte("msg"), msg)
}

func (c Ciphersuite) H5(contextString, msg []byte) []byte {
	return c.Hash.Hash(contextString, []byte("com"), msg)
}
