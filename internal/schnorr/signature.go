// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package schnorr

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

type Signature struct {
	R *group.Element
	Z *group.Scalar
}

func (s Signature) Encode() []byte {
	return append(s.R.Encode(), s.Z.Encode()...)
}

func Challenge(cs internal.Ciphersuite, r, pk *group.Element, msg []byte) *group.Scalar {
	commEnc := r.Encode()
	pkEnc := pk.Encode()
	challengeInput := internal.Concatenate(commEnc, pkEnc, msg)
	return cs.H2(challengeInput)
}

func Sign(cs internal.Ciphersuite, msg []byte, s *group.Scalar) *Signature {
	r := cs.Group.NewScalar().Random()
	R := cs.Group.Base().Multiply(r)
	pk := cs.Group.Base().Multiply(s)
	c := Challenge(cs, R, pk, msg)
	z := r.Add(c.Multiply(s))

	return &Signature{
		R: R,
		Z: z,
	}
}

func Verify(cs internal.Ciphersuite, msg []byte, signature *Signature, pk *group.Element) bool {
	c := Challenge(cs, signature.R, pk, msg)
	l := cs.Group.Base().Multiply(signature.Z)
	r := signature.R.Add(pk.Copy().Multiply(c))

	return l.Equal(r) == 1
}
