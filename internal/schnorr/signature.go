// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package schnorr provides Schnorr signature operations.
package schnorr

import (
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

// Signature represent a Schnorr signature.
type Signature struct {
	R *group.Element
	Z *group.Scalar
}

// Encode serializes the signature into a byte string.
func (s *Signature) Encode() []byte {
	return append(s.R.Encode(), s.Z.Encode()...)
}

// Decode attempts to deserialize the encoded input into the signature in the group.
func (s *Signature) Decode(g group.Group, encoded []byte) error {
	eLen := g.ElementLength()
	sLen := g.ScalarLength()

	if len(encoded) != eLen+sLen {
		return internal.ErrInvalidParameters
	}

	if err := s.R.Decode(encoded[:eLen]); err != nil {
		return fmt.Errorf("invalid signature - decoding R: %w", err)
	}

	if err := s.Z.Decode(encoded[eLen:]); err != nil {
		return fmt.Errorf("invalid signature - decoding Z: %w", err)
	}

	return nil
}

// Challenge computes the per-message challenge.
func Challenge(cs internal.Ciphersuite, r, pk *group.Element, msg []byte) *group.Scalar {
	commEnc := r.Encode()
	pkEnc := pk.Encode()
	challengeInput := internal.Concatenate(commEnc, pkEnc, msg)

	return cs.H2(challengeInput)
}

// Sign returns the signature of message ms with the private key s.
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

// Verify returns whether the signature of the message msg is valid under the public key pk.
func Verify(cs internal.Ciphersuite, msg []byte, signature *Signature, pk *group.Element) bool {
	c := Challenge(cs, signature.R, pk, msg)
	l := cs.Group.Base().Multiply(signature.Z)
	r := signature.R.Add(pk.Copy().Multiply(c))

	return l.Equal(r) == 1
}
