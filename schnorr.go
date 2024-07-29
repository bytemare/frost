// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

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

// challenge computes the per-message challenge.
func challenge(cs internal.Ciphersuite, r, pk *group.Element, msg []byte) *group.Scalar {
	return cs.H2(internal.Concatenate(r.Encode(), pk.Encode(), msg))
}

func computeZ(r, challenge, key *group.Scalar) *group.Scalar {
	return r.Add(challenge.Multiply(key))
}

// Sign returns a Schnorr signature over the message msg with the full secret signing key (as opposed to a key share).
func (c Configuration) Sign(msg []byte, key *group.Scalar) *Signature {
	g := c.Ciphersuite.Group
	r := g.NewScalar().Random()
	R := g.Base().Multiply(r)
	pk := g.Base().Multiply(key)
	ch := challenge(c.Ciphersuite, R, pk, msg)
	z := computeZ(r, ch, key)

	return &Signature{
		R: R,
		Z: z,
	}
}

// VerifySignature returns whether the signature of the message msg is valid under the public key pk.
func (c Configuration) VerifySignature(msg []byte, signature *Signature, publicKey *group.Element) bool {
	ch := challenge(c.Ciphersuite, signature.R, publicKey, msg)
	l := c.Ciphersuite.Group.Base().Multiply(signature.Z)
	r := signature.R.Add(publicKey.Copy().Multiply(ch))

	if c.Ciphersuite.Group == group.Edwards25519Sha512 {
		cofactor := group.Edwards25519Sha512.NewScalar().SetUInt64(8)
		return l.Multiply(cofactor).Equal(r.Multiply(cofactor)) == 1
	}

	return l.Equal(r) == 1
}
