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
	"math/big"

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

	if len(encoded) != int(eLen+sLen) {
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
	return cs.H2(internal.Concatenate(r.Encode(), pk.Encode(), msg))
}

func computeZ(r, challenge, key *group.Scalar) *group.Scalar {
	return r.Add(challenge.Multiply(key))
}

// Sign returns a Schnorr signature over the message msg with the full secret signing key s (as opposed to a key share).
func Sign(cs internal.Ciphersuite, msg []byte, key *group.Scalar) *Signature {
	if cs.Group == group.Edwards25519Sha512 {
		return edSign(cs, msg, key)
	}

	r := cs.Group.NewScalar().Random()
	R := cs.Group.Base().Multiply(r)
	pk := cs.Group.Base().Multiply(key)
	challenge := Challenge(cs, R, pk, msg)

	z := computeZ(r, challenge, key)

	return &Signature{
		R: R,
		Z: z,
	}
}

// Verify returns whether the signature of the message msg is valid under the public key pk.
func Verify(cs internal.Ciphersuite, msg []byte, signature *Signature, pk *group.Element) bool {
	if cs.Group == group.Edwards25519Sha512 {
		return edVerify(cs, msg, signature, pk)
	}

	c := Challenge(cs, signature.R, pk, msg)
	l := cs.Group.Base().Multiply(signature.Z)
	r := signature.R.Add(pk.Copy().Multiply(c))

	return l.Equal(r) == 1
}

func bytesToKeys(g group.Group, input []byte) (*group.Scalar, *group.Element) {
	scalar := internal.Ed25519ScalarFrom64Bytes(g, input)
	return scalar, g.Base().Multiply(scalar)
}

func edSign(cs internal.Ciphersuite, msg []byte, key *group.Scalar) *Signature {
	h := cs.Hash.Hash(key.Encode())
	hLen := len(h) / 2
	_, A := bytesToKeys(cs.Group, h[:hLen])
	h = cs.Hash.Hash(h[hLen:], msg)
	r, R := bytesToKeys(cs.Group, h)
	h = cs.Hash.Hash(R.Encode(), A.Encode(), msg)
	k := internal.Ed25519ScalarFrom64Bytes(cs.Group, h)

	S := computeZ(r, k, key)

	return &Signature{
		R: R,
		Z: S,
	}
}

func edVerify(cs internal.Ciphersuite, msg []byte, signature *Signature, pk *group.Element) bool {
	k := Challenge(cs, signature.R, pk, msg)

	cofactor := cs.Group.NewScalar()
	if err := cofactor.SetInt(big.NewInt(8)); err != nil {
		panic(err)
	}

	left := cs.Group.Base().Multiply(signature.Z).Multiply(cofactor)
	right := signature.R.Copy().Multiply(cofactor).Add(pk.Copy().Multiply(k).Multiply(cofactor))

	return left.Equal(right) == 1
}
