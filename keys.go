// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"fmt"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/dkg"
	secretsharing "github.com/bytemare/secret-sharing"
)

// KeyShare identifies the sharded key share for a given participant.
type KeyShare secretsharing.KeyShare

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint64 {
	return (*secretsharing.KeyShare)(k).Identifier()
}

// SecretKey returns the participant's secret share.
func (k *KeyShare) SecretKey() *group.Scalar {
	return (*secretsharing.KeyShare)(k).SecretKey()
}

// Public returns the public key share and identifier corresponding to the secret key share.
func (k *KeyShare) Public() *PublicKeyShare {
	return (*PublicKeyShare)(&k.PublicKeyShare)
}

// Encode serializes k into a compact byte string.
func (k *KeyShare) Encode() []byte {
	return (*secretsharing.KeyShare)(k).Encode()
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (k *KeyShare) Decode(data []byte) error {
	if err := (*secretsharing.KeyShare)(k).Decode(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// UnmarshalJSON decodes data into k, or returns an error.
func (k *KeyShare) UnmarshalJSON(data []byte) error {
	if err := (*secretsharing.KeyShare)(k).UnmarshalJSON(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// PublicKeyShare specifies the public key of a participant identified with ID.
type PublicKeyShare secretsharing.PublicKeyShare

// Verify returns whether the PublicKeyShare's public key is valid given its VSS commitment to the secret polynomial.
func (p *PublicKeyShare) Verify(commitments [][]*group.Element) bool {
	return dkg.VerifyPublicKey(dkg.Ciphersuite(p.Group), p.ID, p.PublicKey, commitments) == nil
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	return (*secretsharing.PublicKeyShare)(p).Encode()
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (p *PublicKeyShare) Decode(data []byte) error {
	if err := (*secretsharing.PublicKeyShare)(p).Decode(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// UnmarshalJSON decodes data into p, or returns an error.
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	if err := (*secretsharing.PublicKeyShare)(p).UnmarshalJSON(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
