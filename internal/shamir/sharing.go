// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package shamir provides Shamir Secret Sharing operations.
package shamir

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

// KeyShare identifies the sharded key share for a given participant.
type KeyShare struct {
	Identifier *group.Scalar
	SecretKey  *group.Scalar
}

// Shard splits a secret into shares, and returns them as well as the polynomial's coefficients prepended by the secret.
func Shard(g group.Group, secret *group.Scalar, coeffs Polynomial, max, min int) ([]*KeyShare, Polynomial) {
	if min > max {
		panic(nil)
	}

	if min < 2 {
		panic(nil)
	}

	// Prepend the secret to the coefficients
	coeffs = append([]*group.Scalar{secret}, coeffs...)

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*KeyShare, max)

	for i := 1; i <= max; i++ {
		xi := internal.IntegerToScalar(g, i)
		yi := coeffs.Evaluate(g, xi)
		secretKeyShares[i-1] = &KeyShare{xi, yi}
	}

	return secretKeyShares, coeffs
}

// Combine recovers the constant secret by combining the key shares.
func Combine(g group.Group, shares []*KeyShare, min int) *group.Scalar {
	if len(shares) < min {
		panic("invalid parameters")
	}

	return PolynomialInterpolateConstant(g, shares)
}
