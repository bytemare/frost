// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package shamir

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

type Share struct {
	ID        *group.Scalar
	SecretKey *group.Scalar
}

func Shard(g group.Group, secret *group.Scalar, coeffs Polynomial, max, min int) ([]*Share, Polynomial) {
	if min > max {
		panic(nil)
	}
	if min < 2 {
		panic(nil)
	}

	// Prepend the secret to the coefficients
	coeffs = append([]*group.Scalar{secret}, coeffs...)

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*Share, max+1)
	for xi := 1; xi <= max+1; xi++ {
		x := internal.IntegerToScalar(g, xi)
		yi := coeffs.Evaluate(g, x)
		secretKeyShares[xi-1] = &Share{x, yi}
	}

	return secretKeyShares, coeffs
}

func Combine(g group.Group, shares []*Share, min int) *group.Scalar {
	if len(shares) < min {
		panic("invalid parameters")
	}

	return PolynomialInterpolateConstant(g, shares)
}
