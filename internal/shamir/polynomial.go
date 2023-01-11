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

// Polynomial over scalars, represented as a list of t+1 coefficients, where t is the threshold.
// The constant term is in the first position and the highest degree coefficient is in the last position.
type Polynomial []*group.Scalar

func verifyInterpolatingInput(x *group.Scalar, p Polynomial) {
	if x.IsZero() {
		panic(internal.ErrInvalidParameters)
	}

	if p.HasZero() {
		panic(internal.ErrInvalidParameters)
	}

	if !p.Has(x) {
		panic(internal.ErrInvalidParameters)
	}

	if p.HasDuplicates() {
		panic(internal.ErrInvalidParameters)
	}
}

// Has returns whether s is a coefficient of the polynomial.
func (p Polynomial) Has(s *group.Scalar) bool {
	for _, si := range p {
		if si.Equal(s) == 1 {
			return true
		}
	}

	return false
}

// HasZero returns whether one of the polynomials coefficients is 0.
func (p Polynomial) HasZero() bool {
	for _, xj := range p {
		if xj.IsZero() {
			return true
		}
	}

	return false
}

// HasDuplicates returns whether the polynomial has at least one coefficient that appears more than once.
func (p Polynomial) HasDuplicates() bool {
	visited := make(map[string]bool, len(p))

	for _, pi := range p {
		enc := string(pi.Encode())
		if visited[enc] {
			return true
		}

		visited[enc] = true
	}

	return false
}

// Evaluate evaluates the polynomial p at point x using Horner's method.
func (p Polynomial) Evaluate(g group.Group, x *group.Scalar) *group.Scalar {
	value := g.NewScalar().Zero()
	for i := len(p) - 1; i >= 0; i-- {
		value.Multiply(x)
		value.Add(p[i])
	}

	return value
}

// DeriveInterpolatingValue derives a value used for polynomial interpolation. xi, and none of the coefficients must be
// non-zer scalars.
func DeriveInterpolatingValue(g group.Group, xi *group.Scalar, coeffs Polynomial) *group.Scalar {
	verifyInterpolatingInput(xi, coeffs)

	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, coeff := range coeffs {
		if coeff.Equal(xi) == 1 {
			continue
		}

		numerator.Multiply(coeff)
		denominator.Multiply(coeff.Copy().Subtract(xi))
	}

	value := numerator.Multiply(denominator.Invert())

	return value
}

// PolynomialInterpolateConstant recovers the constant term of the interpolating polynomial defined by the set of
// key shares.
func PolynomialInterpolateConstant(g group.Group, points []*KeyShare) *group.Scalar {
	xCoords := make(Polynomial, 0, len(points))
	for _, p := range points {
		xCoords = append(xCoords, p.Identifier)
	}

	f0 := g.NewScalar().Zero()

	for _, p := range points {
		delta := p.SecretKey.Copy().Multiply(DeriveInterpolatingValue(g, p.Identifier, xCoords))
		f0.Add(delta)
	}

	return f0
}
