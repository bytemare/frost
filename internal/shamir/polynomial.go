// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package shamir

import (
	"errors"

	group "github.com/bytemare/crypto"
)

type Polynomial []*group.Scalar

func verifyInterpolatingInput(x *group.Scalar, p Polynomial) {
	if x.IsZero() {
		panic(errors.New("invalid parameters"))
	}

	if p.hasZero() {
		panic(errors.New("invalid parameters"))
	}

	if !p.has(x) {
		panic(errors.New("invalid parameters"))
	}

	// todo: not sure if this is the right test
	if p.hasDuplicates() {
		panic(errors.New("invalid parameters"))
	}
}

func (p Polynomial) has(s *group.Scalar) bool {
	for _, si := range p {
		if si.Equal(s) == 1 {
			return true
		}
	}

	return false
}

func (p Polynomial) hasZero() bool {
	for _, xj := range p {
		if xj.IsZero() {
			return true
		}
	}

	return false
}

func (p Polynomial) hasDuplicates() bool {
	visited := make(map[string]bool, len(p))
	for _, pi := range p {
		enc := string(pi.Encode())
		if visited[enc] == true {
			return true
		}

		visited[enc] = true
	}

	return false
}

func (p Polynomial) reverse() Polynomial {
	for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}

	return p
}

func (p Polynomial) Evaluate(g group.Group, x *group.Scalar) *group.Scalar {
	value := g.NewScalar().Zero()
	for i := len(p) - 1; i >= 0; i-- {
		value.Multiply(x)
		value.Add(p[i])
	}

	return value
}

func DeriveInterpolatingValue(g group.Group, xi *group.Scalar, p Polynomial) *group.Scalar {
	verifyInterpolatingInput(xi, p)

	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, xj := range p {
		if xj.Equal(xi) == 1 {
			continue
		}

		numerator.Multiply(xj)
		denominator.Multiply(xj.Copy().Subtract(xi))
	}

	value := numerator.Multiply(denominator.Invert())

	return value
}

func PolynomialInterpolateConstant(g group.Group, points []*Share) *group.Scalar {
	xCoords := make(Polynomial, 0, len(points))
	for _, p := range points {
		xCoords = append(xCoords, p.ID)
	}

	f0 := g.NewScalar().Zero()
	for _, p := range points {
		delta := p.SecretKey.Copy().Multiply(DeriveInterpolatingValue(g, p.ID, xCoords))
		f0.Add(delta)
	}

	return f0
}
