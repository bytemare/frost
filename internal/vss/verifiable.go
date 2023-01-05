// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package vss

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal/shamir"
)

type Commitment []*group.Element

func Commit(g group.Group, p shamir.Polynomial) Commitment {
	coms := make(Commitment, len(p))
	for i, coeff := range p {
		coms[i] = g.Base().Multiply(coeff)
	}

	return coms
}

func DerivePublicPoint(g group.Group, coms Commitment, i *group.Scalar) *group.Element {
	publicPoint := g.NewElement().Identity()
	one := g.NewScalar().One()

	j := g.NewScalar().Zero()
	for _, com := range coms {
		publicPoint.Add(com.Copy().Multiply(i.Copy().Pow(j)))
		j.Add(one)
	}

	return publicPoint
}

func Verify(g group.Group, share *shamir.Share, coms Commitment) bool {
	id := share.ID
	ski := g.Base().Multiply(share.SecretKey)
	prime := DerivePublicPoint(g, coms, id)

	return ski.Equal(prime) == 1
}
