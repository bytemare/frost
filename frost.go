// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/shamir"
	"github.com/bytemare/frost/internal/vss"
)

type Configuration struct {
	GroupPublicKey *group.Element
	ContextString  []byte
	Ciphersuite    internal.Ciphersuite
}

func DeriveGroupInfo(g group.Group, max int, coms vss.Commitment) (*group.Element, []*group.Element) {
	pk := coms[0]
	keys := make([]*group.Element, max)

	for i := 0; i < max; i++ {
		id := internal.IntegerToScalar(g, i)
		pki := vss.DerivePublicPoint(g, coms, id)
		keys[i] = pki
	}

	return pk, keys
}

func TrustedDealerKeygen(
	g group.Group,
	secret *group.Scalar,
	max, min int,
	coeffs ...*group.Scalar,
) ([]*shamir.Share, *group.Element, vss.Commitment) {
	if coeffs == nil {
		coeffs = make([]*group.Scalar, min-1)
		for i := 0; i < min-1; i++ {
			coeffs[i] = g.NewScalar().Random()
		}
	}

	privateKeyShares, coeffs := shamir.Shard(g, secret, coeffs, max, min)
	coms := vss.Commit(g, coeffs)

	return privateKeyShares, coms[0], coms
}
