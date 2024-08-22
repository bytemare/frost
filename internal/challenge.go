// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"fmt"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"
)

func computeLambda(g group.Group, participantList secretsharing.Polynomial, id uint64) (*group.Scalar, error) {
	l, err := participantList.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(id))
	if err != nil {
		return nil, fmt.Errorf("anomaly in participant identifiers: %w", err)
	}

	return l, nil
}

// ComputeChallengeFactor computes and returns the Schnorr challenge factor used in signing and verification.
func ComputeChallengeFactor(
	g group.Group,
	groupCommitment *group.Element,
	lambda *group.Scalar,
	id uint64,
	message []byte,
	participants []*group.Scalar,
	groupPublicKey *group.Element,
) (*group.Scalar, error) {
	// Compute the interpolating value
	if lambda == nil || lambda.IsZero() {
		l, err := computeLambda(g, participants, id)
		if err != nil {
			return nil, err
		}

		lambda = l
	}

	// Compute per message challenge
	chall := SchnorrChallenge(g, message, groupCommitment, groupPublicKey)

	return chall.Multiply(lambda), nil
}

// SchnorrChallenge computes the per-message SchnorrChallenge.
func SchnorrChallenge(g group.Group, msg []byte, r, pk *group.Element) *group.Scalar {
	return H2(g, Concatenate(r.Encode(), pk.Encode(), msg))
}
