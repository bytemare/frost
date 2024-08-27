// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"encoding/hex"
	"fmt"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"
)

func Lambda(g group.Group, id uint64, polynomial secretsharing.Polynomial) (*group.Scalar, error) {
	l, err := polynomial.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(id))
	if err != nil {
		return nil, fmt.Errorf("anomaly in participant identifiers: %w", err)
	}

	return l, nil
}

type LambdaRegistry map[string]*group.Scalar

const lambdaRegistryKeyDomainSeparator = "FROST-participants"

func lambdaRegistryKey(participants []uint64) string {
	a := fmt.Sprint(lambdaRegistryKeyDomainSeparator, participants)
	return hex.EncodeToString(hash.SHA256.Hash([]byte(a))) // Length = 32 bytes, 64 in hex string
}

func (l LambdaRegistry) Get(g group.Group, id uint64, participants []uint64) (*group.Scalar, error) {
	key := lambdaRegistryKey(participants)

	lambda, registered := l[key]
	if !registered {
		polynomial := secretsharing.NewPolynomialFromListFunc(g, participants, func(p uint64) *group.Scalar {
			return g.NewScalar().SetUInt64(p)
		})

		var err error
		lambda, err = Lambda(g, id, polynomial)
		if err != nil {
			return nil, err
		}

		l.Set(participants, lambda)
	}

	return lambda, nil
}

func (l LambdaRegistry) Set(participants []uint64, lambda *group.Scalar) {
	key := lambdaRegistryKey(participants)
	l[key] = lambda
}

func (l LambdaRegistry) Delete(participants []uint64) {
	key := lambdaRegistryKey(participants)
	l[key].Zero()
	delete(l, key)
}
