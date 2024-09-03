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

// Lambda derives the interpolating value for id in the polynomial made by the participant identifiers.
// This function assumes that:
// - id is non-nil and != 0.
// - every scalar in participants is non-nil and != 0.
// - there are no duplicates in participants.
func Lambda(g group.Group, id uint64, participants []*group.Scalar) *group.Scalar {
	sid := g.NewScalar().SetUInt64(id)
	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, participant := range participants {
		if participant.Equal(sid) == 1 {
			continue
		}

		numerator.Multiply(participant)
		denominator.Multiply(participant.Copy().Subtract(sid))
	}

	return numerator.Multiply(denominator.Invert())
}

// LambdaRegistry holds a signers pre-computed lambda values, indexed by the list of participants they are associated
// to. A sorted set of participants will yield the same lambda.
type LambdaRegistry map[string]*group.Scalar

const lambdaRegistryKeyDomainSeparator = "FROST-participants"

func lambdaRegistryKey(participants []uint64) string {
	a := fmt.Sprint(lambdaRegistryKeyDomainSeparator, participants)
	return hex.EncodeToString(hash.SHA256.Hash([]byte(a))) // Length = 32 bytes, 64 in hex string
}

// New creates a new lambda and for the participant list for the participant id, and registers it.
// This function assumes that:
// - id is non-nil and != 0.
// - every participant id is != 0.
// - there are no duplicates in participants.
func (l LambdaRegistry) New(g group.Group, id uint64, participants []uint64) *group.Scalar {
	polynomial := secretsharing.NewPolynomialFromListFunc(g, participants, func(p uint64) *group.Scalar {
		return g.NewScalar().SetUInt64(p)
	})
	lambda := Lambda(g, id, polynomial)
	l.Set(participants, lambda)

	return lambda
}

// Get returns the recorded lambda for the list of participants, or nil if it wasn't found.
func (l LambdaRegistry) Get(participants []uint64) *group.Scalar {
	key := lambdaRegistryKey(participants)
	return l[key]
}

// GetOrNew returns the recorded lambda for the list of participants, or created, records, and returns a new one if
// it wasn't found.
func (l LambdaRegistry) GetOrNew(g group.Group, id uint64, participants []uint64) *group.Scalar {
	lambda := l.Get(participants)
	if lambda == nil {
		return l.New(g, id, participants)
	}

	return lambda
}

// Set records lambda for the given set of participants.
func (l LambdaRegistry) Set(participants []uint64, lambda *group.Scalar) {
	key := lambdaRegistryKey(participants)
	l[key] = lambda
}

// Delete deletes the lambda for the given set of participants.
func (l LambdaRegistry) Delete(participants []uint64) {
	key := lambdaRegistryKey(participants)
	l[key].Zero()
	delete(l, key)
}

// Decode populates the receiver from the byte encoded serialization in data.
func (l LambdaRegistry) Decode(g group.Group, data []byte) error {
	offset := 0
	for offset < len(data) {
		key := data[offset : offset+32]
		offset += 32

		lambda := g.NewScalar()
		if err := lambda.Decode(data[offset : offset+g.ScalarLength()]); err != nil {
			return fmt.Errorf("failed to decode lambda: %w", err)
		}

		l[hex.EncodeToString(key)] = lambda
		offset += g.ScalarLength()
	}

	return nil
}
