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
	"encoding/json"
	"fmt"

	"github.com/bytemare/ecc"
	eccEncoding "github.com/bytemare/ecc/encoding"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"
)

// ComputeLambda derives the interpolating value for id in the polynomial made by the participant identifiers.
// This function assumes that:
// - id is non-nil and != 0.
// - every scalar in participants is non-nil and != 0.
// - there are no duplicates in participants.
func ComputeLambda(g ecc.Group, id uint16, participants []*ecc.Scalar) *ecc.Scalar {
	sid := g.NewScalar().SetUInt64(uint64(id))
	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, participant := range participants {
		if participant.Equal(sid) {
			continue
		}

		numerator.Multiply(participant)
		denominator.Multiply(participant.Copy().Subtract(sid))
	}

	return numerator.Multiply(denominator.Invert())
}

// A Lambda is the interpolating value for a given id in the polynomial made by the participant identifiers.
type Lambda struct {
	Value *ecc.Scalar `json:"value"`
	Group ecc.Group   `json:"group"`
}

type lambdaShadow Lambda

// UnmarshalJSON decodes data into l, or returns an error.
func (l *Lambda) UnmarshalJSON(data []byte) error {
	shadow := new(lambdaShadow)

	g, err := eccEncoding.JSONReGetGroup(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode Lambda: %w", err)
	}

	shadow.Group = g
	shadow.Value = g.NewScalar()

	if err = json.Unmarshal(data, shadow); err != nil {
		return fmt.Errorf("failed to decode Lambda: %w", err)
	}

	*l = Lambda(*shadow)

	return nil
}

// LambdaRegistry holds a signers pre-computed Lambda values, indexed by the list of participants they are associated
// to. A sorted set of participants will yield the same Lambda.
type LambdaRegistry map[string]*Lambda

const lambdaRegistryKeyDomainSeparator = "FROST-participants"

func lambdaRegistryKey(participants []uint16) string {
	a := fmt.Sprint(lambdaRegistryKeyDomainSeparator, participants)
	return hex.EncodeToString(hash.SHA256.Hash([]byte(a))) // Length = 32 bytes, 64 in hex string
}

// New creates a new Lambda and for the participant list for the participant id, and registers it.
// This function assumes that:
// - id is non-nil and != 0.
// - every participant id is != 0.
// - there are no duplicates in participants.
func (l LambdaRegistry) New(g ecc.Group, id uint16, participants []uint16) *ecc.Scalar {
	polynomial := secretsharing.NewPolynomialFromListFunc(g, participants, func(p uint16) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(p))
	})
	lambda := ComputeLambda(g, id, polynomial)
	l.Set(participants, lambda)

	return lambda
}

// Get returns the recorded Lambda for the list of participants, or nil if it wasn't found.
func (l LambdaRegistry) Get(participants []uint16) *ecc.Scalar {
	key := lambdaRegistryKey(participants)

	v := l[key]
	if v == nil {
		return nil
	}

	return v.Value
}

// GetOrNew returns the recorded Lambda for the list of participants, or created, records, and returns a new one if
// it wasn't found.
func (l LambdaRegistry) GetOrNew(g ecc.Group, id uint16, participants []uint16) *ecc.Scalar {
	lambda := l.Get(participants)
	if lambda == nil {
		return l.New(g, id, participants)
	}

	return lambda
}

// Set records Lambda for the given set of participants.
func (l LambdaRegistry) Set(participants []uint16, value *ecc.Scalar) {
	key := lambdaRegistryKey(participants)
	l[key] = &Lambda{
		Group: value.Group(),
		Value: value,
	}
}

// Delete deletes the Lambda for the given set of participants.
func (l LambdaRegistry) Delete(participants []uint16) {
	key := lambdaRegistryKey(participants)
	l[key].Value.Zero()
	delete(l, key)
}

// Decode populates the receiver from the byte encoded serialization in data.
func (l LambdaRegistry) Decode(g ecc.Group, data []byte) error {
	offset := 0
	for offset < len(data) {
		key := data[offset : offset+32]
		offset += 32

		value := g.NewScalar()
		if err := value.Decode(data[offset : offset+g.ScalarLength()]); err != nil {
			return fmt.Errorf("failed to decode Lambda: %w", err)
		}

		l[hex.EncodeToString(key)] = &Lambda{
			Group: g,
			Value: value,
		}
		offset += g.ScalarLength()
	}

	return nil
}
