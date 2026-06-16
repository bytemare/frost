// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"

	secretsharing "github.com/bytemare/secret-sharing"
)

// ErrJSONMissingField indicates a struct field is missing in the JSON encoding.
var ErrJSONMissingField = errors.New("missing JSON field in encoding")

// ComputeLambda derives the interpolating value for id in the polynomial made by the participant identifiers.
// This function is not public to protect its usage, as the following conditions MUST be met.
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
	// Value is the actual Lambda value.
	Value *ecc.Scalar `json:"value"`

	// Group is necessary so the Value scalar can reliably be decoded in the right group.
	Group ecc.Group `json:"group"`
}

type lambdaJSON struct {
	Value json.RawMessage `json:"value"`
	Group ecc.Group       `json:"group"`
}

// UnmarshalJSON decodes data into l, or returns an error.
func (l *Lambda) UnmarshalJSON(data []byte) error {
	wire := new(lambdaJSON)
	if err := json.Unmarshal(data, wire); err != nil {
		return fmt.Errorf("unmarshal lambda: %w", err)
	}

	if !wire.Group.Available() {
		return fmt.Errorf("unmarshalled lambda group %d not available", wire.Group)
	}

	if err := requireJSONField(wire.Value); err != nil {
		return fmt.Errorf("failed to decode Lambda: Value: %w", err)
	}

	v := wire.Group.NewScalar()
	if err := json.Unmarshal(wire.Value, v); err != nil {
		return fmt.Errorf("unmarshal lambda: %w", err)
	}

	l.Group = wire.Group
	l.Value = v

	return nil
}

func requireJSONField(raw json.RawMessage) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrJSONMissingField
	}

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
func (l LambdaRegistry) New(g ecc.Group, id uint16, participants []uint16) (*ecc.Scalar, error) {
	polynomial, err := secretsharing.NewPolynomialFromListFunc(g, participants, func(participant uint16) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(participant))
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create polynomial from the participant list: %w", err)
	}

	lambda := ComputeLambda(g, id, polynomial)
	l.Set(participants, lambda)

	return lambda, nil
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
// This function assumes that:
// - id is non-nil and != 0.
// - every scalar in participants is non-nil and != 0.
// - there are no duplicates in participants.
func (l LambdaRegistry) GetOrNew(g ecc.Group, id uint16, participants []uint16) (*ecc.Scalar, error) {
	lambda := l.Get(participants)
	if lambda == nil {
		return l.New(g, id, participants)
	}

	return lambda, nil
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
