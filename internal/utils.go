// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides values, structures, and functions to operate FROST that are not part of the public API.
package internal

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"

	group "github.com/bytemare/crypto"
)

var (
	// ErrInvalidParameters indicates that wrong input has been provided.
	ErrInvalidParameters = errors.New("invalid parameters")

	// ErrInvalidCiphersuite indicates a non-supported ciphersuite is being used.
	ErrInvalidCiphersuite = errors.New("ciphersuite not available")

	// ErrInvalidParticipantBackup indicates the participant's encoded backup is not valid.
	ErrInvalidParticipantBackup = errors.New("invalid backup")
)

// Concatenate returns the concatenation of all bytes composing the input elements.
func Concatenate(input ...[]byte) []byte {
	if len(input) == 1 {
		if len(input[0]) == 0 {
			return nil
		}

		return input[0]
	}

	length := 0
	for _, in := range input {
		length += len(in)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
}

// RandomBytes returns length random bytes (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := cryptorand.Read(r); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}

// IntegerToScalar creates a group.Scalar given an int.
func IntegerToScalar(g group.Group, i int) *group.Scalar {
	s := g.NewScalar()
	if err := s.SetInt(big.NewInt(int64(i))); err != nil {
		panic(err)
	}

	return s
}
