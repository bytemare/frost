// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides values, structures, and functions to operate FROST that are not part of the public API.
package internal

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
)

// Concatenate returns the concatenation of all bytes composing the input elements.
func Concatenate(input ...[]byte) []byte {
	if len(input) == 0 {
		return []byte{}
	}

	if len(input) == 1 {
		if len(input[0]) == 0 {
			return nil
		}

		// shallow clone
		return append(input[0][:0:0], input[0]...)
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

// UInt64LE returns the 8 byte little endian byte encoding of i.
func UInt64LE(i uint64) []byte {
	out := [8]byte{}
	binary.LittleEndian.PutUint64(out[:], i)

	return out[:]
}
