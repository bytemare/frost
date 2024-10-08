// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import "errors"

var (
	// ErrInvalidParameters indicates that wrong input has been provided.
	ErrInvalidParameters = errors.New("invalid parameters")

	// ErrInvalidCiphersuite indicates a non-supported ciphersuite is being used.
	ErrInvalidCiphersuite = errors.New("ciphersuite not available")

	// ErrInvalidLength indicates that a provided encoded data piece is not of the expected length.
	ErrInvalidLength = errors.New("invalid encoding length")

	// ErrIdentifierIs0 is returned when the invalid 0 identifier is encountered.
	ErrIdentifierIs0 = errors.New("identifier is 0")

	// ErrEncodingInvalidJSONEncoding is returned when invalid JSON is detected.
	ErrEncodingInvalidJSONEncoding = errors.New("invalid JSON encoding")
)
