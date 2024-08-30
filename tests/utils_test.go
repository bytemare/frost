// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			err = fmt.Errorf("%v", report)
		}
	}()

	f()

	return has, err
}

// testPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, testPanic returns an error.
func testPanic(s string, expectedError error, f func()) error {
	hasPanic, err := hasPanic(f)

	// if there was no panic
	if !hasPanic {
		return errNoPanic
	}

	// panic, and we don't expect a particular message
	if expectedError == nil {
		return nil
	}

	// panic, but the panic value is empty
	if err == nil {
		return errNoPanicMessage
	}

	// panic, but the panic value is not what we expected
	if err.Error() != expectedError.Error() {
		return fmt.Errorf("expected panic on %s with message %q, got %q", s, expectedError, err)
	}

	return nil
}

func badScalar(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ScalarLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func badElement(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ElementLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func expectError(expectedError error, f func() error) error {
	if err := f(); err == nil || err.Error() != expectedError.Error() {
		return fmt.Errorf("expected %q, got %q", expectedError, err)
	}

	return nil
}

func expectErrorPrefix(expectedErrorMessagePrefix string, f func() error) error {
	if err := f(); err == nil || !strings.HasPrefix(err.Error(), expectedErrorMessagePrefix) {
		return fmt.Errorf("expected error prefix %q, got %q", expectedErrorMessagePrefix, err)
	}

	return nil
}

func TestConcatenate(t *testing.T) {
	inputs := [][]byte{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}

	var nilSlice []byte

	// nil
	if !bytes.Equal(internal.Concatenate(), slices.Concat(nilSlice)) {
		t.Fatal("expected equality")
	}

	// empty
	if !bytes.Equal(internal.Concatenate([]byte{}), slices.Concat([]byte{})) {
		t.Fatal("expected equality")
	}

	// using single input
	if !bytes.Equal(internal.Concatenate(inputs[0]), slices.Concat(internal.Concatenate(inputs[0]))) {
		t.Fatal("expected equality")
	}

	// using multiple input
	if !bytes.Equal(internal.Concatenate(inputs...), slices.Concat(internal.Concatenate(inputs...))) {
		t.Fatal("expected equality")
	}
}
