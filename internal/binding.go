// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import group "github.com/bytemare/crypto"

// BindingFactor holds the binding factor scalar for the given identifier.
type BindingFactor struct {
	Identifier    *group.Scalar
	BindingFactor *group.Scalar
}

// BindingFactorList a list of BindingFactor.
type BindingFactorList []*BindingFactor

// BindingFactorForParticipant returns the binding factor for a given participant identifier in the list.
func (b BindingFactorList) BindingFactorForParticipant(id *group.Scalar) *group.Scalar {
	for _, bf := range b {
		if id.Equal(bf.Identifier) == 1 {
			return bf.BindingFactor
		}
	}

	panic("invalid participant")
}
