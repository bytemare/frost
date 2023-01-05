// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import group "github.com/bytemare/crypto"

type BindingFactor struct {
	Identifier    *group.Scalar
	BindingFactor *group.Scalar
}

type BindingFactorList []*BindingFactor

func (b BindingFactorList) BindingFactorForParticipant(id *group.Scalar) *group.Scalar {
	for _, bf := range b {
		if id.Equal(bf.Identifier) == 1 {
			return bf.BindingFactor
		}
	}

	panic("invalid participant")
}
