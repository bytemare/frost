// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
	"github.com/bytemare/frost/internal/shamir"
)

func (p *Participant) Aggregate(
	list internal.CommitmentList,
	msg []byte,
	sigShares []*group.Scalar,
) *schnorr.Signature {
	// Compute binding factors
	bindingFactorList := list.ComputeBindingFactors(p.Ciphersuite, msg)

	// Compute group commitment
	groupCommitment := list.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Compute aggregate signature
	z := p.Ciphersuite.Group.NewScalar().Zero()
	for _, zi := range sigShares {
		z.Add(zi)
	}

	return &schnorr.Signature{
		R: groupCommitment,
		Z: z,
	}
}

func (p *Participant) VerifySignatureShare(
	id *group.Scalar,
	pki *group.Element,
	commi [2]*group.Element,
	sigShareI *group.Scalar,
	coms internal.CommitmentList,
	msg []byte,
) bool {
	// Compute Binding Factor(s)
	bindingFactorList := coms.ComputeBindingFactors(p.Ciphersuite, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(id)

	// Compute Group Commitment
	groupCommitment := coms.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Commitment Share
	commShare := commi[0].Copy().Add(commi[1].Copy().Multiply(bindingFactor))

	// Compute the challenge
	challenge := schnorr.Challenge(p.Ciphersuite, groupCommitment, p.Configuration.GroupPublicKey, msg)

	// Compute the interpolating value
	participantList := coms.Participants()
	lambdaI := shamir.DeriveInterpolatingValue(p.Ciphersuite.Group, id, participantList)

	// Compute relation values
	l := p.Ciphersuite.Group.Base().Multiply(sigShareI)
	r := commShare.Add(pki.Multiply(challenge.Multiply(lambdaI)))

	return l.Equal(r) == 1
}
