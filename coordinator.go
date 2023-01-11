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

// Aggregate allows the coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the participant from the set of allowed participants in future runs of FROST.
func (p *Participant) Aggregate(
	list internal.CommitmentList,
	msg []byte,
	sigShares []*group.Scalar,
) *schnorr.Signature {
	if !list.IsSorted() {
		panic("list not sorted")
	}

	// Compute binding factors
	bindingFactorList, _ := list.ComputeBindingFactors(p.Ciphersuite, msg)

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

// VerifySignatureShare verifies a signature share.
// id, pki, commi, and sigShareI are, respectively, the identifier, public key, commitment, and signature share of
// the participant whose share is to be verified.
//
// The CommitmentList must be sorted in ascending order by identifier.
func (p *Participant) VerifySignatureShare(
	id *group.Scalar,
	pki *group.Element,
	commi [2]*group.Element,
	sigShareI *group.Scalar,
	coms internal.CommitmentList,
	msg []byte,
) bool {
	if !coms.IsSorted() {
		panic("list not sorted")
	}

	// Compute Binding Factor(s)
	bindingFactorList, _ := coms.ComputeBindingFactors(p.Ciphersuite, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(id)

	// Compute Group Commitment
	groupCommitment := coms.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Commitment KeyShare
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
