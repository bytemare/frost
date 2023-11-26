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
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
)

// Aggregate allows the coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid, deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the participant from the set of allowed participants in future runs of FROST.
func (p *Participant) Aggregate(
	list internal.CommitmentList,
	msg []byte,
	sigShares []*SignatureShare,
) *schnorr.Signature {
	if !list.IsSorted() {
		panic("list not sorted")
	}

	// Compute binding factors
	bindingFactorList := p.computeBindingFactors(list, msg)

	// Compute group commitment
	groupCommitment := p.computeGroupCommitment(list, bindingFactorList)

	// Compute aggregate signature
	z := p.Ciphersuite.Group.NewScalar()
	for _, share := range sigShares {
		z.Add(share.SignatureShare)
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
	commitment *internal.Commitment,
	pki *group.Element,
	sigShareI *group.Scalar,
	coms internal.CommitmentList,
	msg []byte,
) bool {
	if !coms.IsSorted() {
		panic("list not sorted")
	}

	// Compute Binding Factor(s)
	bindingFactorList := p.computeBindingFactors(coms, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(commitment.Identifier)

	// Compute Group Commitment
	groupCommitment := p.computeGroupCommitment(coms, bindingFactorList)

	// Commitment KeyShare
	commShare := commitment.HidingNonce.Copy().Add(commitment.BindingNonce.Copy().Multiply(bindingFactor))

	// Compute the challenge
	challenge := schnorr.Challenge(p.Ciphersuite, groupCommitment, p.Configuration.GroupPublicKey, msg)

	// Compute the interpolating value
	participantList := secretsharing.Polynomial(coms.Participants())

	lambdaI, err := participantList.DeriveInterpolatingValue(p.Ciphersuite.Group, commitment.Identifier)
	if err != nil {
		panic(err)
	}

	// Compute relation values
	l := p.Ciphersuite.Group.Base().Multiply(sigShareI)
	r := commShare.Add(pki.Multiply(challenge.Multiply(lambdaI)))

	return l.Equal(r) == 1
}
