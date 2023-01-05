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
	"github.com/bytemare/frost/internal/vss"
)

type Participant struct {
	ParticipantInfo
	nonce      [2]*group.Scalar
	commitment [2]*group.Element
	Configuration
}

type ParticipantInfo struct {
	KeyShare *shamir.Share
	lambda   *group.Scalar // lamba can be computed once and reused across FROST signing operations
}

func (p *Participant) generateNonce(s *group.Scalar) *group.Scalar {
	random := internal.RandomBytes(32)
	enc := s.Encode()

	return p.Ciphersuite.H3(append(random, enc...))
}

func (p *Participant) Commit() ([2]*group.Scalar, [2]*group.Element) {
	hiding := p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey)
	binding := p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey)
	hidingCommit := p.Ciphersuite.Group.Base().Multiply(hiding)
	bindingCommit := p.Ciphersuite.Group.Base().Multiply(binding)

	p.nonce[0] = hiding
	p.nonce[1] = binding

	p.commitment[0] = hidingCommit
	p.commitment[1] = bindingCommit

	return p.nonce, p.commitment
}

func (p *Participant) Sign(msg []byte, list internal.CommitmentList) *group.Scalar {
	// Compute the binding factor(s)
	bindingFactorList := list.ComputeBindingFactors(p.Ciphersuite, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(p.KeyShare.ID)

	// Compute group commitment
	groupCommitment := list.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Compute the interpolating value
	participantList := list.Participants()
	lambdaID := shamir.DeriveInterpolatingValue(p.Ciphersuite.Group, p.KeyShare.ID, participantList)

	p.lambda = lambdaID.Copy()

	// Compute per message challenge
	challenge := schnorr.Challenge(p.Ciphersuite, groupCommitment, p.Configuration.GroupPublicKey, msg)

	// Compute the signature share
	sigShare := p.nonce[0].Add(
		p.nonce[1].Multiply(bindingFactor).Add(lambdaID.Multiply(p.KeyShare.SecretKey).Multiply(challenge)),
	)

	// Clean up values
	p.nonce[0].Zero()
	p.nonce[1].Zero()
	p.commitment[0].Identity()
	p.commitment[1].Identity()

	return sigShare
}

func (p *Participant) VerifyVSS(v vss.Commitment) bool {
	return vss.Verify(p.Ciphersuite.Group, p.KeyShare, v)
}
