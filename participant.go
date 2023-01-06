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
	Nonce         [2]*group.Scalar
	Commitment    [2]*group.Element
	HidingRandom  []byte
	BindingRandom []byte
	Configuration
}

type ParticipantInfo struct {
	KeyShare *shamir.Share
	Lambda   *group.Scalar // lamba can be computed once and reused across FROST signing operations
}

func (p *Participant) generateNonce(s *group.Scalar, random []byte) *group.Scalar {
	if random == nil {
		random = internal.RandomBytes(32)
	}
	enc := s.Encode()

	return p.Ciphersuite.H3(p.ContextString, internal.Concatenate(random, enc))
}

func (p *Participant) Commit() {
	p.Nonce[0] = p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey, p.HidingRandom)
	p.Nonce[1] = p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey, p.BindingRandom)
	p.Commitment[0] = p.Ciphersuite.Group.Base().Multiply(p.Nonce[0])
	p.Commitment[1] = p.Ciphersuite.Group.Base().Multiply(p.Nonce[1])
}

func (p *Participant) Sign(msg []byte, list internal.CommitmentList) *group.Scalar {
	// Compute the binding factor(s)
	bindingFactorList, _ := list.ComputeBindingFactors(p.Ciphersuite, p.ContextString, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(p.KeyShare.ID)

	// Compute group commitment
	groupCommitment := list.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Compute the interpolating value
	participantList := list.Participants()
	lambdaID := shamir.DeriveInterpolatingValue(p.Ciphersuite.Group, p.KeyShare.ID, participantList)

	p.Lambda = lambdaID.Copy()

	// Compute per message challenge
	challenge := schnorr.Challenge(p.Ciphersuite, groupCommitment, p.Configuration.GroupPublicKey, p.ContextString, msg)

	// Compute the signature share
	sigShare := p.Nonce[0].Add(
		p.Nonce[1].Multiply(bindingFactor).Add(lambdaID.Multiply(p.KeyShare.SecretKey).Multiply(challenge)),
	).Copy()

	// Clean up values
	p.Nonce[0].Zero()
	p.Nonce[1].Zero()

	return sigShare
}

func (p *Participant) VerifyVSS(v vss.Commitment) bool {
	return vss.Verify(p.Ciphersuite.Group, p.KeyShare, v)
}

type ParticipantList []*Participant

func (p ParticipantList) Get(id *group.Scalar) *Participant {
	for _, i := range p {
		if i.ParticipantInfo.KeyShare.ID.Equal(id) == 1 {
			return i
		}
	}

	return nil
}
