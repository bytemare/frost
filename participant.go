// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
	"github.com/bytemare/frost/internal/shamir"
)

// Participant is a signer of a group.
type Participant struct {
	ParticipantInfo
	Nonce         [2]*group.Scalar
	HidingRandom  []byte
	BindingRandom []byte
	Configuration
}

// ParticipantInfo holds the participant specific long-term values.
type ParticipantInfo struct {
	KeyShare *shamir.KeyShare
	Lambda   *group.Scalar // lambda can be computed once and reused across FROST signing operations
}

func (p *Participant) generateNonce(s *group.Scalar, random []byte) *group.Scalar {
	if random == nil {
		random = internal.RandomBytes(32)
	}

	enc := s.Encode()

	return p.Ciphersuite.H3(internal.Concatenate(random, enc))
}

// Backup serializes the client with its long term values, containing its secret share.
func (p *Participant) Backup() []byte {
	return internal.Concatenate(p.ParticipantInfo.KeyShare.Identifier.Encode(),
		p.ParticipantInfo.KeyShare.SecretKey.Encode(),
		p.ParticipantInfo.Lambda.Encode())
}

// RecoverParticipant attempts to deserialize the encoded backup into a Participant.
func RecoverParticipant(c Ciphersuite, backup []byte) (*Participant, error) {
	if !c.Available() {
		return nil, internal.ErrInvalidCiphersuite
	}

	conf := c.Configuration()

	sLen := conf.Ciphersuite.Group.ScalarLength()
	if len(backup) != int(3*sLen) {
		return nil, internal.ErrInvalidParticipantBackup
	}

	id := conf.Ciphersuite.Group.NewScalar()
	if err := id.Decode(backup[:sLen]); err != nil {
		return nil, fmt.Errorf("decoding identity: %w", err)
	}

	share := conf.Ciphersuite.Group.NewScalar()
	if err := share.Decode(backup[sLen : 2*sLen]); err != nil {
		return nil, fmt.Errorf("decoding key share: %w", err)
	}

	lambda := conf.Ciphersuite.Group.NewScalar()
	if err := lambda.Decode(backup[2*sLen:]); err != nil {
		return nil, fmt.Errorf("decoding lambda: %w", err)
	}

	p := conf.Participant(id, share)
	p.Lambda = lambda

	return p, nil
}

// Commit generates a participants nonce and commitment, to be used in the second FROST round. The nonce must be kept
// secret, and the commitment sent to the coordinator.
func (p *Participant) Commit() *internal.Commitment {
	p.Nonce[0] = p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey, p.HidingRandom)
	p.Nonce[1] = p.generateNonce(p.ParticipantInfo.KeyShare.SecretKey, p.BindingRandom)

	return &internal.Commitment{
		ID:           p.ParticipantInfo.KeyShare.Identifier.Copy(),
		HidingNonce:  p.Ciphersuite.Group.Base().Multiply(p.Nonce[0]),
		BindingNonce: p.Ciphersuite.Group.Base().Multiply(p.Nonce[1]),
	}
}

// Sign produces a participant's signature share of the message msg.
//
// Each participant MUST validate the inputs before processing the Coordinator's request.
// In particular, the Signer MUST validate commitment_list, deserializing each group Element in the list using
// DeserializeElement from {{dep-pog}}. If deserialization fails, the Signer MUST abort the protocol. Moreover,
// each participant MUST ensure that its identifier and commitments (from the first round) appear in commitment_list.
func (p *Participant) Sign(msg []byte, list internal.CommitmentList) *group.Scalar {
	// Compute the binding factor(s)
	bindingFactorList, _ := list.ComputeBindingFactors(p.Ciphersuite, msg)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(p.KeyShare.Identifier)

	// Compute group commitment
	groupCommitment := list.ComputeGroupCommitment(p.Ciphersuite, bindingFactorList)

	// Compute the interpolating value
	participantList := list.Participants()
	lambdaID := shamir.DeriveInterpolatingValue(p.Ciphersuite.Group, p.KeyShare.Identifier, participantList)

	p.Lambda = lambdaID.Copy()

	// Compute per message challenge
	challenge := schnorr.Challenge(p.Ciphersuite, groupCommitment, p.Configuration.GroupPublicKey, msg)

	// Compute the signature share
	sigShare := p.Nonce[0].Add(
		p.Nonce[1].Multiply(bindingFactor).Add(
			lambdaID.Multiply(p.KeyShare.SecretKey).Multiply(challenge),
		),
	).Copy()

	// Clean up values
	p.Nonce[0].Zero()
	p.Nonce[1].Zero()

	return sigShare
}
