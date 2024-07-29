// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"crypto/rand"
	"encoding/binary"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

// SignatureShare represents a participants signature share and its identifier.
type SignatureShare struct {
	SignatureShare *group.Scalar
	Identifier     uint64
}

// Participant is a signer of a group.
type Participant struct {
	KeyShare      *KeyShare
	Lambda        *group.Scalar // lambda can be computed once and reused across FROST signing operations
	Nonces        map[uint64][2]*group.Scalar
	HidingRandom  []byte
	BindingRandom []byte
	Configuration
}

func (p *Participant) generateNonce(s *group.Scalar, random []byte) *group.Scalar {
	if random == nil {
		random = internal.RandomBytes(32)
	}

	enc := s.Encode()

	return p.Ciphersuite.H3(internal.Concatenate(random, enc))
}

func randomCommitmentID() uint64 {
	buf := make([]byte, 8)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return binary.LittleEndian.Uint64(buf)
}

func (p *Participant) Identifier() uint64 {
	return p.KeyShare.ID
}

// Commit generates a participants nonce and commitment, to be used in the second FROST round. The internal nonce must
// be kept secret, and the returned commitment sent to the signature aggregator.
func (p *Participant) Commit() *Commitment {
	cid := randomCommitmentID()
	for {
		if _, ok := p.Nonces[cid]; !ok {
			break
		}
	}

	p.Nonces[cid] = [2]*group.Scalar{
		p.generateNonce(p.KeyShare.Secret, p.HidingRandom),
		p.generateNonce(p.KeyShare.Secret, p.BindingRandom),
	}

	return &Commitment{
		Ciphersuite:   Ciphersuite(p.Group),
		ParticipantID: p.KeyShare.ID,
		CommitmentID:  cid,
		PublicKey:     p.KeyShare.PublicKey,
		HidingNonce:   p.Ciphersuite.Group.Base().Multiply(p.Nonces[cid][0]),
		BindingNonce:  p.Ciphersuite.Group.Base().Multiply(p.Nonces[cid][1]),
	}
}

func computeLambda(g group.Group, commitments CommitmentList, id uint64) (*group.Scalar, error) {
	participantList := commitments.Participants(g)
	return participantList.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(id))
}

func (c Configuration) do(
	publicKey *group.Element,
	lambda *group.Scalar,
	message []byte,
	commitments CommitmentList,
	id uint64,
) (*group.Scalar, *group.Scalar, error) {
	if !commitments.IsSorted() {
		commitments.Sort()
	}

	// Compute the interpolating value
	if lambda == nil || lambda.IsZero() {
		l, err := computeLambda(c.Ciphersuite.Group, commitments, id)
		if err != nil {
			return nil, nil, err
		}

		lambda = l
	}

	// Compute the binding factor(s)
	bindingFactorList := c.computeBindingFactors(publicKey, commitments, message)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(id)

	// Compute group commitment
	groupCommitment := computeGroupCommitment(c.Group, commitments, bindingFactorList)

	// Compute per message challenge
	chall := challenge(c.Ciphersuite, groupCommitment, publicKey, message)

	return bindingFactor, chall.Multiply(lambda), nil
}

// Sign produces a participant's signature share of the message msg.
//
// Each participant MUST validate the inputs before processing the Coordinator's request.
// In particular, the Signer MUST validate commitment_list, deserializing each group Element in the list using
// DeserializeElement from {{dep-pog}}. If deserialization fails, the Signer MUST abort the protocol. Moreover,
// each participant MUST ensure that its identifier and commitments (from the first round) appear in commitment_list.
func (p *Participant) Sign(commitmentID uint64, msg []byte, coms CommitmentList) (*SignatureShare, error) {
	bindingFactor, lambdaChall, err := p.do(p.KeyShare.GroupPublicKey, p.Lambda, msg, coms, p.KeyShare.ID)
	if err != nil {
		return nil, err
	}

	// Compute the signature share
	sigShare := p.Nonces[commitmentID][0].Copy().Add(
		p.Nonces[commitmentID][1].Copy().Multiply(bindingFactor).Add(lambdaChall.Multiply(p.KeyShare.Secret)),
	).Copy()

	// Clean up values
	p.Nonces[commitmentID][0].Zero()
	p.Nonces[commitmentID][1].Zero()

	return &SignatureShare{
		Identifier:     p.KeyShare.ID,
		SignatureShare: sigShare,
	}, nil
}

// computeBindingFactors computes binding factors based on the participant commitment list and the message to be signed.
func (c Configuration) computeBindingFactors(
	publicKey *group.Element,
	l CommitmentList,
	message []byte,
) internal.BindingFactorList {
	if !l.IsSorted() {
		panic(nil)
	}

	h := c.H4(message)
	encodedCommitHash := c.H5(l.Encode(c.Ciphersuite.Group))
	rhoInputPrefix := internal.Concatenate(publicKey.Encode(), h, encodedCommitHash)

	bindingFactorList := make(internal.BindingFactorList, len(l))

	for i, commitment := range l {
		id := c.Group.NewScalar().SetUInt64(commitment.ParticipantID).Encode()
		rhoInput := internal.Concatenate(rhoInputPrefix, id)
		bindingFactor := c.H1(rhoInput)

		bindingFactorList[i] = &internal.BindingFactor{
			Identifier:    commitment.ParticipantID,
			BindingFactor: bindingFactor,
		}
	}

	return bindingFactorList
}

// computeGroupCommitment creates the group commitment from a commitment list.
func computeGroupCommitment(g group.Group, l CommitmentList, list internal.BindingFactorList) *group.Element {
	if !l.IsSorted() {
		panic(nil)
	}

	gc := g.NewElement()

	for _, commitment := range l {
		if commitment.HidingNonce.IsIdentity() || commitment.BindingNonce.IsIdentity() {
			panic("identity commitment")
		}

		factor := list.BindingFactorForParticipant(commitment.ParticipantID)
		bindingNonce := commitment.BindingNonce.Copy().Multiply(factor)
		gc.Add(commitment.HidingNonce).Add(bindingNonce)
	}

	return gc
}
