// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/frost/internal"
)

// KeyShare identifies the sharded key share for a given participant.
type KeyShare struct {
	// The Secret of a participant (or secret share).
	Secret *group.Scalar

	// The PublicKey of Secret belonging to the participant.
	PublicKey *group.Element

	// ID of the participant.
	ID uint64
}

// Identifier returns the identity for this share.
func (s KeyShare) Identifier() uint64 {
	return s.ID
}

// SecretKey returns the participant's secret share.
func (s KeyShare) SecretKey() *group.Scalar {
	return s.Secret
}

// Participant is a signer of a group.
type Participant struct {
	KeyShare      *KeyShare
	Lambda        *group.Scalar // lamba can be computed once and reused across FROST signing operations
	Nonce         [2]*group.Scalar
	HidingRandom  []byte
	BindingRandom []byte
	Configuration
}

var errDecodeSignatureShare = errors.New("failed to decode signature share: invalid length")

func (p *Participant) generateNonce(s *group.Scalar, random []byte) *group.Scalar {
	if random == nil {
		random = internal.RandomBytes(32)
	}

	enc := s.Encode()

	return p.Ciphersuite.H3(internal.Concatenate(random, enc))
}

// Backup serializes the client with its long term values, containing its secret share.
func (p *Participant) Backup() []byte {
	return internal.Concatenate(internal.UInt64LE(p.KeyShare.ID),
		p.KeyShare.Secret.Encode(),
		p.Lambda.Encode())
}

// RecoverParticipant attempts to deserialize the encoded backup into a Participant.
func RecoverParticipant(c Ciphersuite, backup []byte) (*Participant, error) {
	if !c.Available() {
		return nil, internal.ErrInvalidCiphersuite
	}

	conf := c.Configuration()

	sLen := conf.Ciphersuite.Group.ScalarLength()
	if len(backup) != 8+2*sLen {
		return nil, internal.ErrInvalidParticipantBackup
	}

	id := internal.UInt64FromLE(backup[:8])

	secret := conf.Ciphersuite.Group.NewScalar()
	if err := secret.Decode(backup[sLen : 2*sLen]); err != nil {
		return nil, fmt.Errorf("decoding key share: %w", err)
	}

	lambda := conf.Ciphersuite.Group.NewScalar()
	if err := lambda.Decode(backup[2*sLen:]); err != nil {
		return nil, fmt.Errorf("decoding lambda: %w", err)
	}

	keyShare := &KeyShare{
		Secret:    secret,
		PublicKey: conf.Ciphersuite.Group.Base().Multiply(secret),
		ID:        id,
	}

	p := conf.Participant(keyShare)
	p.Lambda = lambda

	return p, nil
}

// Commit generates a participants nonce and commitment, to be used in the second FROST round. The internal nonce must
// be kept secret, and the returned commitment sent to the signature aggregator.
func (p *Participant) Commit() *Commitment {
	p.Nonce[0] = p.generateNonce(p.KeyShare.Secret, p.HidingRandom)
	p.Nonce[1] = p.generateNonce(p.KeyShare.Secret, p.BindingRandom)

	return &Commitment{
		Identifier:   p.KeyShare.ID,
		PublicKey:    p.KeyShare.PublicKey,
		HidingNonce:  p.Ciphersuite.Group.Base().Multiply(p.Nonce[0]),
		BindingNonce: p.Ciphersuite.Group.Base().Multiply(p.Nonce[1]),
	}
}

func computeLambda(g group.Group, commitments CommitmentList, id uint64) (*group.Scalar, error) {
	participantList := commitments.Participants(g)
	return participantList.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(id))
}

func (c Configuration) do(message []byte, commitments CommitmentList, id uint64) (*group.Scalar, *group.Scalar, *group.Scalar, error) {
	if !commitments.IsSorted() {
		commitments.Sort()
	}

	// Compute the interpolating value
	lambda, err := computeLambda(c.Ciphersuite.Group, commitments, id)
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute the binding factor(s)
	bindingFactorList := c.computeBindingFactors(commitments, c.GroupPublicKey.Encode(), message)
	bindingFactor := bindingFactorList.BindingFactorForParticipant(id)

	// Compute group commitment
	groupCommitment := c.computeGroupCommitment(commitments, bindingFactorList)

	// Compute per message challenge
	chall := challenge(c.Ciphersuite, groupCommitment, c.GroupPublicKey, message)

	return bindingFactor, lambda, chall.Multiply(lambda), nil
}

// Sign produces a participant's signature share of the message msg.
//
// Each participant MUST validate the inputs before processing the Coordinator's request.
// In particular, the Signer MUST validate commitment_list, deserializing each group Element in the list using
// DeserializeElement from {{dep-pog}}. If deserialization fails, the Signer MUST abort the protocol. Moreover,
// each participant MUST ensure that its identifier and commitments (from the first round) appear in commitment_list.
func (p *Participant) Sign(msg []byte, coms CommitmentList) (*SignatureShare, error) {
	bindingFactor, lambda, lambdaChall, err := p.do(msg, coms, p.KeyShare.ID)
	if err != nil {
		return nil, err
	}

	p.Lambda = lambda.Copy()

	// Compute the signature share
	sigShare := p.Nonce[0].Add(
		p.Nonce[1].Multiply(bindingFactor).Add(lambdaChall.Multiply(p.KeyShare.Secret)),
	).Copy()

	// Clean up values
	p.Nonce[0].Zero()
	p.Nonce[1].Zero()

	return &SignatureShare{
		Identifier:     p.KeyShare.ID,
		SignatureShare: sigShare,
	}, nil
}

// computeBindingFactors computes binding factors based on the participant commitment list and the message to be signed.
func (c Configuration) computeBindingFactors(l CommitmentList, pubkey, message []byte) internal.BindingFactorList {
	if !l.IsSorted() {
		panic(nil)
	}

	h := c.Ciphersuite.H4(message)
	encodedCommitHash := c.Ciphersuite.H5(l.Encode())
	rhoInputPrefix := internal.Concatenate(pubkey, h, encodedCommitHash)

	bindingFactorList := make(internal.BindingFactorList, len(l))

	for i, commitment := range l {
		rhoInput := internal.Concatenate(rhoInputPrefix, internal.UInt64LE(commitment.Identifier))
		bindingFactor := c.Ciphersuite.H1(rhoInput)

		bindingFactorList[i] = &internal.BindingFactor{
			Identifier:    commitment.Identifier,
			BindingFactor: bindingFactor,
		}
	}

	return bindingFactorList
}

// computeGroupCommitment creates the group commitment from a commitment list.
func (c Configuration) computeGroupCommitment(l CommitmentList, list internal.BindingFactorList) *group.Element {
	if !l.IsSorted() {
		panic(nil)
	}

	gc := c.Ciphersuite.Group.NewElement().Identity()

	for _, commitment := range l {
		if commitment.HidingNonce.IsIdentity() || commitment.BindingNonce.IsIdentity() {
			panic("identity commitment")
		}

		factor := list.BindingFactorForParticipant(commitment.Identifier)
		bindingNonce := commitment.BindingNonce.Copy().Multiply(factor)
		gc.Add(commitment.HidingNonce).Add(bindingNonce)
	}

	return gc
}

// SignatureShare represents a participants signature share, specifying which participant it was produced by.
type SignatureShare struct {
	Identifier     uint64
	SignatureShare *group.Scalar
}

// Encode returns a compact byte encoding of the signature share.
func (s SignatureShare) Encode() []byte {
	share := s.SignatureShare.Encode()

	out := make([]byte, 8+len(share))
	copy(out, internal.UInt64LE(s.Identifier))
	copy(out[8:], share)

	return out
}

// DecodeSignatureShare takes a byte string and attempts to decode it to return the signature share.
func (c Configuration) DecodeSignatureShare(data []byte) (*SignatureShare, error) {
	g := c.Ciphersuite.Group

	if len(data) != 8+g.ScalarLength() {
		return nil, errDecodeSignatureShare
	}

	s := &SignatureShare{
		Identifier:     internal.UInt64FromLE(data[:8]),
		SignatureShare: g.NewScalar(),
	}

	if err := s.SignatureShare.Decode(data[8:]); err != nil {
		return nil, fmt.Errorf("failed to decode signature share: %w", err)
	}

	return s, nil
}
