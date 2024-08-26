// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

// SignatureShare represents a Signer's signature share and its identifier.
type SignatureShare struct {
	SignatureShare   *group.Scalar
	SignerIdentifier uint64
	Group            group.Group
}

// Signer is a participant in a signing group.
type Signer struct {
	KeyShare      *KeyShare
	Lambda        *group.Scalar
	Commitments   map[uint64]*NonceCommitment
	Configuration *Configuration
	HidingRandom  []byte
	BindingRandom []byte
}

type NonceCommitment struct {
	HidingNonceS  *group.Scalar
	BindingNonceS *group.Scalar
	*Commitment
}

func (s *Signer) ClearNonceCommitment(commitmentID uint64) {
	if com := s.Commitments[commitmentID]; com != nil {
		com.HidingNonceS.Zero()
		com.BindingNonceS.Zero()
		com.HidingNonce.Identity()
		com.BindingNonce.Identity()
		delete(s.Commitments, commitmentID)
	}
}

// Identifier returns the Signer's identifier.
func (s *Signer) Identifier() uint64 {
	return s.KeyShare.ID
}

func randomCommitmentID() uint64 {
	buf := make([]byte, 8)

	_, err := rand.Read(buf)
	if err != nil {
		panic(fmt.Errorf("FATAL: %w", err))
	}

	return binary.LittleEndian.Uint64(buf)
}

func (s *Signer) generateNonce(secret *group.Scalar, random []byte) *group.Scalar {
	if random == nil {
		random = internal.RandomBytes(32)
	}

	enc := secret.Encode()

	return internal.H3(s.Configuration.group, internal.Concatenate(random, enc))
}

func (s *Signer) genNonceID() uint64 {
	cid := randomCommitmentID()

	for range 128 {
		if _, exists := s.Commitments[cid]; !exists {
			return cid
		}

		cid = randomCommitmentID()
	}

	panic("FATAL: CSPRNG could not generate a unique nonce over 128 iterations")
}

// Commit generates a signer's nonces and commitment, to be used in the second FROST round. The internal nonce must
// be kept secret, and the returned commitment sent to the signature aggregator.
func (s *Signer) Commit() *Commitment {
	cid := s.genNonceID()
	hn := s.generateNonce(s.KeyShare.Secret, s.HidingRandom)
	bn := s.generateNonce(s.KeyShare.Secret, s.BindingRandom)
	com := &Commitment{
		Group:        s.Configuration.group,
		SignerID:     s.KeyShare.ID,
		CommitmentID: cid,
		HidingNonce:  s.Configuration.group.Base().Multiply(hn),
		BindingNonce: s.Configuration.group.Base().Multiply(bn),
	}
	s.Commitments[cid] = &NonceCommitment{
		HidingNonceS:  hn,
		BindingNonceS: bn,
		Commitment:    com,
	}

	return com.Copy()
}

func (s *Signer) verifyNonces(com *Commitment) error {
	nonces, ok := s.Commitments[com.CommitmentID]
	if !ok {
		return fmt.Errorf(
			"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
			com.CommitmentID,
			s.KeyShare.ID,
		)
	}

	if nonces.HidingNonce.Equal(com.HidingNonce) != 1 {
		return fmt.Errorf("invalid hiding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	if nonces.BindingNonce.Equal(com.BindingNonce) != 1 {
		return fmt.Errorf("invalid binding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	return nil
}

// VerifyCommitmentList checks for the Commitment list integrity and the signer's commitment.
func (s *Signer) VerifyCommitmentList(commitments CommitmentList) error {
	if err := commitments.Verify(s.Configuration.group, s.Configuration.Threshold); err != nil {
		return fmt.Errorf("invalid list of commitments: %w", err)
	}

	// Check commitment values for the signer.
	for _, com := range commitments {
		if com.SignerID == s.KeyShare.ID {
			return s.verifyNonces(com)
		}
	}

	return fmt.Errorf("no commitment for signer %d found in the commitment list", s.KeyShare.ID)
}

// Sign produces a participant's signature share of the message msg. The commitmentID identifies the commitment produced
// on a previous call to Commit(). Once the signature with Sign() is produced, the internal commitment nonces are
// cleared and another call to Sign() with the same commitmentID will return an error.
//
// Each signer MUST validate the inputs before processing the Coordinator's request.
// In particular, the Signer MUST validate commitment_list, deserializing each group Element in the list using
// DeserializeElement from {{dep-pog}}. If deserialization fails, the Signer MUST abort the protocol. Moreover,
// each signer MUST ensure that its identifier and commitments (from the first round) appear in commitment_list.
func (s *Signer) Sign(commitmentID uint64, message []byte, commitments CommitmentList) (*SignatureShare, error) {
	com, exists := s.Commitments[commitmentID]
	if !exists {
		return nil, fmt.Errorf("commitmentID %d not registered", commitmentID)
	}

	if err := s.VerifyCommitmentList(commitments); err != nil {
		return nil, err
	}

	groupCommitment, bindingFactors := commitments.GroupCommitmentAndBindingFactors(
		s.Configuration.GroupPublicKey,
		message,
	)

	bindingFactor := bindingFactors[s.KeyShare.ID]
	participants := commitments.ParticipantsScalar()

	lambdaChall, err := internal.ComputeChallengeFactor(
		s.Configuration.group,
		s.KeyShare.ID,
		s.Lambda,
		participants,
		message,
		groupCommitment,
		s.Configuration.GroupPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("can't compute challenge: %w", err)
	}

	hidingNonce := com.HidingNonceS.Copy()
	bindingNonce := com.BindingNonceS

	// Compute the signature share: h + b*f + l*s
	sigShare := hidingNonce.
		Add(bindingFactor.Multiply(bindingNonce).
			Add(lambdaChall.Multiply(s.KeyShare.Secret)))

	// Clean up values
	s.ClearNonceCommitment(commitmentID)

	return &SignatureShare{
		Group:            s.Configuration.group,
		SignerIdentifier: s.KeyShare.ID,
		SignatureShare:   sigShare,
	}, nil
}
