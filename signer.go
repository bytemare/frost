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
	// The KeyShare holds the signer's secret and public info, such as keys and identifier.
	KeyShare *KeyShare

	// LambdaRegistry records all interpolating values for the signers for different combinations of participant
	// groups. Each group makes up a unique polynomial defined by the participants' identifiers. A value will be
	// computed once for the first time a group is encountered, and kept across encodings and decodings of the signer,
	// accelerating subsequent signatures within the same group of signers.
	LambdaRegistry internal.LambdaRegistry

	// NonceCommitments maps Nonce and their NonceCommitments to their Commitment's identifier.
	NonceCommitments map[uint64]*Nonce

	// Configuration is the core FROST setup configuration.
	Configuration *Configuration

	// HidingRandom can be set to force the use its value for HidingNonce generation. This is only encouraged for vector
	// reproduction, but should be left to nil in any production deployments.
	HidingRandom []byte

	// HidingRandom can be set to force the use its value for HidingNonce generation. This is only encouraged for vector
	// reproduction, but should be left to nil in any production deployments.
	BindingRandom []byte
}

type Nonce struct {
	HidingNonce  *group.Scalar
	BindingNonce *group.Scalar
	*Commitment
}

func (s *Signer) ClearNonceCommitment(commitmentID uint64) {
	if com := s.NonceCommitments[commitmentID]; com != nil {
		com.HidingNonce.Zero()
		com.BindingNonce.Zero()
		com.HidingNonceCommitment.Identity()
		com.BindingNonceCommitment.Identity()
		delete(s.NonceCommitments, commitmentID)
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

	return internal.H3(s.Configuration.group, internal.Concatenate(random, secret.Encode()))
}

func (s *Signer) genNonceID() uint64 {
	cid := randomCommitmentID()

	for range 128 {
		if _, exists := s.NonceCommitments[cid]; !exists {
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
		Group:                  s.Configuration.group,
		SignerID:               s.KeyShare.ID,
		CommitmentID:           cid,
		HidingNonceCommitment:  s.Configuration.group.Base().Multiply(hn),
		BindingNonceCommitment: s.Configuration.group.Base().Multiply(bn),
	}
	s.NonceCommitments[cid] = &Nonce{
		HidingNonce:  hn,
		BindingNonce: bn,
		Commitment:   com,
	}

	return com.Copy()
}

func (s *Signer) verifyNonces(com *Commitment) error {
	nonces, ok := s.NonceCommitments[com.CommitmentID]
	if !ok {
		return fmt.Errorf(
			"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
			com.CommitmentID,
			s.KeyShare.ID,
		)
	}

	if nonces.HidingNonceCommitment.Equal(com.HidingNonceCommitment) != 1 {
		return fmt.Errorf("invalid hiding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	if nonces.BindingNonceCommitment.Equal(com.BindingNonceCommitment) != 1 {
		return fmt.Errorf("invalid binding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	return nil
}

// VerifyCommitmentList checks for the Commitment list integrity and the signer's commitment.
func (s *Signer) VerifyCommitmentList(commitments CommitmentList) error {
	if err := commitments.Validate(s.Configuration.group, s.Configuration.Threshold); err != nil {
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
	com, exists := s.NonceCommitments[commitmentID]
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

	participants := commitments.Participants()

	lambda, err := s.LambdaRegistry.GetOrNew(s.Configuration.group, s.KeyShare.ID, participants)
	if err != nil {
		return nil, err
	}

	lambdaChall := s.Configuration.challenge(lambda, message, groupCommitment)

	hidingNonce := com.HidingNonce.Copy()
	bindingNonce := com.BindingNonce

	// Compute the signature share: h + b*f + l*s
	bindingFactor := bindingFactors[s.KeyShare.ID]
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
