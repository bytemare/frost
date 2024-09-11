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
	"github.com/bytemare/frost/keys"
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
	KeyShare *keys.KeyShare

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

// Nonce holds the signing nonces and their commitments. The Signer.Commit() method will generate and record a new nonce
// and return the Commitment to that nonce. That Commitment will be used in Signer.Sign() and the associated nonces to
// create a signature share. Note that nonces and their commitments are agnostic of the upcoming message to sign, and
// can therefore be pre-computed and the commitments shared before the signing session, saving a round-trip.
type Nonce struct {
	HidingNonce  *group.Scalar
	BindingNonce *group.Scalar
	*Commitment
}

// ClearNonceCommitment zeroes-out the nonces and their commitments, and unregisters the nonce record.
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

	if _, err := rand.Read(buf); err != nil {
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

	// In the extremely rare and unlikely case the CSPRNG returns an already registered ID, we try again 128 times
	// before failing.
	for range 128 {
		if _, exists := s.NonceCommitments[cid]; !exists {
			return cid
		}

		cid = randomCommitmentID()
	}

	panic("FATAL: CSPRNG could not generate unique commitment identifiers over 128 iterations")
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

// VerifyCommitmentList checks for the Commitment list integrity and the signer's commitment. This function must not
// return an error for Sign to succeed.
func (s *Signer) VerifyCommitmentList(commitments CommitmentList) error {
	// Validate general consistency of the commitment list.
	if err := s.Configuration.ValidateCommitmentList(commitments); err != nil {
		return fmt.Errorf("invalid list of commitments: %w", err)
	}

	// The signer's id must be among the commitments.
	commitment := commitments.Get(s.KeyShare.ID)
	if commitment == nil {
		return fmt.Errorf("signer identifier %d not found in the commitment list", s.KeyShare.ID)
	}

	// Check commitment values for the signer.
	return s.verifyNonces(commitment)
}

// Sign produces a participant's signature share of the message msg. The CommitmentList must contain a Commitment
// produced on a previous call to Commit(). Once the signature share with Sign() is produced, the internal commitment
// and nonces are cleared and another call to Sign() with the same Commitment will return an error.
func (s *Signer) Sign(message []byte, commitments CommitmentList) (*SignatureShare, error) {
	commitments.Sort()

	if err := s.VerifyCommitmentList(commitments); err != nil {
		return nil, err
	}

	groupCommitment, bindingFactors := commitments.groupCommitmentAndBindingFactors(
		s.Configuration.GroupPublicKey,
		message,
	)

	participants := commitments.Participants()
	lambda := s.LambdaRegistry.GetOrNew(s.Configuration.group, s.KeyShare.ID, participants)
	lambdaChall := s.Configuration.challenge(lambda, message, groupCommitment)

	commitmentID := commitments.Get(s.KeyShare.ID).CommitmentID
	com := s.NonceCommitments[commitmentID]
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
