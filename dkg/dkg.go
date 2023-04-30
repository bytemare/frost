// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package dkg implements the Distributed Key Generation described in FROST,
// using zero-knowledge proofs in Schnorr signatures.
package dkg

import (
	"encoding/hex"
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
)

var (
	errRound1DataElements    = errors.New("invalid number of expected round 1 data packets")
	errRound2DataElements    = errors.New("invalid number of expected round 2 data packets")
	errRound2InvalidReceiver = errors.New("invalid receiver in round 2 package")
	errInvalidSignature      = errors.New("invalid signature")

	errCommitmentNotFound      = errors.New("commitment not found for participant")
	errInvalidSecretShare      = errors.New("invalid secret share received from peer")
	errVerificationShareFailed = errors.New("failed to compute correct verification share")
)

// Round1Data is the output data of the Init() function, to be broadcast to all participants.
type Round1Data struct {
	ProofOfKnowledge schnorr.Signature
	SenderIdentifier *group.Scalar
	Commitment       []*group.Element
}

// Round2Data is an output of the Continue() function, to be sent to the Receiver.
type Round2Data struct {
	SenderIdentifier   *group.Scalar
	ReceiverIdentifier *group.Scalar
	SecretShare        *group.Scalar
}

// Participant represent a party in the Distributed Key Generation. Once the DKG completed, all values must be erased.
type Participant struct {
	Identifier   *group.Scalar
	publicShare  *group.Element
	secretShare  *group.Scalar
	coefficients secretsharing.Polynomial
	ciphersuite  internal.Ciphersuite
	maxSigner    int
	threshold    int
}

// NewParticipant instantiates a new participant with identifier id.
func NewParticipant(c internal.Ciphersuite, id *group.Scalar, maxSigner, threshold int) *Participant {
	return &Participant{
		maxSigner:   maxSigner,
		threshold:   threshold,
		ciphersuite: c,
		Identifier:  id,
	}
}

func (p *Participant) challenge(id *group.Scalar, pubkey, r *group.Element) *group.Scalar {
	// The paper actually hashes (id || dst || φ0 || r)
	return p.ciphersuite.HDKG(internal.Concatenate(
		id.Encode(),
		pubkey.Encode(),
		r.Encode(),
	))
}

// Init returns a participant's output for the first round, and stores intermediate values internally.
func (p *Participant) Init() *Round1Data {
	// Step 1
	secretCoefficients := secretsharing.NewPolynomial(uint(p.threshold))
	for i := 0; i < p.threshold; i++ {
		secretCoefficients[i] = p.ciphersuite.Group.NewScalar().Random()
	}

	// step 3 - we do this before step 2, so we can reuse the calculation of the commitment com[0]
	com := secretsharing.Commit(p.ciphersuite.Group, secretCoefficients)

	// step 2
	k := p.ciphersuite.Group.NewScalar().Random()
	r := p.ciphersuite.Group.Base().Multiply(k)
	c := p.challenge(p.Identifier, com[0], r)
	mu := k.Add(secretCoefficients[0].Copy().Multiply(c))

	p.coefficients = secretCoefficients
	p.publicShare = com[0]

	package1 := &Round1Data{
		SenderIdentifier: p.Identifier,
		Commitment:       com,
		ProofOfKnowledge: schnorr.Signature{
			R: r,
			Z: mu,
		},
	}

	// step 4, broadcast package 1 to all other participants
	return package1
}

// Continue ingests the broadcast data from other peers and returns a dedicated Round2Data structure for each peer.
func (p *Participant) Continue(r1data []*Round1Data) ([]*Round2Data, error) {
	if len(r1data) != p.maxSigner {
		return nil, errRound1DataElements
	}

	r2data := make([]*Round2Data, 0, len(r1data)-1)

	for _, r1package := range r1data {
		peer := r1package.SenderIdentifier
		if peer.Equal(p.Identifier) == 1 {
			continue
		}

		// round1, step 5
		c := p.challenge(peer, r1package.Commitment[0], r1package.ProofOfKnowledge.R)
		rc := p.ciphersuite.Group.Base().
			Multiply(r1package.ProofOfKnowledge.Z).
			Subtract(r1package.Commitment[0].Copy().Multiply(c))

		if r1package.ProofOfKnowledge.R.Equal(rc) != 1 {
			return nil, fmt.Errorf(
				"%w: participant %v",
				errInvalidSignature,
				hex.EncodeToString(r1package.SenderIdentifier.Encode()),
			)
		}

		// round 2, step 1
		fil := p.coefficients.Evaluate(p.ciphersuite.Group, peer)
		r2data = append(r2data, &Round2Data{
			SenderIdentifier:   p.Identifier.Copy(),
			ReceiverIdentifier: peer.Copy(),
			SecretShare:        fil,
		})
	}

	p.secretShare = p.coefficients.Evaluate(p.ciphersuite.Group, p.Identifier)

	return r2data, nil
}

// Finalize ingests the broadcast data from round 1 and the round 2 data destined for the participant,
// and returns the participant's secret share and verification key, and the group's public key.
func (p *Participant) Finalize(
	r1data []*Round1Data,
	r2data []*Round2Data,
) (signingShare *group.Scalar, verificationShare, groupPublic *group.Element, err error) {
	if len(r1data) != p.maxSigner {
		return nil, nil, nil, errRound1DataElements
	}

	if len(r1data) != len(r2data)+1 {
		return nil, nil, nil, errRound2DataElements
	}

	signingShare = p.ciphersuite.Group.NewScalar().Zero()
	groupPublic = p.ciphersuite.Group.NewElement().Identity()

	for _, r2package := range r2data {
		if r2package.ReceiverIdentifier.Equal(p.Identifier) != 1 {
			return nil, nil, nil, errRound2InvalidReceiver
		}

		// round 2, step 2

		// Find the commitment from the participant.
		var com []*group.Element

		for _, r1d := range r1data {
			if r1d.SenderIdentifier.Equal(r2package.SenderIdentifier) == 1 {
				com = r1d.Commitment
			}
		}

		if len(com) == 0 {
			return nil, nil, nil,
				fmt.Errorf("%w: %v",
					errCommitmentNotFound,
					hex.EncodeToString(r2package.SenderIdentifier.Encode()))
		}

		// Verify the secret share is valid with regard to the commitment.
		pk := p.ciphersuite.Group.Base().Multiply(r2package.SecretShare)
		if !secretsharing.Verify(p.ciphersuite.Group, p.Identifier, pk, com) {
			return nil, nil, nil, fmt.Errorf(
				"%w: %v",
				errInvalidSecretShare,
				hex.EncodeToString(r2package.SenderIdentifier.Encode()),
			)
		}

		// Round 2, step 3
		signingShare.Add(r2package.SecretShare)

		// Round 2, step 4
		groupPublic.Add(com[0])
	}

	signingShare.Add(p.secretShare)
	groupPublic.Add(p.publicShare)

	// round 2, step 4
	verificationShare = p.ciphersuite.Group.Base().Multiply(signingShare)

	yi := ComputeVerificationShare(p.ciphersuite.Group, p.Identifier, r1data)
	if verificationShare.Equal(yi) != 1 {
		return nil, nil, nil,
			fmt.Errorf("%w: want %q got %q",
				errVerificationShareFailed,
				hex.EncodeToString(yi.Encode()),
				hex.EncodeToString(verificationShare.Encode()),
			)
	}

	return signingShare, verificationShare, groupPublic, nil
}

// ComputeVerificationShare computes the verification share for participant id given the commitments of round 1.
func ComputeVerificationShare(g group.Group, id *group.Scalar, r1data []*Round1Data) *group.Element {
	yi := g.NewElement().Identity()

	for _, p := range r1data {
		prime := g.NewElement().Identity()
		one := g.NewScalar().One()
		j := g.NewScalar().Zero()

		for _, com := range p.Commitment {
			prime.Add(com.Copy().Multiply(id.Copy().Pow(j)))
			j.Add(one)
		}

		yi.Add(prime)
	}

	return yi
}
